#!/usr/bin/env python3
"""Lane coordinator (deviation D-1): hands remaining blocks to whichever lane is free.

- New worker becomes Ready -> deploy a lane on it, verify AVX-512 VBMI+BW, then use it.
- A lane whose driver finished its schedule -> gets the next pending block pair.
- A lane whose driver stopped before finishing -> resumes its own schedule (driver skips DONE episodes).
Prints one line per action (for a Monitor), also appends to research/lab/coordinator.log.

usage: coordinator.py
"""
import json, os, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LAB = os.path.join(ROOT, "research/lab/lab.sh")
SCHED = os.path.join(ROOT, "research/schedules")
LOG = os.path.join(ROOT, "research/lab/coordinator.log")
ENV = dict(os.environ, KUBECONFIG=os.path.join(ROOT, "kube/dfirtx-dev.conf"))
MAIN = json.load(open(os.path.join(SCHED, "main-2026-11-23.json")))

# lanes already running: node -> (namespace, schedule file)
lanes = {"dev02": ["j4s-research", "main-2026-11-23-dev02.json"],
         "dev01": ["j4s-research-dev01", "main-2026-11-23-dev01.json"]}
pending = [[3, 8], [4, 9], [5, 10]]          # blocks not yet assigned to a running lane
candidates = ["dev03", "dev04", "dev05", "dev06"]
rejected = set()

def say(msg):
    line = time.strftime("%H:%M:%S ") + msg
    print(line, flush=True)
    open(LOG, "a").write(line + "\n")

def sh(cmd, timeout=900, extra=None):
    e = dict(ENV, **(extra or {}))
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout, env=e, cwd=ROOT)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "timeout"

def ready_nodes():
    _, out = sh("kubectl get nodes --no-headers")
    return {l.split()[0].replace("dfirtx-worker-", "") for l in out.splitlines() if " Ready " in l}

def lane_state(node):
    ns, sched = lanes[node]
    _, out = sh("NS=%s %s status" % (ns, LAB), timeout=60)
    running = "DRIVER-RUNNING" in out
    sched_eps = [e["epid"] for e in json.load(open(os.path.join(SCHED, sched)))["episodes"]]
    _, done = sh("kubectl -n %s exec lab -c driver -- sh -c 'ls /share/ep/*/DONE 2>/dev/null'" % ns, timeout=60)
    done_ids = {p.split("/")[3] for p in done.split() if p.startswith("/share/ep/")}
    return running, all(e in done_ids for e in sched_eps), len([e for e in sched_eps if e in done_ids]), len(sched_eps)

def write_sched(node, blocks):
    name = "main-2026-11-23-%s-b%s.json" % (node, "-".join(map(str, blocks)))
    eps = [dict(e, lane=node) for e in MAIN["episodes"] if e["block"] in blocks]
    json.dump({"run_id": MAIN["run_id"], "lane": node, "digests": MAIN["digests"], "episodes": eps},
              open(os.path.join(SCHED, name), "w"), indent=1)
    return name

def start(node, sched):
    ns = lanes[node][0]
    rc, out = sh("NS=%s %s run %s" % (ns, LAB, os.path.join(SCHED, sched)), timeout=120)
    lanes[node][1] = sched
    say("RUN %s %s -> %s" % (node, sched, out.splitlines()[-1] if out else rc))

def deploy(node):
    ns = "j4s-research-" + node
    say("DEPLOY %s (ns %s)" % (node, ns))
    rc, out = sh("NS=%s NODE=dfirtx-worker-%s %s deploy" % (ns, node, LAB), timeout=1200)
    if "LAB-READY" not in out:
        say("DEPLOY-FAIL %s: %s" % (node, out[-200:])); return False
    _, cpu = sh("kubectl -n %s exec lab -c app -- grep -m1 -o -w -E 'avx512vbmi|avx512bw' /proc/cpuinfo" % ns, timeout=60)
    _, model = sh("kubectl -n %s exec lab -c app -- grep -m1 'model name' /proc/cpuinfo" % ns, timeout=60)
    if "avx512vbmi" not in cpu or "avx512bw" not in cpu:
        say("REJECT %s: no AVX-512 VBMI+BW (%s) -> teardown" % (node, model.strip()))
        sh("NS=%s %s teardown" % (ns, LAB)); rejected.add(node); return False
    lanes[node] = [ns, None]
    say("LANE-UP %s %s" % (node, model.split(":")[-1].strip()))
    return True

def main():
    say("coordinator up; lanes=%s pending=%s" % (list(lanes), pending))
    while True:
        rn = ready_nodes()
        for node in candidates:
            if node in rn and node not in lanes and node not in rejected and pending:
                if deploy(node):
                    start(node, write_sched(node, pending.pop(0)))
        idle = 0
        for node in list(lanes):
            if lanes[node][1] is None: continue
            running, complete, nd, nt = lane_state(node)
            if running: continue
            if not complete:
                say("RESUME %s (%d/%d done)" % (node, nd, nt)); start(node, lanes[node][1]); continue
            if pending:
                start(node, write_sched(node, pending.pop(0)))
            else:
                idle += 1
        if not pending and idle == len([n for n in lanes if lanes[n][1]]):
            say("ALL-LANES-COMPLETE"); return
        time.sleep(60)

if __name__ == "__main__":
    main()
