#!/bin/bash
# HBase standalone (real app, default install shape) + REST daemon on vulnerable JDK17
# Runs inside the "hbase" container of the e2e pod. Signals /share/READY when attackable.
set -ux
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq wget procps >/dev/null 2>&1

cd /opt
echo "[setup] downloading HBase 2.5.10 (official bin tarball)..."
wget -q https://archive.apache.org/dist/hbase/2.5.10/hbase-2.5.10-bin.tar.gz
tar xzf hbase-2.5.10-bin.tar.gz && mv hbase-2.5.10 hbase && rm hbase-2.5.10-bin.tar.gz

# Official HBase-on-JDK17 module opens (HBase refguide) + fixed 1g heap => G1 default 1MB regions
OPENS="--add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED \
--add-opens=java.base/java.math=ALL-UNNAMED --add-opens=java.base/java.nio=ALL-UNNAMED \
--add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.security=ALL-UNNAMED \
--add-opens=java.base/java.text=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED \
--add-opens=java.base/java.util.concurrent=ALL-UNNAMED --add-opens=java.base/java.util.concurrent.atomic=ALL-UNNAMED \
--add-opens=java.base/jdk.internal.ref=ALL-UNNAMED --add-opens=java.base/sun.nio.ch=ALL-UNNAMED \
--add-opens=java.base/sun.nio.cs=ALL-UNNAMED --add-opens=java.base/sun.security.action=ALL-UNNAMED \
--add-opens=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/sun.security.util=ALL-UNNAMED \
--add-opens=java.base/sun.security.ssl=ALL-UNNAMED --add-opens=java.base/sun.security.x509=ALL-UNNAMED \
--add-opens=java.security.jgss/sun.security.krb5=ALL-UNNAMED --add-opens=java.management/java.lang.management=ALL-UNNAMED"
cat >> /opt/hbase/conf/hbase-env.sh <<EOF
export HBASE_OPTS="\$HBASE_OPTS $OPENS -Xms1g -Xmx1g"
export HBASE_REST_OPTS="$OPENS -Xms1g -Xmx1g -Xlog:gc:file=/share/gc-rest.log -XX:+PrintCompilation"
export HBASE_MANAGES_ZK=true
EOF
# runner-controlled extras (mitig mode injects -XX:-UseBASE64Intrinsics via /share/victim_opts)
if [ -f /share/victim_opts ]; then
  EXTRA=$(cat /share/victim_opts)
  echo "export HBASE_REST_OPTS=\"\$HBASE_REST_OPTS $EXTRA\"" >> /opt/hbase/conf/hbase-env.sh
fi

echo "[setup] starting standalone HBase (embedded ZK, local FS)..."
/opt/hbase/bin/start-hbase.sh >/tmp/hbase-start.log 2>&1

for i in $(seq 1 60); do
  if /opt/hbase/bin/hbase version >/dev/null 2>&1 && (echo > /dev/tcp/127.0.0.1/16020) 2>/dev/null; then break; fi
  sleep 5
done

echo "[setup] starting REST daemon (default install port shape)..."
/opt/hbase/bin/hbase-daemon.sh start rest -p 8080 >/tmp/rest-start.log 2>&1

UP=0
for i in $(seq 1 60); do
  if curl -s -o /dev/null -m 3 http://127.0.0.1:8080/version; then UP=1; break; fi
  sleep 5
done
[ "$UP" = "1" ] || { echo "REST FAILED"; tail -40 /opt/hbase/logs/*rest* 2>/dev/null; tail -20 /tmp/rest-start.log; exit 1; }

echo "[setup] creating attack table 'test' (cf)..."
curl -s -X PUT -H "Content-Type: application/json" -H "Accept: application/json" \
  -d '{"name":"test","ColumnSchema":[{"name":"cf"}]}' http://127.0.0.1:8080/test/schema

echo "[setup] victim fingerprint:"
curl -s http://127.0.0.1:8080/version
java -XX:+PrintFlagsFinal -version 2>&1 | grep -i base64 || true
# python3 inside this container too — the attack can run here if the attacker side fails
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq python3 >/dev/null 2>&1 || true

echo READY > /share/READY
echo "[setup] READY — REST live on 8080"
# keep container alive; crash detection prints
while true; do
  if ! pgrep -f "org.apache.hadoop.hbase.rest.RESTServer" >/dev/null; then
    echo "RESTSERVER-DEAD $(date)"; ls -la /opt/hbase/hs_err_pid*.log 2>/dev/null || ls -la /tmp/hs_err* 2>/dev/null || echo "(no hs_err yet)"
    break
  fi
  sleep 5
done
