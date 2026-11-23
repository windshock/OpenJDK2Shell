#!/bin/bash
# Mechanism confirmation runner (diagnostic). usage: run_mech.sh methodA|buildB|status|pull|teardown
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
export KUBECONFIG="${KUBECONFIG:-$ROOT/kube/dfirtx-dev.conf}"
NS=j4s-mech
IMG=eclipse-temurin:17.0.21_9-jdk-jammy     # real vulnerable build for Method A + build toolchain
GROOM="-XX:+UnlockExperimentalVMOptions -Xms1g -Xmx1g -XX:G1HeapRegionSize=1m -XX:G1MaxNewSizePercent=5 -Xlog:gc:file=/tmp/gc.log -XX:+PrintCompilation --add-opens java.base/jdk.internal.misc=ALL-UNNAMED"
K="kubectl -n $NS"

ensure_ns(){ kubectl get ns $NS >/dev/null 2>&1 || kubectl create ns $NS >/dev/null; 
  $K get cm mech-src >/dev/null 2>&1 || $K create cm mech-src --from-file=MechProbe.java="$HERE/MechProbe.java" >/dev/null; }

case "${1:-}" in
methodA)
  ensure_ns
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: mech-a, namespace: $NS}
spec:
  nodeName: dfirtx-worker-dev03
  restartPolicy: Never
  containers:
  - name: c
    image: $IMG
    command: ["bash","-c",
      "set -e; grep -m1 'model name' /proc/cpuinfo; grep -m1 -o -w -E 'avx512(vbmi|bw)' /proc/cpuinfo;
       mkdir /o && javac --add-exports java.base/jdk.internal.misc=ALL-UNNAMED -d /o /v/MechProbe.java && echo COMPILE-OK;
       java $GROOM -cp /o MechProbe gap pad2 140 /tmp/gc.log; echo MEXIT=\$?;
       for f in /tmp/hs_err*; do echo '-- hs_err' \$f; head -40 \$f; done 2>/dev/null; sleep 300"]
    resources: {requests: {cpu: '3', memory: 2500Mi}, limits: {cpu: '3', memory: 3Gi}}
    volumeMounts: [{name: v, mountPath: /v}]
  volumes: [{name: v, configMap: {name: mech-src}}]
YAML
  echo "methodA pod applied → ./run_mech.sh status"
  ;;
buildB)
  ensure_ns
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: build-b, namespace: $NS}
spec:
  nodeName: dfirtx-worker-dev04
  restartPolicy: Never
  containers:
  - name: c
    image: $IMG
    command: ["bash","-c",
      "set -e; export DEBIAN_FRONTEND=noninteractive;
       apt-get update -qq; apt-get install -y -qq git build-essential autoconf zip unzip file cpio libx11-dev libxext-dev libxrender-dev libxrandr-dev libxi-dev libxt-dev libxtst-dev libcups2-dev libfontconfig1-dev libasound2-dev >/dev/null;
       echo DEPS-OK;
       git clone --depth 1 --branch jdk-17.0.21.0.3-ga https://github.com/openjdk/jdk17u.git /build >/dev/null 2>&1; echo CLONE-OK;
       cd /build; bash configure --with-boot-jdk=/opt/java/openjdk --with-debug-level=fastdebug --with-native-debug-symbols=internal --disable-warnings-as-errors --with-conf-name=fd 2>&1 | tail -8;
       make images CONF_NAME=fd JOBS=6 2>&1 | tail -6; echo BUILD-DONE;
       J=/build/build/fd/images/jdk;
       \$J/bin/java -version 2>&1;
       mkdir /o && javac --add-exports java.base/jdk.internal.misc=ALL-UNNAMED -d /o /v/MechProbe.java && echo COMPILE-OK;
       echo '======== METHOD B: fastdebug + VerifyBeforeGC/AfterGC ========';
       \$J/bin/java $GROOM -XX:+UnlockDiagnosticVMOptions -XX:+VerifyBeforeGC -XX:+VerifyAfterGC -Xlog:gc+verify=info -cp /o MechProbe gap pad2 140 /tmp/gc.log verifygc 2>&1; echo MEXIT=\$?;
       for f in /tmp/hs_err* /build/hs_err*; do echo '-- hs_err' \$f; head -60 \$f; done 2>/dev/null; sleep 600"]
    resources: {requests: {cpu: '6', memory: 6Gi}, limits: {cpu: '8', memory: 7Gi}}
    volumeMounts: [{name: v, mountPath: /v}]
  volumes: [{name: v, configMap: {name: mech-src}}]
YAML
  echo "buildB pod applied (fastdebug build ~2h) → ./run_mech.sh status"
  ;;
status)
  for p in mech-a build-b; do $K get pod $p >/dev/null 2>&1 && { echo "== $p ($($K get pod $p -o jsonpath='{.status.phase}'))"; $K logs $p --tail="${N:-12}" 2>/dev/null; }; done
  ;;
pull)
  mkdir -p "$HERE/out"; for p in mech-a build-b; do $K get pod $p >/dev/null 2>&1 && $K logs $p > "$HERE/out/$p.log" 2>&1 && echo "pulled $p -> out/$p.log"; done
  ;;
vary)
  ensure_ns
  i=0
  for ch in a b q; do
    node=$(printf "dfirtx-worker-dev0%d" $((3 + i))); i=$((i+1))
    CH=$(echo "$ch" | tr a-z A-Z)
    cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: vary-$ch, namespace: $NS}
spec:
  nodeName: $node
  restartPolicy: Never
  containers:
  - name: c
    image: $IMG
    command: ["bash","-c",
      "set -e; mkdir /o && javac --add-exports java.base/jdk.internal.misc=ALL-UNNAMED -d /o /v/MechProbe.java; java $GROOM -cp /o MechProbe gap pad2 140 /tmp/gc.log $CH 2>&1 | grep -E 'length :|INPUT-DEPENDENCE|VERDICT' || true; echo DONE-$CH; sleep 180"]
    resources: {requests: {cpu: '3', memory: 2500Mi}, limits: {cpu: '3', memory: 3Gi}}
    volumeMounts: [{name: v, mountPath: /v}]
  volumes: [{name: v, configMap: {name: mech-src}}]
YAML
  done
  echo "vary pods applied (a,b,q) → ./run_mech.sh varystatus"
  ;;
varystatus)
  for ch in a b q; do echo "== vary-$ch ($($K get pod vary-$ch -o jsonpath='{.status.phase}' 2>/dev/null))"; $K logs vary-$ch 2>/dev/null | grep -E 'length :|INPUT-DEP|VERDICT|MEXIT'; done
  ;;
teardown) kubectl delete ns $NS --ignore-not-found --wait=false >/dev/null 2>&1; echo NS-CLEAN ;;
*) sed -n 2,2p "$0"; exit 2 ;;
esac
