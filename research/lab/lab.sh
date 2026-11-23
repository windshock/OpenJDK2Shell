#!/bin/bash
# Phase 0/1 research lab — one pod, fresh JVM per episode, all arm JDKs side by side.
# usage: lab.sh deploy | run <schedule.json> | status | pull <run_id> | teardown
#   deploy   : namespace + pod (JDKs copied from digest-pinned images, app jar built once)
#   run      : copy schedule into the pod, start driver detached (survives kubectl drop)
#   status   : driver log tail + episode count
#   pull     : archive /share (episodes + JSONL) to research/data/<run_id>/   (P0-3)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
export KUBECONFIG="${KUBECONFIG:-$ROOT/kube/dfirtx-dev.conf}"
NS=j4s-research
NODE=dfirtx-worker-dev02
IMG_1708=docker.io/library/eclipse-temurin@sha256:bfc748eb9766e9c031bd79f6a37d5d7fcb1ba1adca56106fc4c661fa255340c8
IMG_17021=docker.io/library/eclipse-temurin@sha256:acf46b4e646df812fd95c54669bc80d44acef68f0bde1dd420ea47897de0d637
IMG_170211=docker.io/library/eclipse-temurin@sha256:39a7842fefd685466676073a9507666c82e983af8936551c8c3cf825442a123a
K="kubectl -n $NS"

case "${1:-}" in
deploy)
  kubectl get ns $NS >/dev/null 2>&1 || kubectl create ns $NS >/dev/null || exit 1
  $K delete pod lab --ignore-not-found --wait=true >/dev/null 2>&1
  $K delete cm lab-files --ignore-not-found >/dev/null 2>&1
  $K create cm lab-files \
    --from-file=supervisor.sh="$HERE/supervisor.sh" \
    --from-file=episode_driver.py="$HERE/episode_driver.py" \
    --from-file=pom.xml="$ROOT/ops/spring_app/pom.xml" \
    --from-file=AvatarApp.java="$ROOT/ops/spring_app/src/main/java/lab/AvatarApp.java" >/dev/null || exit 1
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: lab, namespace: $NS}
spec:
  nodeName: $NODE
  restartPolicy: Always
  shareProcessNamespace: true
  initContainers:
  - {name: jdk-1708, image: $IMG_1708, command: ["sh","-c","cp -a /opt/java/openjdk /jdks/17.0.8"], volumeMounts: [{name: jdks, mountPath: /jdks}]}
  - {name: jdk-17021, image: $IMG_17021, command: ["sh","-c","cp -a /opt/java/openjdk /jdks/17.0.21"], volumeMounts: [{name: jdks, mountPath: /jdks}]}
  - {name: jdk-170211, image: $IMG_170211, command: ["sh","-c","cp -a /opt/java/openjdk /jdks/17.0.21.1"], volumeMounts: [{name: jdks, mountPath: /jdks}]}
  - name: build
    image: maven:3.9.9-eclipse-temurin-17
    command: ["sh","-c","test -f /share/app.jar && exit 0; mkdir -p /b/src/main/java/lab && cp /v/pom.xml /b/ && cp /v/AvatarApp.java /b/src/main/java/lab/ && cd /b && mvn -q -B package -DskipTests && cp target/avatar-svc-1.0.jar /share/app.jar && sha256sum /share/app.jar"]
    volumeMounts: [{name: v, mountPath: /v}, {name: share, mountPath: /share}]
  containers:
  - name: app
    image: $IMG_1708
    command: ["bash","/v/supervisor.sh"]
    resources: {requests: {cpu: "3", memory: 3Gi}, limits: {cpu: "3", memory: 3Gi}}
    volumeMounts: [{name: v, mountPath: /v}, {name: share, mountPath: /share}, {name: jdks, mountPath: /jdks}]
  - name: driver
    image: python:3.12.7-slim-bookworm
    command: ["sh","-c","echo DRIVER-READY; sleep infinity"]
    resources: {requests: {cpu: "1", memory: 512Mi}, limits: {cpu: "1", memory: 1Gi}}
    volumeMounts: [{name: v, mountPath: /v}, {name: share, mountPath: /share}]
  volumes:
  - {name: v, configMap: {name: lab-files}}
  - {name: share, emptyDir: {}}
  - {name: jdks, emptyDir: {}}
YAML
  for i in $(seq 1 90); do
    ph=$($K get pod lab -o jsonpath='{.status.phase}' 2>/dev/null)
    [ "$ph" = "Running" ] && $K logs lab -c driver 2>/dev/null | grep -q DRIVER-READY && { echo "LAB-READY"; exit 0; }
    sleep 10
  done
  echo "LAB-TIMEOUT"; $K describe pod lab | tail -20; exit 1
  ;;
run)
  SCHED="$2"
  $K exec -i lab -c driver -- sh -c 'cat > /share/schedule.json' < "$SCHED" || exit 1
  $K exec lab -c driver -- sh -c 'cd /share && nohup setsid python3 -u /v/episode_driver.py /share/schedule.json >> /share/driver.log 2>&1 < /dev/null & echo started'
  ;;
status)
  $K exec lab -c driver -- sh -c 'tail -n ${N:-5} /share/driver.log; echo; echo "episodes done: $(ls /share/ep/*/DONE 2>/dev/null | wc -l)  rows: $(wc -l < /share/attempts_all.jsonl 2>/dev/null)"; python3 -c "import os;print(\"DRIVER-RUNNING\" if any(b\"episode_driver.py\" in open(\"/proc/%s/cmdline\"%p,\"rb\").read() for p in os.listdir(\"/proc\") if p.isdigit() and os.path.exists(\"/proc/%s/cmdline\"%p)) else \"DRIVER-STOPPED\")"'
  ;;
pull)
  RUN="$2"; OUT="$ROOT/research/data/$RUN"; mkdir -p "$OUT"
  # stdout.log (PrintCompilation) is large — keep it, but compressed
  $K exec lab -c driver -- sh -c 'cd /share && tar czf - ep attempts_all.jsonl driver.log schedule.json 2>/dev/null' | tar xzf - -C "$OUT" && \
    find "$OUT/ep" -name stdout.log -size +1M -exec gzip -f {} \; ; echo "pulled -> $OUT"; ls "$OUT/ep" | wc -l
  ;;
stop)
  $K exec lab -c driver -- python3 -c '
import os,signal,time
me=os.getpid()
for p in os.listdir("/proc"):
    if p.isdigit() and int(p)!=me:
        try: c=open("/proc/%s/cmdline"%p,"rb").read()
        except Exception: continue
        if b"episode_driver.py" in c: os.kill(int(p),signal.SIGTERM); print("driver stopped",p)
time.sleep(2)
for e in os.listdir("/share/ep"):
    d="/share/ep/"+e
    if os.path.exists(d+"/pid") and not os.path.exists(d+"/exit_code"):
        os.kill(int(open(d+"/pid").read()),signal.SIGTERM); print("jvm stopped",e)
'
  ;;
teardown)
  kubectl delete ns $NS --ignore-not-found --timeout=120s >/dev/null 2>&1; echo NS-CLEAN
  ;;
*) sed -n 2,8p "$0"; exit 2 ;;
esac
