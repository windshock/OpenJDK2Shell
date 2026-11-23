#!/bin/bash
# Phase 0 supervisor (P0-1/P0-2) — the container never exits when the JVM dies.
# Each JVM process = one episode. The driver requests an episode by writing
# /share/ctl/next.env (EPID, JDK, FLAGS); this loop launches a FRESH JVM for it,
# records pid/start/exit code, and waits for the next request.
#
# Files per episode (/share/ep/<EPID>/):
#   spec.env  jvm_version.txt  effective_flags.txt  pid  start_ms  stdout.log
#   gc.log  hs_err_pid*.log  exit_code  end_ms
set -u
JAR=/share/app.jar
mkdir -p /share/ctl /share/ep
echo "[sup] supervisor up $(date -u +%FT%TZ)"
while true; do
  if [ ! -f /share/ctl/next.env ]; then sleep 1; continue; fi
  # shellcheck disable=SC1091
  . /share/ctl/next.env
  D=/share/ep/$EPID
  mkdir -p "$D"
  mv /share/ctl/next.env "$D/spec.env"
  J=/jdks/$JDK/bin/java
  "$J" -version > "$D/jvm_version.txt" 2>&1
  "$J" -Xms1280m -Xmx1280m $FLAGS -XX:+PrintFlagsFinal -version 2>/dev/null \
    | grep -E ' (UseBASE64Intrinsics|UseAVX|UseG1GC|G1HeapRegionSize|MaxHeapSize) ' > "$D/effective_flags.txt"
  grep -m1 -o -w -E 'avx512(vbmi|bw|vl|f)|bmi2' /proc/cpuinfo | sort -u | tr '\n' ' ' > "$D/cpu_flags.txt"
  date +%s%3N > "$D/start_ms"
  "$J" -Xms1280m -Xmx1280m $FLAGS \
       -XX:+PrintCompilation -XX:-CreateCoredumpOnCrash \
       -Xlog:gc:file="$D/gc.log":uptime,tags \
       -XX:ErrorFile="$D/hs_err_pid%p.log" \
       -jar "$JAR" > "$D/stdout.log" 2>&1 &
  echo $! > "$D/pid"
  echo "[sup] $EPID started pid=$(cat "$D/pid") jdk=$JDK flags='$FLAGS'"
  wait "$(cat "$D/pid")"
  ec=$?
  date +%s%3N > "$D/end_ms"
  echo "$ec" > "$D/exit_code"
  echo "[sup] $EPID exited code=$ec"
done
