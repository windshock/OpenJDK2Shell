#!/bin/bash
# x86_64 컨테이너에서 E2E 실행 — colima(x86_64 VM) 또는 실제 x86 호스트에서
# 사용: ops/docker/run_x64.sh [--smoke]
# AVX-512 호스트에서는 동일 명령이 VBMI fast path(오딧트 대상)까지 검증한다.
set -e
BASE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$BASE/../.." && pwd)"
EXTRA="${1:-}"

echo "== CPU 플래그 실측 (AVX-512 여부 = VBMI 경로 활성 조건) =="
docker run --rm --platform linux/amd64 oj2s-x64 \
  sh -c 'grep -m1 "^flags" /proc/cpuinfo | tr " " "\n" | grep -E "^avx" | sort -u | tr "\n" " "; echo; /opt/jdk/bin/java -version 2>&1 | head -1; /opt/jdk/bin/java -XX:+PrintFlagsFinal -version 2>/dev/null | grep -w UseBASE64Intrinsics'

echo
echo "== E2E differential (intrinsic 강제 on vs off) =="
docker run --rm --platform linux/amd64 -v "$ROOT/exploit:/h" -w /h oj2s-x64 \
  python3 e2e.py --java /opt/jdk/bin/java --diff $EXTRA
