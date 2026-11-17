#!/bin/bash
# 익스플로이션 시도/크래시 tripwire — JVM 치명적 오류 로그에서 Base64 경로 흔적 탐지
# 사용: ./scan_hs_err.sh <루트디렉터리...> [최근 N시간, 기본 72]
# 주의: H2 특화 시그니처는 아님(프리미티브 미확정) — '인증 전 디코드를 하는 서비스의
# 설명 없는 SIGSEGV' 를 후보로 올리는 역할. 확정 시그니처는 패치 diff 확보 후 갱신.
set -u
HOURS="${@: -1}"
re='^[0-9]+$'
if ! [[ "$HOURS" =~ $re ]]; then HOURS=72; fi
DIRS=("$@")
[ "${#DIRS[@]}" -ge 2 ] && [ "${DIRS[-1]}" = "$HOURS" ] && unset 'DIRS[-1]'

mins=$((HOURS * 60))
for d in "${DIRS[@]}"; do
  [ -d "$d" ] || continue
  while IFS= read -r f; do
    sig="$(grep -m1 'Current thread' "$f" 2>/dev/null | cut -c1-100)"
    if grep -qm1 -e 'Base64' -e 'decodeBlock' -e 'stubGenerator' "$f" 2>/dev/null; then
      echo "HIT(Base64 관련): $f"
      grep -m2 -e 'SIGSEGV' -e 'SIGBUS' -e 'Problematic frame' "$f" | sed 's/^/    /'
      echo "    $sig"
    else
      echo "candidate: $f — $sig"
    fi
  done < <(find "$d" -name 'hs_err_pid*.log' -mmin "-$mins" 2>/dev/null)
done
echo "스캔 완료(최근 ${HOURS}h). HIT 발견 시: 로그 원본 보존 + vuln-analysis §8.4 절차."
