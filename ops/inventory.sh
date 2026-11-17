#!/bin/bash
# H2 노출 인벤토리 — JDK 버전 × AVX-512 CPU × intrinsic 활성 조건 점검
# 사용: ./inventory.sh [java경로]   (기본: PATH의 java)
set -u
JAVA="${1:-java}"
ver="$("$JAVA" -version 2>&1 | head -1 | sed -n 's/.*version "\([^"]*\)".*/\1/p')"
[ -z "$ver" ] && { echo "ERROR: java 인식 실패"; exit 2; }

# AVX-512 감지
AVX=""
if [ "$(uname)" = "Darwin" ]; then
  f="$(sysctl -n machdep.cpu.features 2>/dev/null)$(sysctl -n machdep.cpu.leaf7_features 2>/dev/null)"
  echo "$f" | grep -qi avx512 && AVX=yes
else
  grep -qm1 avx512 /proc/cpuinfo 2>/dev/null && AVX=yes
fi

# intrinsic 활성 여부(x86 product 플래그 존재 여부)
FLAG="$(j="$JAVA"; "$j" -XX:+PrintFlagsFinal -version 2>/dev/null | awk '/UseBASE64Intrinsics/ {print $2"="$4; exit}')"

# H2 가정 하 취약 버전 범위(NCSC "17.0.6 이상" + 현재 패치 라인 17.0.21.0.x 까지)
in_range() {
  case "$1" in
    17.0.[0-5])            return 1 ;;
    17.0.6|17.0.[7-9]|17.0.1[0-9]|17.0.2[01]|17.0.21.0.*) return 0 ;;
    *)                      return 255 ;;  # 타 라인(11/21/25)은 별도 확인
  esac
}
echo "JDK      : $ver ($(uname -m))"
echo "AVX-512  : ${AVX:+yes}${AVX:-no}"
echo "Flag     : ${FLAG:-<없음 — 이 경로 해당 없음(arm64 등)>}"

verdict="N/A"
if in_range "$ver"; then
  if [ -n "$AVX" ]; then verdict="EXPOSED(H2 조건 충족: 버전+AVX-512) — mitigate.sh 적지 권장"
  else verdict="버전은 범위 내, CPU 무AVX-512 → 이 경로 낮음(전제: H2)"
  fi
elif [ $? -eq 255 ]; then
  verdict="타 라인 — Oracle CSPU 11건 대상이므로 17.0.21.1 공개 시 재평가"
else
  verdict="범위 외(17.0.5 이하)"
fi
echo "판정     : $verdict"
