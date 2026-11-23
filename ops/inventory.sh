#!/bin/bash
# CVE-2026-114938 (Java4Shell) 노출 인벤토리 — JDK 버전 × CPU(VBMI+BW) × intrinsic 플래그
# 사용: ./inventory.sh [java경로]          (기본: PATH의 java)
#       PID=<pid> ./inventory.sh           (실행 중 프로세스의 실제 플래그를 jcmd로 확인)
# 판정 근거 (2026-11-23 소스 재확인, CORRECTION-3 C-10):
#   - intrinsic 에르고노믹스: UseAVX>2 && avx512vl && avx512bw  (vm_version_x86.cpp)
#   - 취약 벡터 경로 생성:   avx512_vbmi && avx512bw             (stubGenerator_x86_64.cpp)
#   - 수정 빌드: 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 (Temurin +2/+2/+2/+4)
set -u
JAVA="${1:-java}"
ver="$("$JAVA" -version 2>&1 | head -1 | sed -n 's/.*version "\([^"]*\)".*/\1/p')"
[ -z "$ver" ] && { echo "ERROR: java 인식 실패"; exit 2; }

ARCH="$(uname -m)"
flags=""
if [ -r /proc/cpuinfo ]; then
  flags="$(grep -m1 '^flags' /proc/cpuinfo)"
elif [ "$(uname)" = "Darwin" ]; then
  flags="$(sysctl -n machdep.cpu.features machdep.cpu.leaf7_features 2>/dev/null | tr 'A-Z' 'a-z' | tr '.' '_')"
fi
has() { echo " $flags " | grep -qw "$1"; }
VBMI=no; BW=no; VL=no
has avx512vbmi && VBMI=yes
has avx512bw && BW=yes
has avx512vl && VL=yes

# 실행 중 프로세스 우선 (설정 파일이 아니라 실제 JVM 상태)
if [ -n "${PID:-}" ] && command -v jcmd >/dev/null 2>&1; then
  FLAG="$(jcmd "$PID" VM.flags -all 2>/dev/null | awk '/UseBASE64Intrinsics/ {print $2"="$4" "$5; exit}')"
  FLAGSRC="jcmd pid=$PID"
else
  FLAG="$("$JAVA" -XX:+PrintFlagsFinal -version 2>/dev/null | awk '/UseBASE64Intrinsics/ {print $2"="$4" "$5; exit}')"
  FLAGSRC="PrintFlagsFinal (새 JVM 기준 — 운영 프로세스는 PID= 로 확인)"
fi

# 버전 비교: $1 < $2 ?  (점 구분 숫자, +빌드 접미사 제거)
vlt() { local a b; a="${1%%+*}"; b="$2"
  [ "$(printf '%s\n%s\n' "$a" "$b" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | head -1)" = "$a" ] && [ "$a" != "$b" ]; }
vuln_ver() {   # 0=영향, 1=수정/범위 외, 2=모름
  local v="${1%%+*}"; local major="${v%%.*}"
  case "$major" in
    17) vlt "$v" "17.0.6" && return 1; vlt "$v" "17.0.21.1" && return 0; return 1 ;;
    21) vlt "$v" "21.0.13.1" && return 0; return 1 ;;
    25) vlt "$v" "25.0.5.1" && return 0; return 1 ;;
    27) vlt "$v" "27.0.1.1" && return 0; return 1 ;;
    1|11) return 1 ;;   # 표준 8/11 무영향 (Oracle 8 Performance Pack은 별도 확인)
    *) return 2 ;;
  esac
}

echo "JDK      : $ver ($ARCH)"
echo "CPU      : avx512vbmi=$VBMI avx512bw=$BW avx512vl=$VL"
echo "Flag     : ${FLAG:-<없음 — x86 아님 등>}  [$FLAGSRC]"

vuln_ver "$ver"; vr=$?
if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "amd64" ]; then
  verdict="NOT AFFECTED — x86-64 아님"
elif [ $vr -eq 2 ]; then
  verdict="UNKNOWN — 타 라인, 벤더 공지로 개별 확인"
elif [ $vr -eq 1 ]; then
  verdict="NOT AFFECTED — 범위 외 또는 수정 빌드"
elif [ "$VBMI" != yes ] || [ "$BW" != yes ]; then
  verdict="LOW — 버전은 영향 범위지만 CPU에 VBMI+BW 없음 → 취약 벡터 경로 미생성 (하드웨어 이전 시 재평가)"
elif echo "$FLAG" | grep -q 'false'; then
  verdict="MITIGATED — UseBASE64Intrinsics=false (패치 전 임시 상태, 업그레이드 필요)"
else
  verdict="EXPOSED — 버전+VBMI CPU+intrinsic 활성. 17.0.21.1(.1 빌드) 업그레이드 또는 -XX:-UseBASE64Intrinsics"
fi
echo "판정     : $verdict"
echo "남은 조건: 공격자 입력이 java.util.Base64.Decoder에 도달하는지 (sink 인벤토리 — DEFENDER-GUIDE §0-1)"
