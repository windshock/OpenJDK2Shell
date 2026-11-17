#!/bin/bash
# H2(Base64 AVX-512 intrinsic) 임시 패치 — Oracle 17.0.21.1 정식 패치 전까지의 완화
# 근거(저장소 검증): 스텁 생성이 if (UseBASE64Intrinsics) 하위 — product 플래그로
# 인트린식만 차단, 디코드는 Java 폴백으로 정상 동작. 패치 후 옵션 제거.
set -u
OPT="-XX:-UseBASE64Intrinsics"
FALLBACK="-XX:TieredStopAtLevel=1"   # UseBASE64Intrinsics 미지원 구버전용(성능 영향 큼)

usage() { sed -n '2,8p' "$0"; echo "  $0 print            — 적용할 JVM 옵션 출력
  $0 verify [java]    — 현재 플래그 상태 확인(x86에서 bool false 여부)
  $0 systemd UNIT [--apply] — systemd drop-in 작성(기본 dry-run)
  $0 waf              — nginx 사전검증 스니펫 출력"; exit 1; }
[ $# -lt 1 ] && usage

case "$1" in
print)
  echo "JAVA_TOOL_OPTIONS=\"$OPT\""
  echo "# 미지원 구버전 폴백: $FALLBACK (C2 전체 억제 — 성능 영향 큼, 최후 수단)"
  ;;
verify)
  J="${2:-java}"
  out="$("$J" -XX:+PrintFlagsFinal -version 2>/dev/null | grep -w UseBASE64Intrinsics)"
  if [ -z "$out" ]; then
    echo "플래그 없음(arm64 등) → 이 경로 해당 없음"
  else
    echo "$out"
    echo "$out" | grep -q 'bool UseBASE64Intrinsics = false' && echo "→ 완화 적용됨" || echo "→ 미적용(취약 경로 활성)"
  fi
  ;;
systemd)
  UNIT="${2:?unit명 필요 (예: myapp.service)}"; APPLY="${3:-}"
  CONF="/etc/systemd/system/${UNIT}.d/99-h2base64.conf"
  BODY="[Service]
Environment=\"JAVA_TOOL_OPTIONS=$OPT\"
# 패치(17.0.21.1) 적용 후 이 파일 삭제 후 daemon-reload && restart
"
  if [ "$APPLY" = "--apply" ]; then
    [ "$(id -u)" -ne 0 ] && { echo "root 필요"; exit 1; }
    mkdir -p "$(dirname "$CONF")"; printf '%s\n' "$BODY" > "$CONF"
    systemctl daemon-reload && echo "작성됨: $CONF — systemctl restart $UNIT 로 반영"
  else
    echo "(dry-run) $CONF 에 작성할 내용:"; printf '%s\n' "$BODY"
  fi
  ;;
waf)
  cat <<'EOF'
# nginx: Basic 인증 페이로드 사전 검증 — 캐릭터셋/길이 위반은 앱 도달 전 차단
# (MIME 쓰레기·경계 길이 트리거가 Base64 디코더에 닿기 전에 걸러짐)
map $http_authorization $bad_basic {
    default 0;
    "~*^Basic [A-Za-z0-9+/=]{1,8192}\s*$" 0;
    "~*^Basic " 1;
}
# server { ... } 내:
#   if ($bad_basic) { return 400; }
EOF
  echo
  echo "# 앱 레벨(예: 게이트웨이 필터) — 디코드 전 동일 규칙 + /nio·/mime 유사 경로 바디 검증"
  ;;
*) usage ;;
esac
