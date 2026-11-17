#!/bin/bash
# 상위 1~4위 후보 클래스 임시 완화 (candidate-triage-2026-11-17.md §4)
# 패치(17.0.21.1)와 무관하게 무해·유효. JDK 내장 기본값 강화 + 공격 경로 차단.
# 사용: mitigate-top4.sh print | env | systemd UNIT [--apply]
set -u
OPTS='-Dcom.sun.jndi.ldap.object.trustURLCodebase=false
-Dcom.sun.jndi.rmi.object.trustURLCodebase=false
-Dcom.sun.jndi.ldap.object.trustSerialData=false
-Djdk.serialFilter=!com.sun.rowset.JdbcRowSetImpl;!com.sun.corba.se.impl.presentation.rmi.IDLNameTranslatorImpl;maxbytes=1000000;maxdepth=64
-Djavax.xml.accessExternalStylesheet=none
-Djavax.xml.accessExternalDTD=none
-Djavax.xml.accessExternalSchema=none'
usage() { sed -n '2,5p' "$0"; exit 1; }
[ $# -lt 1 ] && usage
case "$1" in
print)
  echo "# JAVA_TOOL_OPTIONS — 1위(역직렬화 가젯)·2위(JNDI/LDAP)·3위(XSLT) 완화"
  echo "JAVA_TOOL_OPTIONS=\"$OPTS\""
  echo "# 4위(jdk.httpserver): 플래그 없음 — 노출 서비스만 허용하는 보안그룹/NetworkPolicy로 차단"
  echo "# 패치 적용 후 이 옵션 제거 (기본값 회귀)"
  ;;
env)  echo "$OPTS" ;;
systemd)
  UNIT="${2:?unit명 필요}"; APPLY="${3:-}"
  CONF="/etc/systemd/system/${UNIT}.d/99-triage-top4.conf"
  BODY="[Service]
Environment=\"JAVA_TOOL_OPTIONS=$OPTS\"
# 패치(17.0.21.1) 적용 후 삭제 → daemon-reload && restart
"
  if [ "$APPLY" = "--apply" ]; then
    [ "$(id -u)" -ne 0 ] && { echo "root 필요"; exit 1; }
    mkdir -p "$(dirname "$CONF")"; printf '%s\n' "$BODY" > "$CONF"
    systemctl daemon-reload && echo "작성: $CONF — systemctl restart $UNIT"
  else
    echo "(dry-run) → $CONF"; printf '%s\n' "$BODY"
  fi ;;
*) usage ;;
esac
