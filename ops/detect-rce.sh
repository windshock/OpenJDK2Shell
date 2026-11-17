#!/bin/bash
# RCE 시도 탐지 축 (candidate-triage §4 — 기존 hs_err 축만으론 1~3위를 못 봄)
# ① JVM 자식프로세스 생성 ② JVM→외부 LDAP/RMI 콜백 ③ 직렬화/XSLT/파싱 예외 폭주
# 사용: detect-rce.sh [로그 디렉터리...] (기본: /var/log)
# live 모드(현재 호스트): detect-rce.sh --live
set -u
if [ "${1:-}" = "--live" ]; then
  echo "== live: java 프로세스의 외부 연결 (389/636/1099/1389 = LDAP/RMI 콜백) =="
  ss -tnp 2>/dev/null | awk '/java/ && /:(389|636|1099|1389) /'
  echo "== live: java가 띄운 자식 프로세스 =="
  pgrep -f 'java' | while read -r p; do pgrep -P "$p" 2>/dev/null; done | xargs -r ps -o pid,comm,args -p 2>/dev/null | head -10
  exit 0
fi
DIRS=("$@"); [ ${#DIRS[@]} -eq 0 ] && DIRS=(/var/log)
echo "== 로그 기반: 직렬화/XSLT/JNDI/파싱 예외 (최근 24h) =="
grep -rhiE 'InvalidClassException|ObjectInputFilter.*reject|Transformer(Factory)?Exception|SAXParseException|NotSerializableException' \
  "${DIRS[@]}" 2>/dev/null | grep -vE 'DEBUG|health' | tail -20
echo "== 로그 기반: 셸/exec 실행 흔적 =="
grep -rhiE 'ProcessBuilder|Runtime\.getRuntime\(\)\.exec|/bin/(sh|bash) -c' \
  "${DIRS[@]}" 2>/dev/null | tail -10
echo "완료. 유의미한 hit = 즉시 보존(로그 원본+타임스탬프) 후 vuln-analysis §8.4 이행."
