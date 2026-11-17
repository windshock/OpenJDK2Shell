#!/bin/bash
# OpenJDK 17.0.21.1 OOB 패치 공개 감시 — GitHub API 폴링(git fetch/blob 없음 = 디스크 안전)
# NEW: 줄이 출력되면 vuln-analysis-2026-11-17.md §8.4 절차로 이행.
set -u
BASE="$(cd "$(dirname "$0")" && pwd)"
STATE="$BASE/.monitor_state"
API="https://api.github.com/repos"

# gh 인증 API 사용(레이트리밋 회피). 경로에 owner(openjdk) 필수 — 누락 시 404로
# 상태가 조용히 비효시돼 오탐(2026-11-17 사고의 진짜 원인)
head_sha() { gh api "repos/openjdk/$1/commits?sha=$2&per_page=1" --jq '.[0].sha' 2>/dev/null || echo "-"; }
tag_list() { gh api "repos/openjdk/$1/tags?per_page=100" --jq '.[].name' 2>/dev/null || echo "FETCH_FAIL"; }

snapshot() {
  echo "== branch heads =="
  for r in jdk17u:jdk17.0.21.1 jdk11u:jdk11.0.33.1 jdk21u:jdk21.0.13.1 jdk25u:jdk25.0.5.1; do
    echo "$r $(head_sha "${r%%:*}" "${r##*:}")"
  done
  echo "== jdk17u 관련 태그 =="
  tag_list openjdk/jdk17u | grep -E '^jdk-17\.0\.(21\.1|22)' || true
}

NEW=0
cur="$(snapshot)"
if echo "$cur" | grep -qE '( -$|FETCH_FAIL)'; then
  echo "(API 일부 실패 — 오탐 방지 위해 상태 갱신 생략)"
else
  if [ -f "$STATE" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      case "$line" in
        '== '* ) ;;                      # 섹션 헤더
        *) if ! grep -qxF "$line" "$STATE"; then echo "NEW: $line"; NEW=1; fi ;;
      esac
    done <<< "$cur"
  else
    echo "(초기 스냅샷 — 상태 저장)"
  fi
  printf '%s\n' "$cur" > "$STATE"
fi

if [ "$NEW" -eq 1 ]; then
  echo "→ 조치: ./check_patch.sh 후 git -C jdk17u log jdk-17.0.21.0.3-ga..origin/jdk17.0.21.1 --stat"
  command -v osascript >/dev/null && osascript -e 'display notification "jdk17u OOB 갱신 감지" with title "OpenJDK 패치 감시"' 2>/dev/null
  exit 1
fi
echo "변화 없음 ($(date '+%H:%M'))"
