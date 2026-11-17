#!/bin/bash
# OpenJDK 17.0.21.1 OOB 패치 공개 감시 — GitHub API 폴링(git fetch/blob 없음 = 디스크 안전)
# NEW: 줄이 출력되면 vuln-analysis-2026-11-17.md §8.4 절차로 이행.
set -u
BASE="$(cd "$(dirname "$0")" && pwd)"
STATE="$BASE/.monitor_state"
API="https://api.github.com/repos"

jget() { curl -sf --max-time 20 "$1" || echo '{}'; }
head_sha() { jget "$API/$1/commits?sha=$2&per_page=1" | python3 -c 'import json,sys
try: print(json.load(sys.stdin)[0]["sha"])
except Exception: print("-")' 2>/dev/null; }
tag_list() { jget "$API/$1/tags?per_page=100" | python3 -c 'import json,sys
try: print("\n".join(t["name"] for t in json.load(sys.stdin)))
except Exception: pass' 2>/dev/null; }

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

if [ "$NEW" -eq 1 ]; then
  echo "→ 조치: ./check_patch.sh 후 git -C jdk17u log jdk-17.0.21.0.3-ga..origin/jdk17.0.21.1 --stat"
  command -v osascript >/dev/null && osascript -e 'display notification "jdk17u OOB 갱신 감지" with title "OpenJDK 패치 감시"' 2>/dev/null
  exit 1
fi
echo "변화 없음 ($(date '+%H:%M'))"
