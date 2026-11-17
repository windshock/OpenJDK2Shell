#!/bin/bash
# OpenJDK 17u 비정기(OOB) 보안 패치 공개 여부 확인
# 과거 패턴: 릴리스 당일 jdk17.0.X.1 브랜치에 "Enhance/Improve ..." 커밋 + jdk-17.0.X.1-ga 태그가 함께 올라옴
REPO="$(dirname "$0")/jdk17u"
BRANCH=jdk17.0.21.1
BASE=jdk-17.0.21.0.3-ga

git -C "$REPO" fetch -q --tags origin
echo "== GA 태그"
git -C "$REPO" tag -l 'jdk-17.0.21.1*' 'jdk-17.0.22*' | grep -- '-ga' || echo "(아직 없음)"
echo "== $BRANCH 의 보안 의심 커밋"
git -C "$REPO" log --format='%h %ci %an | %s' "$BASE..origin/$BRANCH" \
  | grep -iE 'enhance|improve|better|strengthen' || echo "(아직 없음)"
echo "== 다른 LTS OOB 태그"
for r in jdk11u jdk21u jdk25u; do
  git ls-remote --tags "https://github.com/openjdk/$r.git" | grep -E '\.1-ga$' | awk '{print $2}' | sort -V | tail -1
done
# 커밋이 보이면: git -C jdk17u show <hash>  (수정 코드 + 회귀 테스트 diff)
