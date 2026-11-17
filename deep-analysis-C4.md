# C4 — JDWP 백엔드

작성: 2026-11-17 (GOAL-deep-analysis 템플릿)

## 1. 도입 시점
17.0.6 델타에 JDWP 관련 변경으로 `8256811`(Delayed/missed jdwp class unloading events,
이벤트 지연 수정) 1건 — 기능 수정이며 공격면 도입 아님.

## 2. 코드 형태
JDWP 백엔드는 네이티브(dt preprocessing 없는 C++) — 형태상 커럽션 가능은 있으나:

## 3. pre-auth 도달 경로 — **결정적 결격**
JDWP 리스너는 **`-agentlib:jdwp=...,server=y` 명시적 실행 옵션**이 있어야만 활성화.
미인증 리스너이긴 하나 비기본 구성. "인증 없는 RCE 9.2"가 무조건부 전제라면
CVSS 산정에서 "이런 구성 필요"는 감점 요인 — 9.2 무조건부와 불일치.

## 7. 판정
**미지지(형태/도달 전제)**. 예외: 공지 원문에 "디버그 활성 서버" 조건이 발견되면
즉시 재평가. 패치 diff가 src/jdk.jdwp를 건드리는지로 최종 확인.
