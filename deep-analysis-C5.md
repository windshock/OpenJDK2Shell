# C5 — JSSE 17.0.6 델타 (DH·DTLS·closeInbound·SessionID)

작성: 2026-11-17 (diff 실측 기반)

## 1. 도입 시점 (실측 — 4커밋 모두 17.0.6 탑재)
| 커밋 | 내용 | 규모 |
|---|---|---|
| 8293554 Enhanced DH Key Exchanges | DH 파라미터·지수 크기 로직 재작성 | 5파일, 순수 Java |
| 8287411 Enhance DTLS performance | **세션 재개 시 쿠키 검증을 스킵하는 동작 변경**(속성 게이트) | ClientHello 25+/17-, SSLConfiguration +3 |
| 8273553 closeInbound 오류 처리 | close_notify 부재 시 예외 경로 수정 | SSLEngine/Socket 20-, 테스트 491줄 |
| 8277881 TLS1.3 SessionID compat | 호환 모드 SessionID 생성 조건 | ClientHello 16-/16+ |

## 2. 코드 형태
**전부 순수 Java 상태처리**(핸드셰이크 상태머신·파라미터 로직). 네이티브 무.
RCE 9.2 형태(메모리 커럽션)와 불일치 — 실현 등급은 DoS·상태혼동·(DTLS 쿠키의 경우)
재개 우회급.

## 3. pre-auth 도달 경로
DTLS/TLS 핸드셰이크는 **인증 이전** — 도달성은 4후보 중 최상(서버 포트 개방이 전부).

## 4-5. 입력 축·관측 축 (설계는 가능하나 차선 처리 근거)
핸드셰이크 결과 차등(17.0.5 vs 17.0.6 이미지 병렬)·DTLS 쿠키 변형·close_notify 절단.
형태상 RCE가 아니므로 클러스터 실측은 **C1·C2 이후 차선**으로 연기(골 §4의 균등 원칙 하,
형태 불일치는 명시적 감점 사유).

## 7. 판정
**미지지(형태)** — 4커밋 모두 RCE 9.2와 불일치. 단 8287411(DTLS 재개 쿠키 검증 스킵)은
pre-auth 상태머신 변경으로 **C7 스윕에서 최우선 재검토 대상**. 패치 diff가
sun/security/ssl을 건드리면 확장 분석 개시.
