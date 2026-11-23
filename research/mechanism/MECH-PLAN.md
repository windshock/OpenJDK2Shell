# 중간 기전 확인 — 진단 계획 (2026-11-23)

실험 A(`research/RESULTS-2026-11-23.md`)가 비워 둔 칸, 감사 지적(기전 미관측), CORRECTION-3 C-3
("쓰기 폭 실측 아님")을 메운다. **진단/포렌식이며 승격 연구가 아니다.**

## 측정 범위
| 측정 대상 | 측정 범위 밖 |
|---|---|
| OOB 쓰기 → 인접 live 객체 **헤더 손상**의 바이트 단위 관측 | 손상 **값·부호의 제어** (11/18 부호 제어 미달 기록) |
| 손상 필드 식별 (mark/klass/length/body) | 제어 가능한 읽기/쓰기 primitive |
| GC 검증기의 손상 객체 지목 관측 (기전 확정) | 정보 유출 / 코드 실행 |

## 방법
- **A (실제 취약 빌드):** Temurin 17.0.21+9에서 `MechProbe` — OobCanary의 검증된 humongous
  갭 grooming을 그대로 쓰고, 인접 canary의 헤더 워드(mark@0·narrowKlass@8·length@12)와 본문
  앞 48B를 `jdk.internal.misc.Unsafe`로 **원시 읽기**(손상 klass를 역참조하지 않음). trigger 전
  pristine 사본과 diff → 바뀐 바이트 지도·폭·대상 필드. C-3의 폭 미실측을 실측으로 확정.
- **B (fastdebug 빌드):** 같은 소스(jdk-17.0.21.0.3-ga)를 `--with-debug-level=fastdebug`로 빌드,
  `-XX:+VerifyBeforeGC/+VerifyAfterGC`로 실행. trigger 후 GC를 강제하면 힙 **검증기가 전 객체를
  순회**하다 손상 객체를 **주소·필드와 함께 지목**한다 = "GC가 손상 객체를 밟는다"의 결정적·
  VM-authored 증거. fastdebug는 **별도 바이너리**라 인과 arm엔 쓰지 않고 기전 진단으로만.

## 산출
`research/mechanism/MECH-RESULTS.md` — A의 바이트 지도, B의 검증기 리포트, C-3 갱신.
