# Phase B 확정 — CVE-2026-114938 (hotspot/compiler) 판정

작성: 2026-11-18 새벽 · 근거: OpenJDK Advisory 2026/11/17 + jdk11u 커밋

## 진범

**CVE-2026-114938 | hotspot/compiler | CVSS 8.1 (NHNNUNHHN)**

| 항목 | 값 | 해석 |
|---|---|---|
| Vector | AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | 네트워크, 고복잡도, 무인증, 전체침해 |
| 커밋 | `8389989: Enhance loop handling` | C2 JIT 루프 최적화 |
| v4.0 환산 | ≈ 9.2 | **NCSC 공지 CVSS 9.2와 정합** |
| 버전 | "17.0.21.0.3 and earlier" | 17.0.6+ 하한의 출처는 C2 루프 버그 도입 시점 추정 |

## 우리 가설과의 대조

| 가설 | 판정 | 근거 |
|---|---|---|
| H2 (Base64 AVX-512 intrinsic) | **기각** | Risk matrix에 Base64 없음. stubGenerator 수정 없음 |
| H5 (HotSpot 문자열/UTF-8) | **재분류** | hotspot이 맞지만 compiler이지 string이 아님 |
| A1 (RMI 역직렬화) | **별개 경로** | 독립 RCE 프리미티브로 유효, CSPU와 무관 |
| A2 (LDAP trustSerialData) | **별개 경로** | 17.0.13+에서 이미 수정, CSPU와 무관 |
| A3 (TemplatesImpl RCE) | **별개 경로** | 17.0.21에서 이미 수정, CSPU와 무관 |

## C2 JIT 루프 버그의 공격 구조

```
① 공격자 입력 → 자바 앱 → 특정 바이트코드 패턴 실행
② C2 JIT 컴파일 → 루프 최적화 버그 포함 네이티브 코드 생성
③ 컴파일 코드의 경계검사 누락/OOB → 메모리 커럽션
④ AC:H = 패턴이 JIT 컴파일돼야 함 (해석 실행 시에는 안전)
```

이는 **CVE-2024-21131/21147**(HotSpot 컴파일러, AC:H)과 동일 클래스 — Oracle이
"외부 데이터가 취약 API에 전달되는 경로"를 악용 조건으로 명시했던 선례와 부합.

## 11건 전체 요약

| CVE | Component | CVSS | 우리가 찾은 것과의 관계 |
|---|---|---|---|
| **114938** | **hotspot/compiler (C2 loop)** | **8.1** | **CSPU 최고점 — 우리 미탐 영역** |
| 114941 | hotspot/compiler (C2 cmp) | 7.0 | 동일 클래스 |
| 114946 | hotspot/compiler | 4.8 | 동일 클래스 |
| 114939 | security-libs/jgss | 7.4 | triage 6위 적중 |
| 114940 | security-libs/javax.net.ssl | 7.4 | triage 9위 (형태 기각했던) |
| 114942 | core-libs | 7.0 | triage 4위 적중 |
| 114943 | hotspot/runtime | 6.5 | 미순위 |
| 114944 | core-svc/mgmt | 5.9 | triage 1위 인접 (JMX) |
| 114945 | core-libs/java.lang | 5.3 | 미순위 |
| 114947 | security-libs/javax.net.ssl | 3.7 | triage 9위 |
| 86144 | javafx/web | 7.5 | 17 라인 무관 |

## triage 교훈

1. **base-rate만 보면 blind spot**: "JIT 컴파일러 버그"는 역사적 빈도가 낮아 최하위
   우선순위였으나 실제 최고점. 보안공지의 AC:H+8.1 시그널을 base-rate보다 먼저
   봤어야 함.
2. **형태 분석 우선**: 순수 Java 아닌 네이티브 = JIT 생성 코드임을 간과. "native code
   = C로 작성된 것"이 아니라 "JIT가 생성하는 것"도 네이티브.
3. **P1(17.0.6 하한)의 새 해석**: C2 루프 최적화 코드가 17.0.6에 backport/변경됐을
   가능성 — jdk17u push 후 diff로 확인.

## 다음 단계

jdk17u에 `8389989`가 push되면:
1. diff에서 정확한 루프 최적화 결함 파악
2. 회귀 테스트에서 공격 입력 축 추출
3. 17.0.8 DFIRtx 클러스터에서 재현
4. 완화: `-XX:TieredStopAtLevel=1`(C2 비활성) 유효성 확인
