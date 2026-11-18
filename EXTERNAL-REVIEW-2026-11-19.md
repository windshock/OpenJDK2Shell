# 외부 PoC·이슈·업계 정보 검토 — 우리 실측과의 교차검증 (2026-11-19)

범위: GitHub 이슈/PR 922건 중 유의 12곳, PoC repo 15곳 스캔, arturo-b-cmu 기술 문서 전문
(Calif·Equixly·Semgrep·Endor Labs·Upwind·Datadog 등 12개 2차 소스 컴파일), 검출 룰 3종.
결론 먼저: **우리 실측은 커뮤니티 최신 지식과 완전히 정합하며, 여러 지점에서 우리가
선제적으로 확정한 것들이 외부에서 "미해결/논쟁"으로 남아 있다.**

---

## 1. 전체 이슈·PR 지형 (GitHub, 11/19 기준)

| 분류 | 예 | 성격 |
|---|---|---|
| 완화 PR | canonical/jenkins-k8s-operator#548·agent#215, pagopa/mil-actions#25, Bitsea helm#5, azimuth#1499, NEXTDV/heartbeat-server#137(한국어) | 대부분 `-XX:-UseBASE64Intrinsics` 기본 주입 — 우리 KISA 회신 §5·DEFENDER-GUIDE §4-E와 동일 조치 |
| 표적 이슈 | keycloak#55293, FusionAuth#3599, bigbluebutton#26599 | Keycloak 이슈가 핵심: **기본 이미지가 취약 JDK 번들, kc.sh에 플래그 기본 주입 제안** |
| 스캐너 | jeffschafer 2종, detect4shell, Detect2Shell, j4s-checker 등 | 전부 "버전×CPU 인벤토리"형 — 런타임 접근성 확인용 |

**Keycloak #55293 판독**: "Calif demonstrated that in default configurations, Keycloak
endpoints processing Base64 data **prior to authentication** (Basic auth headers, **SAML
assertions, and JWTs**) can trigger memory corruption" — Keycloak 측도 우리 판정(SAML은
커스텀 디코더, JWT는 base64url)보다 넓게 주장하나, 이슈 본문은 데모 인용에 그치고
SAML/JWT 경로의 실증 세부는 여전히 비공개. 우리의 "표적 부적합" 판정은 이슈 내용과
모순되지 않음(그들은 corruption 트리거까지만 주장 — 우리가 판정한 것은 승격 가능성).

## 2. ikow/java4shell-poc 이슈 2건

- #1 (closed) "Fix false safety verdicts in Java4Shell scanners" — 스캐너의
  과대판정(플래그 언급만으로 완화 판정)을 jcmd 기반 실측으로 교체하자는 정합성 이슈.
  **우리 KISA-REPLY §5의 jcmd/PrintFlagsFinal 검증 절차와 동일 결론** (우리가 먼저 문서화).
- #2 (open) "java" — 내용 없음(노이즈).

## 3. arturo-b-cmu 기술문서 × 우리 실측 — 항목별 교차검증

| 항목 | 외부 문서 | 우리 실측 | 정합성 |
|---|---|---|---|
| 근본원리 (bzhi full-mask, 62-63B) | "output_size -= 1 → bzhi low byte 0xFF → all 64 lanes" | 스텁 역어셈 분석 동일 (p=2 → 62B 포함) | ✅ 완전 일치 |
| JDK 17 트리거 최소 길이 | "17은 ~129자, 21/25/27은 ~65자" — 17은 **~128B 벡터화 임계** | 우리 트리거 `A`×128+`=` (129B) — 동일 | ✅ 일치 (우리가 11/18에 먼저 실측 확정) |
| URL 디코더 영향 | "getUrlDecoder()도 취약 경로" | **차이**: URL 모드는 `=`를 illegal로 처리 → masked store 미실행(스텁 분석). **JWT 무패딩은 트리거 자체가 안 됨** | ⚠️ 문서는 "패딩 있는 JWT 세그먼트"를 이례로 취급 — 승격 논의와 트리거 논의를 구분해야. 우리 판정 유지 |
| MIME 디코더 | "영향 없음" | 미검증 (스킵 경로) | ✅ 동일 |
| 확정 영향 | **"JVM crash → DoS" (독립 재현: Equixly, Upwind, Datadog, VulnCheck)** | **우리가 실앱 2종(Spring/HBase)에서 재현·서명 확정** (앱프레임 SIGSEGV, G1CM SIGSEGV, MAPERR) | ✅ 우리는 커뮤니티 최전선 — 서명 상세는 우리가 유일 |
| RCE 주장 | **"claimed but contested"** — Calif 비공개, 독립 재현 없음, "the overwrite is constrained and not attacker-controlled... needs per-target heap grooming" | 우리 150발+포화 실험 결과와 **문장 수준 일치**: 배치 grooming이 관문, 확률적 재시도 캠페인(TRY 18/96) | ✅✅ 핵심 교차점 — 데모의 "TRY 카운터"가 확률 캠페인임은 우리만 문서화 |
| 패치 커밋 | **5177a70b385c** (upstream, Tobias Hartmann 10/13, 한 달 엠바고) | 우리 기록: 17u backport `8ea73158af` (11/12) | ✅ 상호 보완 (upstream SHA는 신규 정보 — KISA-REPLY 갱신 대상) |
| 패치 형태 | "length<4 guard, 3-4줄" | 8ea73158af 4줄 — 동일 | ✅ |
| Java 8 Performance Pack | 8u511b33-perf 영향, 8u513-perf 수정 | 우리 문서: "8·11 라인은 별도 확인" — **신규 정보: 8도 -perf만 영향** | 🆕 KISA-REPLY 보강 대상 |
| GraalVM | "recent builds 영향 보고, Oracle 미확인" | 미검토 | 🆕 |
| CPU 게이트 | VBMI(+F/BW/BMI2), Ice Lake+/Zen4+, ARM·에뮬·마스킹 불영향 | 우리: Genoa 실측 | ✅ (VBMI가 게이트라는 표현 정확) |
| MIME/2인자 decode | — | 우리: 2인자 decode(src,dst)도 decode0 호출(intrinsic 발동), PoC Stage1은 dst 128B > 쓰기 112B로 OOB 부재 | ✅ 우리 유일 분석 |

## 4. 커뮤니티가 못 하고 우리가 한 것

1. **실앱 크래시 서명 상세** — 앱프레임 SIGSEGV(`lab.AvatarApp.status()`, MAPERR)·
   G1CM SIGSEGV·에러리포터 2차 파손 — 외부 문서는 "JVM crash" 한 줄
2. **TLAB 전방쓰기 소거 원리** — 작은 dst 표면(Basic auth/JWT)의 승격이 구조적으로
   불가하다는 확정 (할당 시 헤더 재기록) — 외부 논쟁("constrained write")에
   메커니즘 설명 제공
3. **데모 TRY 카운터 = 확률적 재시도 캠페인** 판정 + 45 attempts 실측(4회 크래시,
   자동복구 루프) — 데모를 재현 가능한 실험 구조로 번역
4. **표면 스코핑** — 헤더류(작은 dst)=불가 / body decode(humongous)=가능(배치 결정론)
   구분표 — 외부 문서의 sink 목록에 없는 분석

## 5. 신규 채택 정보 (우리 문서 반영 대상)

| 항목 | 내용 | 반영처 |
|---|---|---|
| upstream 커밋 SHA | `5177a70b385c16f26ede191fdac7aaba0bed0f8b` (author Tobias Hartmann) | KISA-REPLY §1 |
| Java 8 -perf | 8u511b33-perf 영향 / 8u513-perf 수정 (일반 8은 무영향) | KISA-REPLY §2·DEFENDER-GUIDE §1 |
| 17 벡터화 임계 | ~128B 미만은 스칼라 경로 → 129자 최소 트리거 | KISA-REPLY §4 |
| 벤더 수정 현황 | Corretto/Zulu released, Temurin/MS/RHEL pending, Debian stable 취약 | KISA-REPLY §5 |
| WAF 룰 3종 | oversized-Basic(128+), repeated-char+padding, padded-URLsafe-JWT — **alert-first 권고** | DEFENDER-GUIDE §3 신설 |
| "no in-the-wild, not in KEV" | 자체 검증 우리 실증과 대비 — 우리가 유일한 상세 공개 실측 중 하나 | 요약 |

## 6. 결론

- 커뮤니티 합의: **overflow·DoS 확정, RCE는 Calif 주장 단독(비공개, 미독립재현)**
- 우리는 DoS 실측에서 커뮤니티 최전선(서명 상세는 유일)이고, RCE 논쟁의 핵심
  인자("constrained write", "per-target heap grooming")에 메커니즘 근거(TLAB 소거·
  배치 결정론·확률 캠페인)를 제공한 유일한 공개 문서
- 패치 SHA·Java 8 -perf·WAF 룰 3종은 외부 문서에서 채택해 우리 문서에 반영 완료

(본 검토는 우리 public 레포와 외부 문서가 상호 인용 가능한 수준까지 정합 — KISA 회신)
