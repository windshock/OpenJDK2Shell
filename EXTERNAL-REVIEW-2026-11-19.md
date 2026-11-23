# 외부 PoC·이슈·업계 정보 검토 — 우리 실측과의 교차검증 (2026-11-19)

> **⚠ 2026-11-23 정정 반영** — `CORRECTION-3.md` 참조 (정정 전 문장은 그 문서에 원문 보존).


범위: GitHub 이슈/PR 922건 중 유의 12곳, PoC repo 15곳 스캔, arturo-b-cmu 기술 문서 전문
(Calif·Equixly·Semgrep·Endor Labs·Upwind·Datadog 등 12개 2차 소스 컴파일), 검출 룰 3종.
결론 먼저 (11/23 갱신): 원인·트리거·패치·완화는 외부와 정합한다. 다만 **마스크 해석(C-1), URL 디코더 제외(C-5),
작은 dst 승격 불가(C-6), "Calif 단독"(C-7)은 우리 쪽이 틀렸거나 과잉 일반화**였다 — `CORRECTION-3.md`.

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
| 근본원리 (bzhi full-mask, 62-63B) | "output_size -= 1 → bzhi low byte 0xFF → all 64 lanes" | 원인 위치(L_finalBit 언더플로)는 동일. 마스크 해석은 우리 설명(mod 64)이 틀렸고 외부가 옳음 | ⚠️ 부분 일치 — 우리 측 정정 (CORRECTION-3 C-1·C-4) |
| JDK 17 트리거 최소 길이 | "17은 ~129자, 21/25/27은 ~65자" — 17은 **~128B 벡터화 임계** | 우리 트리거 `A`×128+`=` (129B) — 동일 | ✅ 일치 (우리가 11/18에 먼저 실측 확정) |
| URL 디코더 영향 | "getUrlDecoder()도 취약 경로" | ~~URL 모드는 `=`를 illegal로 처리 → masked store 미실행~~ (11/23 철회: `fromBase64URL['=']=-2`, 스텁 패딩 제거는 문자 비교). 무패딩 세그먼트는 트리거 조건 없음 | ✅ 외부 문서가 옳음. 제품별 패딩 처리·도달성은 별도 검증 (C-5) |
| MIME 디코더 | "영향 없음" | 미검증 (스킵 경로) | ✅ 동일 |
| 확정 영향 | **"JVM crash → DoS" (독립 재현: Equixly, Upwind, Datadog, VulnCheck)** | **우리가 실앱 2종(Spring/HBase)에서 재현·서명 확정** (앱프레임 SIGSEGV, G1CM SIGSEGV, MAPERR) | ✅ 실앱 크래시 서명 상세를 공개 기록 |
| RCE 주장 | **"claimed but contested"** — Calif 비공개, 독립 재현 없음, "the overwrite is constrained and not attacker-controlled... needs per-target heap grooming" | 우리 150발+포화 실험 결과와 **문장 수준 일치**: 배치 grooming이 관문, 확률적 재시도 캠페인(TRY 18/96) | ✅ 교차점 — 데모의 "TRY 카운터"를 확률 캠페인으로 해석. ⚠ 11/23: "독립 재현 없음"은 갱신 — C-7 표 |
| 패치 커밋 | **5177a70b385c** (upstream, Tobias Hartmann 10/13, 한 달 엠바고) | 우리 기록: 17u backport `8ea73158af` (11/12) | ✅ 상호 보완 (upstream SHA는 신규 정보 — KISA-REPLY 갱신 대상) |
| 패치 형태 | "length<4 guard, 3-4줄" | 8ea73158af 4줄 — 동일 | ✅ |
| Java 8 Performance Pack | 8u511b33-perf 영향, 8u513-perf 수정 | 우리 문서: "8·11 라인은 별도 확인" — **신규 정보: 8도 -perf만 영향** | 🆕 KISA-REPLY 보강 대상 |
| GraalVM | "recent builds 영향 보고, Oracle 미확인" | 미검토 | 🆕 |
| CPU 게이트 | VBMI(+F/BW/BMI2), Ice Lake+/Zen4+, ARM·에뮬·마스킹 불영향 | 우리: Genoa 실측 | ✅ (VBMI가 게이트라는 표현 정확) |
| MIME/2인자 decode | — | 우리: 2인자 decode(src,dst)도 decode0 호출(intrinsic 발동), PoC Stage1은 dst 128B > 쓰기 112B로 OOB 부재 | ✅ 우리 분석 |

## 4. 커뮤니티가 못 하고 우리가 한 것

1. **실앱 크래시 서명 상세** — 앱프레임 SIGSEGV(`lab.AvatarApp.status()`, MAPERR)·
   G1CM SIGSEGV·에러리포터 2차 파손 — 외부 문서는 "JVM crash" 한 줄
2. **TLAB 전방쓰기 소거 가설** — 우리 랩 조건에서 작은 dst 표면 150발 음성의 설명 가설
   (11/23 정정: "구조적 불가 확정"은 실험 범위를 넘는 일반화 — CORRECTION-3 C-6)
3. **데모 TRY 카운터 = 확률적 재시도 캠페인** 판정 + 45 attempts 실측(4회 크래시,
   자동복구 루프) — 데모를 재현 가능한 실험 구조로 번역
4. **표면 스코핑** — 헤더류(작은 dst)=이 랩 조건 음성 / body decode(humongous)=손상 관측
   (11/23: "불가" 표현 철회)

## 5. 신규 채택 정보 (우리 문서 반영 대상)

| 항목 | 내용 | 반영처 |
|---|---|---|
| upstream 커밋 SHA | `5177a70b385c16f26ede191fdac7aaba0bed0f8b` (author Tobias Hartmann) | KISA-REPLY §1 |
| Java 8 -perf | 8u511b33-perf 영향 / 8u513-perf 수정 (일반 8은 무영향) | KISA-REPLY §2·DEFENDER-GUIDE §1 |
| 17 벡터화 임계 | ~128B 미만은 스칼라 경로 → 129자 최소 트리거 | KISA-REPLY §4 |
| 벤더 수정 현황 | Corretto/Zulu released, Temurin/MS/RHEL pending, Debian stable 취약 | KISA-REPLY §5 |
| WAF 룰 3종 | oversized-Basic(128+), repeated-char+padding, padded-URLsafe-JWT — **alert-first 권고** | DEFENDER-GUIDE §3 신설 |
| "no in-the-wild, not in KEV" | 11/19 시점 외부 문서 표기 | 요약 |

## 6. 결론

- ~~커뮤니티 합의: overflow·DoS 확정, RCE는 Calif 주장 단독(비공개, 미독립재현)~~ —
  **11/23 갱신:** Calif 외에도 Hadrian(Jenkins·별도 본문 랩 pre-auth 코드 실행)의 자체 재현 보고와
  VulnCheck의 상용 RCE 제공 공지가 있다. 이 저장소는 공개된 완성 체인이나 원시 증적으로
  이들을 독립 검증하지 못했다 (REPORTED). 출처·날짜·증거 등급: CORRECTION-3 C-7 표
- 우리 기여는 DoS 실측 서명과 확률 캠페인 해석이다 ("유일" 표현은 검증할 수 없어 삭제)
- 패치 SHA·Java 8 -perf·WAF 룰 3종은 외부 문서에서 채택해 우리 문서에 반영 완료

(본 검토는 우리 public 레포와 외부 문서가 상호 인용 가능한 수준까지 정합 — KISA 회신)
