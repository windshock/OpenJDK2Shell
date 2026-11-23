# 통합 연구 계획 v2.0 — Java4Shell 정정·계측·인과·예측 (2026-11-23)

> **상태 (11/23 17:10):** 트랙 C·D, Phase 0, 실험 A·B 완료 → `research/RESULTS-2026-11-23.md` (A causal supported / B INCONCLUSIVE). Phase 3 미착수 (PI 결정)

v1.0(`RESEARCH-PLAN-2026-11-19.md`)을 **대체하지 않고 확장**한다. v1.0의 범위 선언·사전등록 지표(Brier)·
episode 단위 분할·게이트는 그대로 상속한다. v1.0 파일은 이력으로 보존한다.

## 0. 통합 입력

| # | 입력 | 날짜 | 이 계획에 반영한 것 |
|---|---|---|---|
| I1 | `RESEARCH-PLAN-2026-11-19.md` v1.0 | 11/19 | Phase 0(P0-1~4), 실험 A 4-arm, 실험 B, 게이트 — 골격 |
| I2 | Issue #1 본문 (H0/H1/H2, 실험 계약, §5 체크리스트) | 11/18 | 체크리스트 전 항목 → §9 매핑 |
| I3 | Issue #1 댓글 2 "공개자료 재검토 — 원인 설명 정정·증거 상태 갱신·Phase 0 관측 보강" | 11/22 | **트랙 C(정정)** 신설, `memory_corruption_state` 축, Temurin 빌드, 진행 순서 "정정 → 관측 기준 → A/B" |
| I4 | Issue #1 댓글 3 "RCE Chain 가능성 심층 분석" | 11/22 | 결과 6축 분리, JIT/intrinsic 도달 관측, JFR TLAB 이벤트, GC 축(확장), `-XX:UseAVX=2` 완화, 방어 체크리스트 |
| I5 | 11/23 클러스터 재실행 (HTTP/1.1 강제, 본 세션) | 11/23 | P0-3 필요성 재확인(아래), 방어 문서 "HTTP/2 비필수" 근거 |
| I6 | Docker Hub `eclipse-temurin:17.0.21.1_2-jdk-jammy`, `17.0.21_9-jdk-jammy` (11/20 게시) | 11/23 확인 | A2를 **공식 벤더 빌드**로 교체, A1 최근접 대조 후보 |

**I5 요약 (pre-Phase-0, 실험 A 표본에 산입하지 않음):** DFIRtx `dfirtx-worker-dev02` (AMD EPYC-Genoa,
avx512f/bw/vl/vbmi), Temurin 17.0.8, `UseBASE64Intrinsics=true {default}`. victim은 JDK 내장
`com.sun.net.httpserver`(HTTP/2 미지원: h2c prior-knowledge 거부, Upgrade 무시). 공격 요청 전량
`--http1.1`, attacker pcap에 HTTP/2 프레임 없음(프로브 1건 제외). trigger 1회 후 JVM 사망 —
`SIGSEGV SEGV_ACCERR`, `G1CMTask` 프레임, exit 134. 단일 episode·REPORTED 등급.
**계측 결함 재현:** victim 컨테이너가 crash 후 `Failed`로 종료 → hs_err·gc.log·victim pcap 회수 실패
(로그 head만 확보). P0-1/P0-3 미해결 상태로는 증거가 소실됨을 재확인.

## 1. 범위 선언 (v1.0 + 추가)

| 한다 | 하지 않는다 |
|---|---|
| v1.0 전체 | v1.0 전체 |
| 확정된 설명 오류 정정과 정정 이력 보존 (트랙 C) | 원본 로그·기존 판정의 소급 덮어쓰기 |
| 프로세스 상태와 메모리 손상 관측 상태의 **분리 기록** | 생존(SURVIVED)을 무결성·비취약의 근거로 사용 |
| 외부 보고(Calif·Hadrian·VulnCheck 등)를 출처·날짜·증거 등급과 함께 인용 | 외부 재현 보고로 이 저장소의 미입증 성과를 "완료"로 변경 |
| 제품 경로의 **디코더 도달성**(입력이 패딩 tail 형태로 `Base64.Decoder`에 닿는가) 확인 | 힙 배치법·인접성 조작·disclosure/RCE 절차 개발 (댓글 3 §재현 실패 요인 경계 준수) |

증거 등급 표기는 Issue #1 체계를 따른다: `SOURCE_VERIFIED` / `MEASURED`(우리 실측) / `REPORTED`(외부·단일 관측) / `UNESTABLISHED`.

## 2. 트랙 C — 정정 (최우선, 0.5일)

원칙: 원문은 수정하되 **정정 전 문장은 `CORRECTION-3.md`에 원문·근거·변경 이유와 함께 보존**. 원시 로그(`exploit/results/`)는 일절 수정하지 않는다.

| ID | 대상 (현 위치) | 현재 서술 | 정정 방향 | 근거 |
|---|---|---|---|---|
| C-1 | `OOB-OBSERVATION-2026-11-18.md:21-22`, `KISA-REPLY-2026-11-20.md:54-55`, `exploit/src/OobCanary.java:14,100-101` | `bzhiq`가 index를 mod 64로 해석 → 마스크 64-p비트 → p=1:63B, p=2:62B | BZHI는 index의 하위 8비트 사용, ≥64면 원본 보존 → **all-ones 마스크, 64바이트 store**. 기록을 4항목으로 분리: ① 명령어 저장 폭(64B) ② 계산된 목적지 크기 ③ 경계 초과량(시작 offset+64−dst 크기) ④ 실제 관측 변경 범위 | Intel SDM rev.093 BZHI, Deep Kondah 11/22, JFrog |
| C-2 | `OobCanary.java:222`, `OOB-OBSERVATION:66-70,84`, `WAS-LOG-CRASH-ANALYSIS:166`, `E2E-EXPLOIT-SUITE.md:65,73,129`, `ESCALATION-STATUS:148`, `DEFENDER-GUIDE.md:257`, `HANDOFF.md:66` | pad1=63B / pad2=62B 라벨, 판정 문자열 `OOB-OBSERVED (62B write)` | 라벨을 C-1 모델로 재계산. 판정 문자열은 `OOB-OBSERVED (header corrupted)`로 변경하고 바이트 수는 별도 필드. **이미 기록된 로그의 문자열은 그대로 두고** 해석 주석만 추가 | C-1 |
| C-3 | `OOB-OBSERVATION:89`, `WAS-LOG-CRASH-ANALYSIS:172` | 1MiB/2MiB 오프셋 온전 → "쓰기 범위 정확히 ≤62B" | "헤더 손상 관측"과 "쓰기 폭 정밀 측정"을 분리. 원거리 2점 온전은 폭의 상한을 확정하지 않음 → `UNESTABLISHED` | 댓글 2 §1 |
| C-4 | `EXTERNAL-REVIEW-2026-11-19.md:36` | 근본원리 "✅ 완전 일치" | "원인 위치 일치, 마스크 해석은 우리 설명이 틀렸음(C-1)" | 댓글 2 §1 |
| C-5 | `EXTERNAL-REVIEW:38`, `E2E-EXPLOIT-SUITE.md:155`, `HANDOFF.md:75-76,101` | URL 디코더는 `=`를 illegal 처리 → masked store 미실행 → JWT 트리거 불가 | `fromBase64URL['='] = -2` (패치 직전 Base64.java @529f066), API는 올바른 개수의 패딩 허용 → **API 수준 제외 근거 철회**. 제품별 형식 검사·패딩 정규화·도달성은 별도 검증 항목(§6 E-2)으로 이관. "모든 JWT 경로 취약"도 주장하지 않음 | 댓글 2 §4-1 |
| C-6 | `ESCALATION-STATUS:107,111` + §8 표 | 작은 dst 표면 승격 "구조적 불가", humongous가 "유일 경로" | "우리 랩 조건(Spring/Tomcat, G1, 1.25GB, 해당 할당 패턴)에서 150발 음성" 으로 **조건 한정**. 일반 불가능성 주장 철회 | 댓글 2 §4-2, 댓글 3 |
| C-7 | `EXTERNAL-REVIEW:40,70,75-77`, §6 결론 | "RCE는 Calif 단독 주장", "우리가 유일한 공개 문서" | Hadrian(11/17, 갱신 11/19: Basic 경로 크래시 + 별도 본문 디코딩 랩 코드 실행)·VulnCheck(상용 RCE 제공 공지) 추가. 각 항목 게시일/갱신일/확인일·환경·보고 성과·공개 증거·우리 독립 검증 여부 열 추가. "유일" 표현 삭제 | 댓글 2 §3 |
| C-8 | `KISA-REPLY:37`, `DEFENDER-GUIDE` | "Temurin pending" | Temurin 17.0.21.1+2 / 21.0.13.1+2 / 25.0.5.1+2 / 27.0.1.1+4 (Adoptium 11/18). 플랫폼·채널별 상태는 adoptium/temurin#326 기준으로 날짜와 함께 기재. Docker Hub `17.0.21.1_2-jdk*` 11/20 게시 확인 | 댓글 2 §6, I6 |
| C-9 | `PHASE-B-VERDICT`·`DEFENDER-GUIDE` 등 크래시 프레임 서술 | (점검) | GC 프레임 크래시 위치만으로 원인 컴포넌트 확정 금지 원칙 재확인. Adoptium support#1480(운영 Parallel GC 크래시, 6월)은 "운영 결함 선행 기록"으로만 인용 | 댓글 2 §7 |

완료 조건: 위 9건 반영 + `CORRECTION-3.md` 작성 + `grep -n "mod 64\|62/63\|구조적으로 불가\|완전 일치\|유일"` 재점검.

## 3. 트랙 D — 방어 문서 (트랙 C와 병행, 0.5일)

`DEFENDER-GUIDE`·`KISA-REPLY`에 반영:

1. 수정 빌드 표(C-8) + 벤더별 확인일
2. 완화 2단: `-XX:-UseBASE64Intrinsics`(국소) / `-XX:UseAVX=2`(광역, AVX-512 전체 포기) — 적용 후 **재기동 + `jcmd <pid> VM.flags -all`로 실제 프로세스 확인**
3. 영향 판정 조건표: x86-64 + AVX-512 VBMI/BW(+BMI2) + 영향 버전 + intrinsic 활성 + 공격자 입력이 `Base64.Decoder`에 도달. **HTTP 버전·HTTP/2 설정은 조건 아님** (I5 실측: HTTP/1.1 전용 서버 2종에서 트리거·크래시)
4. 임베디드 JDK(앱 번들·컨테이너 이미지) 확인 — OS `java`만 보면 누락
5. pre-auth Base64 sink 인벤토리(Basic/JWT/SAML/업로드/메시지) — JWT는 "제품별 확인 필요"(C-5)
6. 탐지 서술: "크래시 부재 ≠ 안전", "생존 ≠ 무손상"(Hadrian 보고: 코드 실행 후 정상 서비스 지속 — REPORTED). WAF는 보조

## 4. Phase 0 — 계측 교정 + 관측 축 확장 (0.5~1일)

### 4-1. v1.0 P0-1~4 (그대로, I5로 긴급도 상승)
supervisor 재시작 루프 / java 종료코드 기록 / episode 종료마다 증거 복제(파드 재생성 대비) / attempt 단위 타임스탬프 JSONL.

### 4-2. 신규

| # | 항목 | 내용 | 출처 |
|---|---|---|---|
| P0-5 | **결과 6축 분리** | attempt 레코드에 독립 필드: `intrinsic_reached`, `exception_thrown`, `logical_oob_observed`, `live_object_corruption`, `process_crash`, `disclosure_observed`. 서로를 대리 신호로 쓰지 않음 | 댓글 3 §재현 실패 요인 |
| P0-6 | **`memory_corruption_state`** | `OBSERVED / NOT_OBSERVED / UNKNOWN` + `observation_method` + `observation_scope`(어느 객체·몇 바이트를 봤는가). 관측 수단 부재·증거 누락 = `UNKNOWN`. `NOT_OBSERVED`는 "확인 범위 내 미발견"으로만 해석 | 댓글 2 §5 |
| P0-7 | **관측 행위 교란 통제** | 11/18 선례: `status()`의 캐시 순회가 파손 헤더를 읽어 SIGSEGV 유발 → 관측이 결과를 만듦. 손상 스캔 절차를 **전 arm 동일**하게 적용하고 `crash_during_observation` 플래그 기록 | ESCALATION-STATUS §9 |
| P0-8 | **intrinsic 도달 근거** | `-XX:+PrintCompilation`에서 `Base64$Decoder::decode0` C2(tier 4) 컴파일 시각 기록 → `intrinsic_reached`는 "컴파일 확인 + trigger가 그 이후"로 정의 (직접 관측 아님을 명시) | 댓글 3 JIT 상태 |
| P0-9 | **할당 경로 관측 (선택)** | JFR `jdk.ObjectAllocationInNewTLAB` / `jdk.ObjectAllocationOutsideTLAB` — 비침습 확인되면 실험 B feature 후보로 **사전등록 시점에만** 추가 | 댓글 3 |
| P0-10 | **이미지 고정** | 모든 arm 이미지를 tag 아닌 **digest**로 고정, run.json에 기록 | v1.0 §7 리스크 |
| P0-11 | **스키마 버전** | `run.json`에 `schema_version`. 관측 항목 추가 시 버전 증가, 과거 레코드 소급 변경 금지 | 댓글 2 §5 |

### 4-3. 파일럿 (Phase 0 종료 조건)
- 의도적 crash → 2분 내 재기동·READY, hs_err/gc.log/pcap 회수 성공 (I5 실패 지점 재검증)
- **A1 JDK 선택 파일럿:** `17.0.21_9`(패치 직전 최근접 빌드)로 2 episode. 크래시 재현되면 A1 = 17.0.21_9 (A2와 **패치 커밋 1개 차이**가 되어 인과 대비가 가장 깨끗함), 재현 안 되면 A1 = 17.0.8 유지하고 A1–A2 차이를 리스크로 명시
- 파일럿 데이터는 실험 A/B에 산입하지 않음 (`episode_class=pilot`)

### 4-4. 사전등록 고정 (Phase 1 착수 전 커밋)
`PREREG-2026-11-XX.md`: arm 정의·이미지 digest·episode 수·K·1차 지표(Brier, CRASH 라벨)·feature 목록·split 규칙·개선 임계 0.05·검정력 재계산·INVALID 기준·중단 규칙. **커밋 해시 이후 변경은 deviation 로그로만.**

## 5. Phase 1 — 실험 A: 인과 (2~3일)

| Arm | 구성 (v1.0 → v2.0 변경) |
|---|---|
| A1 취약 | Temurin 17.0.21_9 **또는** 17.0.8 (4-3 파일럿 결과), intrinsic ON |
| A2 패치 | ~~자체 빌드 17.0.21.1~~ → **공식 `eclipse-temurin:17.0.21.1_2-jdk-jammy`** (재빌드 2h 제거, "자체 빌드 ≠ 벤더 빌드" 리스크 해소). 자체 빌드 셀 5·6 결과는 보조 증거로 유지 |
| A3 완화 | A1과 동일 JDK + `-XX:-UseBASE64Intrinsics` |
| A4 대조 | A1과 동일 JDK, 동일 부하, 악성 입력 0 |
| (A5 선택) | A1 + `-XX:UseAVX=2` — 트랙 D의 광역 완화 실효 확인용. 예산 여유 시만 |

프로토콜·N=10·K=12·판정(Fisher exact, episode 단위)·INVALID 처리: v1.0 §2 그대로.

**판정 분리 (v2.0):**
- **1차(사전등록, 불변):** `process_crash` 기준 causal supported / not supported / inconclusive
- **2차(보고용):** `live_object_corruption = OBSERVED` 비율 arm 비교 — A1 SURVIVED 중 OBSERVED 건수를 별도 표로. "생존 = 무손상" 해석 차단

## 6. Phase 2 — 실험 B: 예측 (1일)

v1.0 §3 그대로 (1차: CRASH 라벨 Brier, baseline=힙 점유율, 로지스틱, episode 단위 split, 개선 ≥0.05).

- **추가(탐색적, 사전등록서에 탐색적으로 명시):** 라벨을 `live_object_corruption=OBSERVED`로 바꾼 동일 분석. `UNKNOWN`은 제외하고 제외율 보고. 1차 결론에 영향 주지 않음.

## 7. Phase 3 — 확장 (별도 PI 결정 필요, 기본 OFF)

| ID | 내용 | 경계 |
|---|---|---|
| E-1 | **GC 축**: Serial / Parallel / ZGC에서 A1 vs A3 대조, crash율·TLAB 이벤트만 관측 | 관측 연구. "타 GC 안전/불가" 결론은 증거 범위로 한정 (댓글 3 GC 표: 현재 "미지") |
| E-2 | **디코더 도달성 매트릭스**: 제품·라이브러리별(예: Basic 파서, JWT 라이브러리, SAML) — 패딩 tail 입력이 `Base64.Decoder.decode*`에 그대로 닿는지 **로컬 단위 시험**(디코더 호출 인자 기록) | C-5 후속. 도달 여부만 판정, 손상/승격 시도 없음 |
| E-3 | 선행연구 비교표 최종본 (SHRIKE/MAZE/BAGUA/G1-VEE/GCFuzz + Hadrian/Calif/VulnCheck 공개 범위) | 외부 성과는 REPORTED로 표기 |

## 8. 게이트 (v1.0 §5 상속 + 보강)

| 상황 | 조치 |
|---|---|
| 트랙 C 미완료 | **Phase 1 착수 금지** (댓글 2 진행 순서) |
| Phase 0 파일럿에서 증거 회수 실패 | HOLD — 계측 재교정 |
| A1 크래시 재현 실패 | HOLD → 1회 재시도 → 실패 시 기존 증거로 스코핑 확정 |
| A 인과 확인 + B 개선 | CONTINUE (상태 모델 정리) |
| A 인과 확인 + B 개선 없음 | PIVOT/SCOPE |
| 선행연구가 **G1 상태 → 결과 예측**을 이미 입증 | STOP. 참고: Hadrian/VulnCheck/Calif 보고는 **익스플로잇 성공** 보고이므로 이 게이트를 직접 트리거하지 않음 — 단 Phase 2 착수 전 재검색 |

## 9. 체크리스트 매핑

| 출처 항목 | 반영 위치 |
|---|---|
| 본문 §5 선행연구 비교표 | §7 E-3 |
| 본문 §5 생명주기·증적 보존 검증 | §4-1, §4-3 |
| 본문 §5 시험 단위·라벨·타임라인 사전등록 | §4-4 |
| 본문 §5 실험 A 대조·원시 결과 연결 | §5 |
| 본문 §5 실험 B 사전 고정 | §4-4, §6 |
| 본문 §5 negative result 기록 | §8, 산출물 |
| 본문 §5 DoS / J4S 유출 / J4S RCE / 역직렬화 RCE 구별 | 트랙 C 전 문서 점검 시 병행 (C-7과 함께) |
| 본문 §5 six-lens 독립 감사 | Phase 1 종료 후, 결과 공개 전 1회 |
| 댓글 2 §7 BZHI·바이트 수 정정 | C-1~C-3 |
| 댓글 2 §7 EXTERNAL-REVIEW 갱신 | C-4, C-5, C-7 |
| 댓글 2 §7 외부 자료 메타데이터 | C-7 |
| 댓글 2 §7 TLAB·humongous 한정 | C-6 |
| 댓글 2 §7 프로세스/손상 상태 분리 | P0-5, P0-6 |
| 댓글 2 §7 DEFENDER/KISA 점검 | C-8, 트랙 D |
| 댓글 2 §7 원본 보존·정정 기록 | `CORRECTION-3.md` |
| 댓글 3 결과 6축·JIT·JFR·GC 변수 | P0-5, P0-8, P0-9, E-1 |
| 댓글 3 방어 체크리스트 | 트랙 D |

## 10. 일정

| 단계 | 기간 | 의존 |
|---|---|---|
| 트랙 C + 트랙 D | 0.5~1일 (병행) | 없음 |
| Phase 0 (P0-1~11 + 파일럿) | 0.5~1일 | 트랙 C 완료 전 착수 가능, **Phase 1은 C 완료 후** |
| 사전등록 커밋 | 0.5일 | 파일럿 |
| Phase 1 (40~50 episode) | 2~3일 | A2 재빌드 제거로 v1.0 대비 단축 |
| Phase 2 | 1일 | |
| **합계** | **~1주** | Phase 3는 별도 결정 |

## 11. 즉시 착수 순서

1. `CORRECTION-3.md` + C-1~C-9 문서 반영 (원시 로그 무수정)
2. DEFENDER-GUIDE / KISA-REPLY 트랙 D 반영
3. `spring_lab.sh` supervisor 루프·종료코드·증거 복제 + `spring_lab_campaign.py` JSONL·6축·`memory_corruption_state` 스키마 v2
4. 파일럿: 의도적 crash 회수 테스트 → 17.0.21_9 2 episode
5. 사전등록 커밋 → Phase 1 개시
