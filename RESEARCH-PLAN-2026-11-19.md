# 연구 계획 — Java4Shell G1 상태 기반 인과·예측 검증 (v1.0, 2026-11-19)

PI 결정: **Issue #1의 PIVOT 권고를 승인**한다. 반복 캠페인의 횟수 확대(무기화 지향)를
연구 성과로 삼지 않고, 이슈가 정의한 검증 계약(실험 A 인과 → 실험 B 예측)을 수행한다.
본 계획은 이슈 #1의 체크리스트·게이트를 그대로 상속하며, 실행 가능한 단계·예산·종료
조건을 추가한다.

---

## 0. 범위 선언

| 한다 | 하지 않는다 |
|---|---|
| G1 관측 상태 → 크래시/생존 결과의 인과·예측 검증 | 원격 정보유출/RCE 성공률 최적화 |
| 취약/패치/완화/부하 대조 실험 (독립 episode 단위) | 새 공격 기법 주장 (MAZE/BAGUA 계열과 차별점은 "설명 모델+반증") |
| 사전등록된 지표(Brier) 기반 baseline 비교 | 사후 지표 선택·세계 최초 주장 |
| 부정 결과(negative result)도 1급 산출로 기록 | Calif 비공개 체인의 독립 검증 시도 (불가능 — Issue #1 §3) |

표적 서비스: 기존 Spring Boot/Tomcat 랩(avatar-svc) 유지 — decode→cache→GET/DELETE
표면이 공격자 조형 프리미티브를 그대로 제공하므로 실험 단위 통제에 적합.
CVE-2026-114938 / Temurin 17.0.8 / EPYC Genoa (AVX-512 VBMI+BW+VL) / G1 / 1.25GB 힙.

## 1. Phase 0 — 계측 교정 (이슈 #1 §2 지적 4건, 선행 조건)

| # | 지적 | 수정 | 검증 |
|---|---|---|---|
| P0-1 | JVM 사망 후 자동 재시작 미보장 (커맨드가 `java …; sleep infinity` — 컨테이너는 안 죽어 JVM이 죽은 채 정지. 오버나이트 캠페인의 "app not ready" 12회가 바로 이것) | app 컨테이너를 **supervisor 루프**로 교체: `until java …; do err=…; sleep 2; done` — JVM 사망 → 컨테이너 내 즉시 재시작(캐시 리셋 = 신규 episode 시작점으로 명시적 기록) | 의도적 크래시 유발 → 2분 내 재기동·READY 확인 |
| P0-2 | 파이프라인 종료코드가 java 종료코드와 불일치 | supervisor가 java 종료코드를 `/share/last_exit` 기록, episode 메타에 첨부 | crash/정상 각각 파일값 대조 |
| P0-3 | emptyDir는 컨테이너 재시작엔 유지, **파드 재생성엔 소실** | (a) episode 종료마다 hs_err·gc.log·state를 attacker 컨테이너로 복제 + (b) 로컬 `kubectl cp` 아카이브. state 파일에 episode_id 기록 | 파드 재생성 후 아카이브 존재 확인 |
| P0-4 | attacker 로그가 오류만 담김(시간축 증거 부재) | attack 요청/응답을 **타임스탬프 JSONL**(attempt_id 포함)로 기록 — hs_err 타임스탬프와 상관 가능 | run ID로 hs_err 시각과 조인 확인 |

**episode 정의 (실험 단위)**: 신규 JVM 프로세스 시작(app 기동) → 웜업 → fill →
drop/trigger 반복(최대 K attempts 또는 JVM 사망) → 증거 아카이브. 같은 힙 상태에서의
연속 attempt는 독립 표본이 아님(이슈 #1 §4).

## 2. Phase 1 — 실험 A: 인과 검증 (최우선)

### 2-1. 4-arm 설계

| Arm | 구성 | 목적 |
|---|---|---|
| A1 취약 | temurin 17.0.8, intrinsic ON, 동일 trigger 시퀀스 | 크래시 재현 (기존 관측) |
| A2 패치 | **자체 빌드 17.0.21.1-ga** (기존 절차 재사용 — 이전 빌드는 파드 소실로 삭제, 재빌드 1회 ~2h 후 이미지 tar 캐시) | 패치가 동일 시퀀스를 무해화하는지 |
| A3 완화 | 17.0.8 + `-XX:-UseBASE64Intrinsics` | 완화 플래그 실효 (HBase/Synthetic에서 이미 관측 — episode 단위로 재확인) |
| A4 대조 | 17.0.8, 동일 부하, **악성 입력 0** (정상 b64만) | "포화+부하 자체"가 크래시를 만드는지 — 인과의 반대축 |

공통: CPU/JVM/이미지/힙/실험 스크립트 동일. 각 arm에서 trigger 시퀀스·타이밍 동일화
(같은 drop 회전, 같은 웜업, 같은 pump).

### 2-2. 프로토콜 (arm당)

- episodes: **N=10** (근거: 크래시가 확률적 — 포화 70%에서 5트리거 내 사망 관측 2회,
  미적중 1회 → episode당 사망 확률 p 추정 ±0.15 수준. N=10이면 95% CI ±0.3,
  arm 간 유의 차이 판별엔 충분. 정밀 CI는 2차 확장)
- episode당: reset(201 junk→clear) → 웜업 20K → fill 100(700MB) →
  attempts K=12 (drop 회전 f71..f82, shape 교대 pad2/pad1, 사이클 폴링) →
  종료 조건: JVM 사망 / K 도달
- 기록 (run.json per attempt): arm, episode_id, attempt_id, drop_id, shape,
  trigger_http_code, iae_count, gc_cycle_before/after, diag 스냅샷(사망 전 마지막),
  alive, crash(0/1), hs_err 경로, 타임스탬프 전체

### 2-3. 판정 (이슈 #1 §4 오라클·무효 기준 그대로)

- **causal supported**: A1에서 크래시 ≥ 다수 episode, A2·A3·A4에서 0또는 무시 수준
  (Fisher exact, arm별 episode 단위)
- **not supported**: A1에서도 재현 안 됨 / A4에서도 동일 빈도 (포화·부하가 원인)
- **INVALID**: 설정 불일치·웜업 누락·로그-실험 연결 실패 episode는 분석에서 제외하되
  **원본 보존**(무효 처리도 기록)
- G1 SIGSEGV 단독으로 인과 주장 금지 — trigger 시퀀스와의 조건부 관계만 주장

## 3. Phase 2 — 실험 B: 홀드아웃 예측력

- **데이터**: Phase 1 전 episode의 attempt별 레코드 (라벨: CRASH/SURVIVED, INVALID 제외)
- **feature (GC 상태, 사전 고정)**: trigger 직전 — concurrent cycle 수, 직전 cycle
  이후 경과 시간, humongous 할당 수(_gc.log_ 파싱), 힙 점유율, drop 후 경과 시간,
  cycle 증가율(직전 60초)
- **baseline (H0)**: 힙 점유율 단일 변수
- **모델 (H1)**: 위 feature의 로지스틱 회귀 (복잡 모델 금지 — 이슈 #1: Markov/HMM을
  처음부터 정답으로 가정 금지)
- **1차 지표**: Brier score (실행 전 고정) — holdout episode에서
- **누수 방지**: **episode 단위 split** (같은 episode의 attempt가 학습/검증에 동시 포함 금지),
  가능하면 arm별 외부 검증
- **결정 기준 (사전등록)**: baseline 대비 Brier 개선 ≥ 0.05이면 H1 채택 근거,
  미만이면 H0/H2 검토, 표본 부족 시 INCONCLUSIVE
- **검정력**: episode 40개(4 arm × 10) 기준 — 사전등록서 "개선 폭 0.05 검출에
  필요 표본" 재계산 후 부족하면 INCONCLUSIVE 명시

## 4. Phase 3 — 산출물

1. 선행연구 비교표 최종본 (SHRIKE/MAZE/BAGUA/GCFuzz/G1-VEE — 이슈 #1 §3 표 확정)
2. episode 데이터 세트 (run.json + gc.log + hs_err + pcap 선택) — public repo
3. 실험 A 보고서 (인과 판정 + 반례 포함)
4. 실험 B 보고서 (Brier 비교 + calibration)
5. 부정 결과 포함 최종 스코핑 갱신 (ESCALATION-STATUS·DEFENDER-GUIDE 연동)

## 5. 게이트 평가 (이슈 #1 §6 매핑)

| 상황 | 조치 |
|---|---|
| Phase 1에서 A1 크래시 재현 실패 | **HOLD** — 계측 재교정 후 1회 재시도, 그래도 실패 시 현재 증거(hs_err 4건)로 스코핑 확정 |
| A 인과 확인 + B 예측 개선 | **CONTINUE** — 상태 모델 논문화 검토 (GCFuzz/MAZE와 차별점 명시) |
| A 인과 확인 + B 개선 없음 | **PIVOT/SCOPE** — 인과 보고 + 확률 캠페인 실측으로 마감 |
| 선행연구와 동일 입증 | **STOP** — 재현 아티팩트로 정리 |

## 6. 일정·예산 (랩 기준)

| 단계 | 예상 | 비고 |
|---|---|---|
| Phase 0 | 0.5일 | supervisor·JSONL·아카이브 |
| A2 재빌드 | 2h 1회 (백그라운드) | 기존 절차 재사용 |
| Phase 1 | 2~3일 | episode ~30-60분 × 40 (A2 재빌드 병렬) |
| Phase 2 | 1일 | 분석·보고서 |
| 총 | **~1주** | 오버나이트 캠페인 자원과 병행 가능 (랩 1개 유지) |

## 7. 리스크

- 크래시 확률이 arm 간 차이를 내기에 낮으면 → episode 수 확장 또는 INCONCLUSIVE
- 자체 빌드 JDK가 vendor 빌드와 미세 차이 → A2 해석 시 빌드 문자열 명시
- 파드 재생성 시 state 소실 → Phase 0-3 아카이브로 방어
- Calif 비공개 체인과의 비교 불가 → 논의는 공개 문장("constrained write",
  "per-target grooming") 수준으로 한정 (EXTERNAL-REVIEW §3과 동일)

## 8. 즉시 착수 항목 (승인 시)

1. Phase 0 supervisor 루프 + JSONL 패치 (spring_lab.sh·campaign.py)
2. A2 자체 빌드 재실행 (백그라운드, ops/build_jdk17u.sh 재사용 — hs_err 수집 경로 보강)
3. run.json 스키마 확정 후 Phase 1 episode 1회 드라이런 → 본 실험 개시
