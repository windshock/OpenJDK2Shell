# HANDOFF — 신규 세션 인계 문서

> **⚠ 2026-11-23 정정 반영** — `CORRECTION-3.md` 참조 (정정 전 문장은 그 문서에 원문 보존).


작성: 2026-11-18 오전 · 갱신: 2026-11-18 저녁 (§6 전 과제 완수 + E2E JVM 크래시(DoS) 재현 + 관제 공유 pcap)

## 0. 현재 상태 (2026-11-23 17:10 KST 갱신 — 이 절이 최신)

- **실험 A·B 완료** → `research/RESULTS-2026-11-23.md`
  - A: **causal supported** — 17.0.21+9 크래시 6/10 vs 패치(17.0.21.1+2)·완화 플래그·정상 입력 각 0/10 (Holm p=0.016)
  - B: **INCONCLUSIVE** — 양성 6 < 8. 탐색적으로는 episode 초반 집중 → episode 수준 배치 가설
  - 크래시 6/6 서명 동일: G1 Conc#0, SEGV_MAPERR, G1CM 마킹 프레임
- 계획 `RESEARCH-PLAN-2026-11-23.md` v2.0 · 사전등록 `research/PREREG-2026-11-23.md` (잠금 5fbe402, D-1 보충 1·2)
- 원자료 `research/data/main-2026-11-23/` (lane별 ep/ + attempts_merged.jsonl), 재분석:
  `python3 research/analysis/analyze.py research/data/main-2026-11-23/attempts_merged.jsonl` · `research/.venv/bin/python research/analysis/crosscheck.py …`
- 클러스터: 워커 dev01~06 (dev03~06은 11/23 16:10 가입, 전부 EPYC-Genoa VBMI). 실험 네임스페이스 `j4s-research*` 전부 삭제됨.
  재실험 시 `research/lab/lab.sh deploy|run|status|pull|stop` (NS·NODE 환경변수) + `research/lab/coordinator.py` (PENDING·LANES_EXTRA)
- **중간 기전 확인 완료** → `research/mechanism/MECH-RESULTS.md`: OOB 64B store 꼬리 48B가 인접 헤더
  (mark+klass+length+body)를 덮음(Method A 실측), GC가 손상 klass 따라가다 치명(Method B fastdebug 어서션).
  유출: fill 문자 축으로는 length 제어 안 됨(vary 실험 기각), 정렬 축은 미시도(승격 범위 밖) → UNESTABLISHED
- **재사용 인덱스:** `research/README.md` — lab/coordinator/analysis/mechanism 재실행 명령 전부
- **남은 결정 (PI):** RESULTS §6 — SCOPE 마감 권고 / 선택지: episode 수준 배치 가설 새 사전등록
- 아래 §1~§9는 11/18 기준 기록 — 바이트 수·Keycloak·TLAB 서술은 CORRECTION-3로 정정됨

## 1. 프로젝트 한 줄 요약

OpenJDK CVE-2026-114938 (Java4Shell — Base64 AVX-512 assembly OOB 쓰기) 대응 프로젝트.
분석 → 실증 → 무기화(역직렬화 체인 — 별개 취약점) → 방어 가이드 → **OOB 직접 관측 → 원격 E2E JVM 크래시(DoS) 5회 재현 →
관제 공유용 pcap → KISA 회신 초안**까지 전부 완료. §6 남은 과제 없음 (§6-2 Keycloak은
플러드 방식이 비현실적으로 느려 중단·부분 로그만 보존 — E2E victim 모델로 대체 실증).

## 2. 저장소 위치·환경

- 로컬: `~/Downloads/OpenJDK2Shell` (구 경로 `~/Downloads/OpenJDK`는 심볼릭 링크)
- GitHub: https://github.com/windshock/OpenJDK2Shell (private, 협업자 HeeRPOU 초대됨)
- jdk17u 클론: `~/Downloads/OpenJDK2Shell/jdk17u` (blobless — **전트리 git grep 금지,
  blob 폭탄 ENOSPC 전례**, 경로 한정 git show만)
- kubeconfig: `kube/dfirtx-dev.conf` (admin, git 제외, 600)
- 클러스터: DFIRtx dev (전 노드 AMD EPYC-Genoa, avx512vbmi/bw/vl — Java4Shell 실증 환경)
- colima: 삭제 완료 (디스크 6G 회수)

## 3. 최종 결론 (2026-11-18 기준)

| 항목 | 결론 |
|---|---|
| **CVE-2026-114938** | **Base64 AVX-512 assembly OOB 쓰기 (Java4Shell)** |
| 트리거 | JDK 17: `A`×128 + `=` (129바이트) — 4바이트 미만 패딩 조각을 assembly가 처리 |
| 패치 | 17.0.21.1 커밋 `8ea73158af` (8393212) — `cmpl(length,4); jcc(L_bruteForce)` 4줄 |
| 취약 버전 | 17.0.6~17.0.21.0.x (intrinsic 도입 = 17.0.6, NCSC 하한과 정합) |
| 완화 | `-XX:-UseBASE64Intrinsics` (product 플래그, §9.1 소스 검증) 또는 17.0.21.1 업그레이드 |
| H2 가설 | **재확정 — 처음부터 옳았음** (트리거 몰라서 231케이스 미발동했을 뿐) |
| 8389989 C2 JIT | **별개 버그** — 계산 정확성 버그(루프 조기 종료), OOB/RCE 아님 (CORRECTION-2.md) |
| TemplatesImpl | 별개 실증 (add-opens 환경 원격 RCE 성공) — JDK 17 모듈 시스템이 기본 설정 차단 |
| LDAP trustSerialData | 별개 — 17.0.13에서 이미 패치 (기본값 true→false) |

## 4. 핵심 문서 지도

| 문서 | 내용 |
|---|---|
| `vuln-analysis-2026-11-17.md` | 전체 분석 (§1~§11) — 사실/전제/가설/실증 기록 |
| `candidate-triage-2026-11-17.md` | 후보 triage (+§7 검증 결과) — JIT 미순위 교훈 포함 |
| `PHASE-B-VERDICT.md` | ⚠ **부분 폐기** — CVE↔8389989 매핑은 오인 (CORRECTION-2 참조) |
| `CORRECTION.md` / `CORRECTION-2.md` | 정오표 2건 — 과장 주장 정정 이력 |
| `DEFENDER-GUIDE.md` | **v4** (Base64 확정·OOB 실측 반영; v3의 C2 중심 서술 폐기) |
| `KISA-REPLY-2026-11-20.md` | **KISA 회신 초안** — 컴포넌트·하한·완화 전부 소스 검증 완료 |
| `OOB-OBSERVATION-2026-11-18.md` | **OOB 직접 관측 보고서** — 메커니즘·레시피·매트릭스·포렌식 |
| `deep-analysis-*.md` (C1~C7, A1~A4) | 후보별 심층 분석 |
| `GOAL-find-and-exploit.md` | 실행 골 (국면 A 완료, B 완료) |
| `exploit/E2E-EXPLOIT-SUITE.md` | 익스플로잇 아키텍처 |

## 5. 익스플로잇 자산

| 파일 | 상태 |
|---|---|
| `exploit/src/Java4Shell*.java` | CVE-2026-114938 트리거 (Java 레벨 차등 — 커럽션 미관측 한계) |
| `exploit/src/OobCanary.java` | **★ OOB 직접 관측 도구** (5리전 갭 그루밍 + 힙 커널리) — `oob_run.sh`로 매트릭스 실행 |
| `exploit/results/oob_*.log` | 관측 매트릭스 로그 (셀 1·2 OOB 관측, 셀 3 완화 CLEAN) |
| `exploit/src/Chain2LdapExploit.java` | TemplatesImpl RCE (완전 실증, add-opens) |
| `exploit/src/WeaponizedExploit.java` | RMI → TemplatesImpl (원격, --add-exports 조건) |
| `exploit/src/C2OobExploit.java` | C2 JIT 계산 버그 (별개 버그, OOB 아님) |
| `exploit/victims/` | DeserVictim·EvilDgcServer·StringDecodeSvc 등 |
| `exploit/results/` | 원격 실증 로그 전부 |

## 6. 남은 과제 (2026-11-18 저녁 기준 — §6 전 과제 완수)

1. ~~OOB 실측 승격~~ — 완료 (`OOB-OBSERVATION-2026-11-18.md`, 인접 헤더 손상 관측; 바이트 수는 CORRECTION-3 C-2)
2. ~~애플리케이션 표적~~ — Keycloak 플러드는 웜 병목으로 중단(부분 로그 보존),
   **E2E victim 모델로 대체 실증 완료** (업로드 디코드 표면)
3. ~~완화 3중 대조~~ — **완결**: 취약 ON=OOB / 완화 OFF=CLEAN /
   **자체빌드 17.0.21.1 ON=CLEAN** (패치 8393212 효과 입증,
   `exploit/results/jdk17u-build-and-canary.log`)
4. ~~DEFENDER-GUIDE v4~~ — 완료
5. ~~KISA 회신 초안~~ — 완료 (`KISA-REPLY-2026-11-20.md`, 11/20 회신 전 검토만 남음)

**후속 후보 (신규 작업)**: JWT 라이브러리별 패딩 처리·디코더 도달성 확인(11/23 정정: base64url도
`=` 패딩을 허용하고 스텁은 URL 모드에서도 같은 store 실행 — CORRECTION-3 C-5, 계획 E-2), 타 라인(8·11·21)
하한 아키폴로지 스폿 체크, hs_err 기반 탐지룰 튜닝.

## 7. 신규 세션 시작 명령

```
~/Downloads/OpenJDK2Shell/HANDOFF.md 를 읽고 이어서 진행하라.
```

한 줄이면 충분 — 이 문서가 자기완결.

## 9. E2E·관제 공유 자산 (11/18 저녁 추가)

| 자산 | 위치 |
|---|---|
| **E2E 체인 3 문서** | `exploit/E2E-EXPLOIT-SUITE.md` (체인 3 절) |
| **★ 체인 4: 실앱 E2E (HBase REST 기본 설치 JVM 크래시·DoS ×2)** | `exploit/E2E-EXPLOIT-SUITE.md` 체인 4 절 — `ops/hbase_e2e_setup.sh`·`ops/hbase_e2e_attack.py`·`exploit/hbase_e2e.sh` |
| **관제 공유 문서** | `OPS-SHARING-2026-11-18.md` — 와이어 시그니처·탐지룰·pcap 목차 |
| **WAS 로그·크래시 덤프 패턴** | `WAS-LOG-CRASH-ANALYSIS-2026-11-18.md` — 앱로그 A1~A4 룰, hs_err 서명, GC 로그 룰 |
| **pcap (공유용)** | `exploit/results/pcap/j4s-e2e-vuln-attacker-full.pcap.gz` (13초 전체, 트리거+사망 RST), `victim-flood.pcap.gz`, `soc-r1.pcap` |
| E2E 코드 | `exploit/src/Java4ShellE2EVictim.java` + `ops/e2e_java4shell_attacker.sh` + `exploit/e2e_java4shell.sh` |
| E2E 결과 | `exploit/results/e2e_j4s_{attacker,victim}_{vuln,mitig}.log` (7회, JVM 크래시(DoS) 5회) / `results/hbase_*_vuln.log` (실앱 JVM 크래시 2회) |
| 빌드 대조 로그 | `exploit/results/jdk17u-build-and-canary.log` (셀 5·6) |

**레포 상태: PUBLIC** (11/18 전환 — `kerberosjoo27@gmail.com`만 마스킹 후 공개).
~~Keycloak은 본 CVE 표적 부적합 판정~~ (11/23 철회 — CORRECTION-3 C-5·C-6). 실앱 표적 = **HBase REST (ScannerModel JDK Base64)**.

## 8. 운영 메모

- 감시 cron: 임무 완수 (jdk-17.0.21.1-ga 관측) — 남아 있으면 삭제 가능
  (`CronList`에서 `OpenJDK 17.0.21.1 패치 감시` 확인)
- 클러스터: 항상 ns 생성→테스트→`kubectl delete ns` 원상복구 사이클
- blobless clone 규율: `git grep` 전트리 금지 / auto-gc 비활성 (`gc.auto 0` 설정됨)
- 협업자 초대: HeeRPOU 완료, 별도 후보 1명은 GitHub 사용자명 미확인 (보류)
