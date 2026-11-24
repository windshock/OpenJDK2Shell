# HANDOFF — 신규 세션 인계 문서

> **⚠ 2026-11-23 정정 반영** — `CORRECTION-3.md` 참조 (정정 전 문장은 그 문서에 원문 보존).


작성: 2026-11-18 오전 · 갱신: 2026-11-18 저녁 (§6 전 과제 완수 + E2E JVM 크래시(DoS) 재현 + 관제 공유 pcap)

## 0. 현재 상태 (2026-11-25 갱신 — 이 절이 최신)

### 11/25 — 체인 6 후속: `Runtime` 미러를 빌드 상수 없이 찾기, 랩 모델

- **결론:** `exploit/E2E-EXPLOIT-SUITE.md` 체인 6 후속. `--runtime-pick oracle`은 미러 상수(미러 거리·klass) 대신 victim에게 묻는다 — 후보 미러를 수신자로
  `Class.getDeclaredField("currentRuntime")`를 호출하고 응답의 `Field` 문자열로 선언 클래스를 확인한다. **JDK 17 라인 + CDS 기본 아카이브에서 11/11**,
  이중 한 번도 재지 않은 빌드(17.0.19+10 3회, 17.0.18+8 1회)는 무보정. 후보 9~11번째에서 찾고 체인 5·객체 간 쓰기도 같이 성공.
- 그 미측정 빌드는 기존 상수와 우연히 같아서 기존 방식도 됐다. 두 방식의 차이는 CDS를 끄거나(새 방식 최종 코드 0/3, 기존 0/1) JDK 21에서 나타난다.
- **남은 빌드 의존 — 슬롯 두 개:** `exec(String)`=16, `Class.getDeclaredField(String)`=139. CDS 아카이브가 고정하는 값이라 CDS를 끄면 실행 설정마다
  바뀐다(프로덕션 플래그 JVM에서 16은 `freeMemory()`). JDK 18 이상은 기본 리플렉션이 메서드 핸들 기반(JEP 416)이라 호출 시점에 슬롯을 읽지 않는다.
  JDK 21.0.13+9는 취약점은 그대로 있고(`f071` length 손상), 레거시 접근자 플래그 + 슬롯 147이면 1/1(dev 랩).
- CDS를 끈 실행에서도 체인 5(토큰 → `/ops/exec`)와 객체 간 쓰기는 정상.
- 같은 작업에서 확정한 것: 접근자는 `root`에 공유돼 15번 넘으면 이름 기준 생성 접근자로 바뀐다(둘 다 되돌린다) · 인자 0개 메서드는 수신자에 인자가
  들어간다(`reflection.cpp`) · 손상 뒤 한참 지나거나 큰 반사 작업 뒤의 첫 PATCH는 해석 실행으로 죽는다 · 엉터리 슬롯 호출 한 번에 victim이 죽는다.
- 변경: `exploit/j4s_rce.py`(`--runtime-pick oracle`·`--exec-slot`·`--gdf-slot`), `j4s_rce.sh`(`img` 모드, `ATK_ARGS`, `EXTRA_JVM`, 크래시 요약 저장),
  `lab_rce.sh`(start가 `DEVFLAGS`를 넘김 — 전에는 정의만 되고 안 쓰였다), `src/J4sRceVictim.java`(dev `/dev/label`, 핸들러가 던진 예외의 원인 로그),
  신규 `runtime_study.sh`. 산출물: `results/rce-*-20261125-*`, `results/runtime-struct/`(17.0.21+9·17.0.8+7·CDS 끔 라벨 대조 데이터).
- **대응 자료 갱신 (11/25):** `DEFENDER-GUIDE.md` v6 — §3-F 코드 실행 단계 지표(응답 본문 `Process[pid=`, 실패한 호출의 예외, 캡처 한계),
  §3-A 자식 프로세스(셸 없는 직접 실행), §4-E3 완화가 아닌 것(`-Xshare:off`·JDK 18 이상 리플렉션 설정), 버전·날짜 표기.
  `MONITORING-CHECKLIST-2026-11-25.md` 신설(인프라·관제용). 같은 날 main을 `rce-chain5-6`까지 fast-forward.

### 11/24 — 체인 6: Java4Shell → 메모리 손상만으로 JVM 코드 실행, 랩 모델

- **결론:** `exploit/E2E-EXPLOIT-SUITE.md` 체인 6. 토큰도 권한 인터페이스도 없이, OOB 읽기로 힙의 `Method`·`Runtime.class` 미러·`Runtime` 인스턴스를
  찾은 뒤 OOB 쓰기 3건(각 4바이트)으로 그 `Method`를 `Runtime.exec(String)`으로 바꾸고 무해한 핸들러(`/actions/upper`)을 호출 → JVM이 명령 실행.
  취약 JDK **8/8**(17.0.21+9 6/6 — 원격 1회 포함, 17.0.8+7 2/2), 완화·패치는 트리거 3발씩 손상 0. victim 생존 8/8.
  **피해자는 랩 모델이며 실앱 대상이 아니다. 빌드별 측정 상수(미러 거리·klass·`exec` idnum)가 필요하다.** (11/25: 미러 상수는 `--runtime-pick oracle`로 뺐고, 슬롯은 남는다.)
- 같은 8회에서 체인 5(토큰 회수 → `/ops/exec`)도 8/8 다시 확인. 누적으로 체인 5는 17/17.
- 핵심: ① 호출이 읽는 것은 앱이 가진 `Method` 사본이 아니라 그 `root`(`ReflectionFactory.newMethodAccessor`) ② 네이티브 호출 경로 검사는
  수신자·인자 수·인자 타입 셋 — `(String)` 시그니처라 통과 ③ `Runtime` 미러는 이름이 아니라 **빌드 상수**로 찾는다(`Class.name`은 지연 초기화).
- **관측 효과 교훈:** dev 열람(`-Dj4s.dev.layout`)이 `getName()`을 불러 `Runtime` 미러 이름을 풀어줬다 → dev에서만 되고 프로덕션 첫 배치는 5/5 실패.
  관측 도구가 대상 상태를 바꿀 수 있으니 dev 결과는 반드시 프로덕션 플래그로 재확인할 것.
- 원격 실행(이 PC → NodePort 31883): 2026-11-24 21:55:01.844~21:56:01.673 KST, TCP 세션 2개(업로드 958·1,327 MiB, 다운로드 628 MiB).
  트리거(21:55:40.9) 약 8초 뒤 `GET /actions/upper?arg=touch…` 1건으로 실행. 공유 묶음 `exploit/results/pcap/j4s-chain6-remote-share.tar.gz`.

### 11/24 — 체인 5: Java4Shell → OOB 읽기·쓰기 → 코드 실행(캐나리), 랩 모델

- **결론:** `exploit/E2E-EXPLOIT-SUITE.md` 체인 5. 취약 JDK(17.0.21+9 **7/7**, 17.0.8+7 **2/2** — 체인 6 배치에서 추가로 8/8)에서 무인증 공격자가
  OOB 읽기로 ops 세션 토큰을 회수해 `/ops/exec`를 호출(캐나리 파일, uid 0). 완화·패치는 트리거 3발씩 손상 0.
  **앱 로직 승격이다. 피해자는 랩 모델(`J4sRceVictim`)이며 실앱 대상이 아니다.** (JVM 내부 직접 실행은 같은 날 체인 6으로 입증.)
- 11/23의 "유출 UNESTABLISHED"가 바뀐 이유: 음수 length(`0xa6699aa6`)도 부호 없는 경계 검사를 통과해 **인덱스 단위** OOB 읽기·쓰기가 된다.
  양수 length가 필요한 것은 배열을 통째로 반환하는 경로뿐이다.
- 트리거 배치는 힙 상태가 정한다: IHOP 위(기존 1 GB 70% 채움)에서는 humongous 할당이 할당 전에 동시 마킹을 깨워 DoS.
  IHOP 아래(2 GB에 700 MiB)에서는 young GC의 eager reclaim 뒤 구멍이 가장 낮은 5-리전이 되어 1발째에 결정적으로 놓인다(17/17).
- 트래픽(1회 실측): keep-alive 연결 **1개**에 요청 31,597건·송신 3,277 MiB·수신 449 MiB·약 26초. "세션당 100 MB 업로드" 류의 볼륨 룰에 걸리지만(32배)
  그건 연결을 하나만 쓴 구현 선택이라 — 단일 최대 요청은 6.67 MiB. 더 특이적인 신호는 체인 5 §트래픽 프로파일에 정리.
- **원격 실행(이 PC → 클러스터)**: `REMOTE=1 ./j4s_rce.sh vuln 1` — 공격자를 작업 PC(`10.202.211.14`)에서 NodePort 31883으로. 체인 성공 1/1.
  와이어(victim eth0 pcap): TCP 세션 2개(963 MiB·2,337 MiB 업로드), 다운로드 495 MiB, 67초, 2026-11-24 19:35:33~19:36:40 KST.
  파드 캡처에는 소스가 노드 SNAT 주소(`10.233.68.1`)로 보임 — 관제 대조는 노드 외부 인터페이스 기준.
- 손상 뒤 GC — **생존은 보장되지 않는다(정정).** 처음엔 "young GC 5회 통과"라고 적었으나 그건 배치가 운 좋았던 run이었다. young GC 준비 단계가 모든 humongous 객체의 klass를
  읽으므로(`humongous_region_is_candidate` → `is_typeArray`), 깨진 klass가 읽기 가능한 주소에 놓이면 통과하고 아니면 첫 GC의 `G1PrepareRegionsClosure::do_heap_region`에서 SIGSEGV.
  → pump는 GC 직후에 멈추고(`/health` heapUsed 하락으로 감지), 손상 뒤 요청은 수백 건 이내. 동시 마킹이 시작되면 `G1 Conc#0` SIGSEGV.
  깨진 배열 참조는 `checkcast`·`aastore`·인터프리터 `bastore`에 닿으면 앱 프레임에서 SIGSEGV.
- 자산: `exploit/src/J4sRceVictim.java` · `exploit/j4s_rce.py`(공격자) · `exploit/ops_client.py`(정상 ops persona) ·
  `exploit/j4s_rce.sh`(증거 러너) · `exploit/lab_rce.sh`(dev 랩) · `exploit/results/rce-{vuln,1708,mitig,patched}-2026-11-24-*/`
- 환경: 로컬 Mac에는 Java 런타임이 없다 — 컴파일·실행은 전부 클러스터 파드에서(`lab_rce.sh start|atk`). JDK HTTP 서버는 헤더·본문을 따로 보내
  Nagle 지연(40ms/요청)이 있으니 공격자 클라이언트는 `TCP_QUICKACK`를 켠다(`j4s_rce.py` `V.req`).
- 클러스터: `j4s-rce-dev`·`j4s-rce-e2e` 삭제 확인. ns는 삭제 완료까지 기다린 뒤 재생성할 것(Terminating 경합으로 pod 생성 실패 전례).
- 위치: 연구 계획 v2.0 §1의 "하지 않는다"(힙 배치·승격 절차 개발)는 그 관측 연구의 범위 선언이다. 체인 5는 그 밖의 별도 작업이며 사전등록 데이터와 무관하다.
- **커밋:** 체인 5·6 코드·결과물·문서 변경은 2026-11-24에 커밋했다(종전 "미커밋 — PI 검토 후 커밋" 항목 갱신).
- 남은 선택지 (PI): 공개 범위 결정(랩 모델 결과를 어디까지 리포에 올릴지) · 실앱 표적 재평가(범위 읽기·부분 수정·리플렉션 호출 지점이 있는 서비스) · 다른 JDK 빌드 측정

### 11/23 — 실험 A·B·기전 (종전 기록)

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
- GitHub: https://github.com/windshock/OpenJDK2Shell (**PUBLIC** — 11/18 전환, §9. 전에는 private·협업자 HeeRPOU 초대)
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
| `DEFENDER-GUIDE.md` | **v6** (11/25 — 코드 실행 단계 지표 §3-F·적용 범위 §4-E3. v4 11/18 Base64 확정·OOB 실측, v3의 C2 중심 서술 폐기) |
| `MONITORING-CHECKLIST-2026-11-25.md` | 인프라·관제용 체크리스트 — 우선순위·한 실행의 요청 순서·수집 시 주의·검증 범위 |
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
| **체인 5 (11/24): OOB 읽기·쓰기 → 코드 실행(캐나리)** | `exploit/E2E-EXPLOIT-SUITE.md` 체인 5 — `exploit/src/J4sRceVictim.java` + `exploit/j4s_rce.py` + `exploit/j4s_rce.sh` |
| 체인 5 결과 | `exploit/results/rce-{vuln,1708,mitig,patched}-2026-11-24-*/` (취약 9/9 캐나리, 완화·패치 손상 0) |
| **체인 6 (11/24)·후속 (11/25)** | `exploit/E2E-EXPLOIT-SUITE.md` 체인 6과 후속 절 — `exploit/results/rce-*-20261125-*/` |
| 체인 5·6 원격 pcap 묶음 | `exploit/results/pcap/j4s-chain5-remote-share.tar.gz`, `j4s-chain6-remote-share.tar.gz` (snaplen 96 — 요청 라인은 보이고 응답 본문은 범위 밖) |
| 인프라 모니터링 체크리스트 (11/25) | `MONITORING-CHECKLIST-2026-11-25.md` |
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
