# OpenJDK2Shell — Java4Shell (CVE-2026-114938) 분석·실증·대응 랩

작성일: 2026-11-17 · 최종 갱신: 2026-11-25 · 담당: windshock <windshock@gmail.com>

NCSC 공지(2026-11-16, "OpenJDK Java 17.0.6 이상, 인증 없는 RCE, CVSS 9.2") 대응으로 시작한 저장소다.
취약점 분석 → 원격 재현 → E2E 익스플로잇 체인 → 관제 공유 자료·대응 가이드까지 담고 있다.
처음(11/17)에는 패치 공개 감시 환경이었다. 패치는 17.0.21.1로 공개됐고, 현재 판정은 아래 표가 최신이다.

## 결과 분류 (2026-11-25 — 이 표가 최신 판정)

| 범주 | 이 저장소의 판정 | 근거 |
|---|---|---|
| Java4Shell OOB 쓰기 | **실측** — 인접 객체 헤더 손상 관측, 완화·수정 빌드에서 CLEAN | `OOB-OBSERVATION-2026-11-18.md`, `CORRECTION-3.md`, `research/mechanism/MECH-RESULTS.md` |
| Java4Shell → JVM 크래시 (DoS) | **실측 + 인과 확인** — 취약 6/10 vs 패치·완화·정상 입력 0/10. 실앱(HBase REST) JVM 크래시 2회 | `research/RESULTS-2026-11-23.md`, `exploit/E2E-EXPLOIT-SUITE.md` 체인 3·4 |
| Java4Shell → 정보 유출 | **실측(랩 모델, 11/24)** — 손상된 length로 힙 449 MiB를 읽어 인접하지 않은 객체의 ops 세션 토큰 회수. 실앱 대상 아님 | `exploit/E2E-EXPLOIT-SUITE.md` 체인 5 |
| Java4Shell → 코드 실행 (RCE) | **실측(랩 모델, 11/24~25)** — 두 경로. ① 메모리 손상만(체인 6): 피해자의 `Method.invoke`를 `Runtime.exec`로 바꿔 호출 — JDK 17 + CDS 기본 아카이브에서 빌드 상수 없이 11/11, 한 번도 재지 않은 빌드(17.0.18·17.0.19) 포함. ② 앱 로직 승격(체인 5): OOB 읽기로 ops 토큰을 회수해 토큰 보호 exec 인터페이스 호출 — 취약 JDK 17/17(11/24), 11/25 추가 19회 전부 성공. 실앱 대상 아님. 외부 보고는 REPORTED (Calif·Hadrian·VulnCheck) | `exploit/E2E-EXPLOIT-SUITE.md` 체인 5·6, `CORRECTION-3.md` C-7 |
| 역직렬화 체인 (RMI/LDAP → TemplatesImpl) 코드 실행 | **실측** — 단 CVE-2026-114938과 **별개**, serialFilter=null·add-opens/exports 조건 | `exploit/E2E-EXPLOIT-SUITE.md` 체인 1·2·1+ |

### 범위와 한계

- **코드 실행의 피해자는 랩 모델이다** (`exploit/src/J4sRceVictim.java`). 실제 애플리케이션에서 재현한 것은 JVM 크래시(DoS)까지다.
- 두 체인 모두 **손상 뒤 GC가 없는 구간 안에서만** 성립한다 — GC가 오면 JVM은 죽는다(`exploit/E2E-EXPLOIT-SUITE.md` 체인 5 §왜 되는가).
- **체인 6은 JDK 17 라인 + CDS 기본 아카이브로 한정된다.** 슬롯 두 개(`Runtime.exec(String)`=16, `Class.getDeclaredField(String)`=139)를
  CDS 아카이브가 고정한다. CDS를 끄면(`-Xshare:off`) 슬롯이 실행 설정마다 달라져 체인 6은 실패한다(체인 5는 정상).
  JDK 18 이상은 기본 리플렉션이 메서드 핸들 기반(JEP 416)이라 호출 시점에 슬롯을 읽지 않는다.
- JDK 21.0.13+9에서도 취약점 자체는 그대로 있었다(랩, 3회).
- 종점은 캐나리 마커다. 스테이저는 없다(`GOAL-find-and-exploit.md` §1-3).

11/23까지는 정보 유출·코드 실행 둘 다 "입증 안 됨"이었다(`ESCALATION-STATUS-2026-11-18.md`, `CORRECTION-3.md` C-7). 11/24에 바뀐 것과 그 전제·한계는 체인 5·6 절에 있다.

문서 곳곳의 "PWNED"는 체인 3·4(Java4Shell)에서는 **JVM 사망(DoS)**을 뜻한다 (CORRECTION-3 C-11).

## 취약점 요약

| 항목 | 내용 |
|---|---|
| CVE | CVE-2026-114938 — Base64 AVX-512 assembly OOB 쓰기 (Java4Shell) |
| 트리거 | JDK 17: `A`×128 + `=` (129바이트) — 4바이트 미만 패딩 조각을 assembly가 처리 |
| 패치 | 17.0.21.1 커밋 `8ea73158af` (8393212) — `cmpl(length,4); jcc(L_bruteForce)` 4줄 |
| 취약 버전 | 17.0.6~17.0.21.0.x (intrinsic 도입 = 17.0.6) |
| 완화 | `-XX:-UseBASE64Intrinsics` 또는 17.0.21.1 업그레이드 |
| 발동 조건 | x86 + AVX-512 VBMI·BW + C2 컴파일된 `Base64.Decoder.decode0`. 실측은 AMD EPYC Genoa |

같은 기간에 구분해 둔 별개 문제: C2 JIT 계산 버그 8389989 (`CORRECTION-2.md`), TemplatesImpl 역직렬화(add-opens 조건), LDAP `trustSerialData`(17.0.13에서 이미 패치).

## OpenJDK가 보안 패치를 공개해 온 방식 (jdk17u 이력으로 확인)

공개 저장소 `openjdk/jdk17u`의 과거 릴리스를 직접 확인한 결과.

| 릴리스 | 날짜 | 종류 | 공개 방식 |
|---|---|---|---|
| 17.0.21 | 2026-10-20 | 정기(CPU) | 10/7~10/17에 `Enhance HTTP Client Response Handling` 등 보안 커밋 수십 개가 한꺼번에 반영 |
| 17.0.20.1 | 2026-08-07 | 비정기(OOB) | 7/24에 `jdk17.0.20.1` 브랜치 생성 → 수정 커밋 3개와 GA 태그가 **릴리스 당일(8/7)** 함께 공개 |
| 17.0.21.0.2/.0.3 | 2026-10 | 비정기 | CA 인증서 관련 수정만 포함 |

핵심 패턴:
- 보안 수정은 **릴리스 당일에야** 공개 저장소에 나타난다(embargo). 사전 열람 불가.
- 커밋 제목은 내용을 가리려 `Enhance X` / `Improve X` 형태로 작성된다. 연결된 JBS 이슈는 비공개.
- 패치는 `jdk17u-dev`가 아니라 **`jdk17u`의 릴리스 브랜치**(`jdk17.0.X.Y`)에 올라온다.

## 현재 상태 (2026-11-25)

- **패치는 공개·확인됐다.** 17.0.21.1 (커밋 `8ea73158af`). 자체 빌드 17.0.21.1에서 OOB 미관측 — `exploit/results/jdk17u-build-and-canary.log`.
- **실증 흐름:** OOB 직접 관측(11/18) → DoS 인과 확인·기전 실측(11/23) → 코드 실행 두 체인(11/24) → 체인 6 후속: 미러 상수 제거·한계 확정(11/25).
- **대응 자료:** `DEFENDER-GUIDE.md`, `OPS-SHARING-2026-11-18.md`, `WAS-LOG-CRASH-ANALYSIS-2026-11-18.md`, `KISA-REPLY-2026-11-20.md`.
- **열린 문제:** 체인 6의 JDK 18 이상 기본 경로(MethodHandle)는 만들지 않았다 · CDS를 끈 JVM에서 슬롯을 힙에서 읽는 방법은 찾지 못했다 ·
  실제 애플리케이션 대상 코드 실행은 입증하지 않았다. 후속 후보는 `HANDOFF.md` §6.

## 저장소 구성

- `exploit/` — 트리거 스윕 하니스(`e2e.py`·`trigger_gen.py`), OOB 관측 도구(`src/OobCanary.java`, `oob_run.sh`),
  체인 5·6 증거 러너(`j4s_rce.sh`·`j4s_rce.py`), 실측 증거(`results/`), 아키텍처 문서 `E2E-EXPLOIT-SUITE.md`
- `research/` — 관측 연구(11/23): 계획·사전등록·결과(`RESULTS-2026-11-23.md`), 기전 실측(`mechanism/`), 원자료(`data/`)
- `ops/` — 감시·인벤토리·완화·탐지 스크립트, 실앱 E2E(HBase·Spring 등), x86_64 docker 러너
- 최상위 문서 — 분석·정정·관제 공유·대응 가이드 (아래 문서 지도)
- `check_patch.sh`, `jdk17u/` — 패치 감시(11/17). `jdk17u/`는 blobless clone이라 저장소에 포함되지 않는다

## 사용법

패치 릴리스 브랜치 확인(11/17 감시 용도):

```bash
cd ~/Downloads/OpenJDK2Shell
./check_patch.sh                      # 최신 브랜치·태그에서 Enhance/Improve 커밋 확인
git -C jdk17u show 8ea73158af         # 17.0.21.1 수정 커밋 diff
```

체인 5·6 증거 러너 — 회차마다 새 victim JVM을 띄워 무인증 공격자를 돌리고, 캐나리 파일·토큰 지문·GC 로그를 공격자 밖에서 검증한다:

```bash
cd exploit
./j4s_rce.sh vuln 2            # Temurin 17.0.21+9 ×2회 (취약)
./j4s_rce.sh 1708 1            # 17.0.8+7
./j4s_rce.sh mitig 1           # -XX:-UseBASE64Intrinsics 대조
./j4s_rce.sh patched 1         # 17.0.21.1+2 대조
ATK_ARGS="--runtime-pick oracle" ./j4s_rce.sh vuln 1    # 체인 6: Runtime 미러를 빌드 상수 없이 찾기
```

AVX-512 VBMI CPU 노드와 kubectl 접속 설정(저장소 미포함)이 필요하다. 결과는 `exploit/results/rce-<모드>-<시각>/`에 남는다.

## 문서 지도

| 문서 | 내용 |
|---|---|
| `HANDOFF.md` | 현재 상태·자산·운영 메모 (§0이 최신) |
| `vuln-analysis-2026-11-17.md` | 전체 분석 — 사실/전제/가설/실증 기록 |
| `CORRECTION.md` ~ `CORRECTION-3.md` | 정오표 — 과장 주장 정정 이력 |
| `OOB-OBSERVATION-2026-11-18.md` | OOB 직접 관측 보고서 — 메커니즘·레시피·매트릭스 |
| `research/RESULTS-2026-11-23.md` | DoS 인과 실험 결과 (사전등록 기반) |
| `exploit/E2E-EXPLOIT-SUITE.md` | E2E 익스플로잇 아키텍처 — 체인 1~6, 결과·전제·한계 |
| `DEFENDER-GUIDE.md` | 대응 가이드 — 완화·탐지 신호 |
| `OPS-SHARING-2026-11-18.md`, `WAS-LOG-CRASH-ANALYSIS-2026-11-18.md` | 관제 공유 문서 — 와이어 시그니처·탐지룰·로그 패턴 |
| `KISA-REPLY-2026-11-20.md` | KISA 회신 초안 |

## 참고

- https://github.com/openjdk/jdk17u (릴리스 브랜치 — 패치가 여기 올라옴)
- https://github.com/openjdk/jdk17u-dev (유지보수 개발)
- 8월 OOB 선례: 브랜치 생성 후 약 2주 뒤 패치 공개

## 산출물 (2026-11-17 — 패치 공개 전)

NCSC 공지 대응 3단계 수행 결과. 전 과정은 `vuln-analysis-2026-11-17.md` 참조. 이후 산출물은 위 절들에 있다.

| 경로 | 내용 |
|---|---|
| `vuln-analysis-2026-11-17.md` | 사전분석 보고서 — 사실/전제 분리, 가설 순위, Oracle CSPU 교차검증, 출구 규칙 |
| `check_patch.sh` | 패치 공개 수동 확인 (git 기반) |
| `ops/monitor.sh` | 공개 감시 자동화 — GitHub API 폴링(blob fetch 없음). 11/17 기준 |
| `ops/inventory.sh` | JDK 버전 × AVX-512 × 플래그 노출 판정 |
| `ops/mitigate.sh` | 임시 패치: `-XX:-UseBASE64Intrinsics` (product 플래그, 소스 검증) / WAF 스니펫 |
| `ops/scan_hs_err.sh` | 공격 시도/크래시 tripwire |
| `exploit/` | E2E 검증 하니스 — 인증 전 디코드 희생서비스 + 트리거 **231케이스**(directed 포함) + `--diff` differential |
| `ops/docker/` | x86_64 검증 러너 (Temurin 17.0.8 이미지 + `run_x64.sh`) — AVX-512 호스트 공용 |

당시 H2 가설(Base64 AVX-512 intrinsic)은 231케이스에서 미발동이라 약화된 것으로 적었었다. 이후 **재확정됐다** — 트리거를 몰라 발동하지 않았을 뿐이다 (`HANDOFF.md` §3).
