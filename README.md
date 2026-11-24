# OpenJDK 17 비정기 보안 패치 모니터링

작성일: 2026-11-17 · 담당: windshock <windshock@gmail.com>

NCSC 공지(2026-11-16, "OpenJDK Java 17.0.6 이상, 인증 없는 RCE, CVSS 9.2, CVE 미지정,
Oracle 패치 공개 예정")에 대응해, 패치가 공개되는 즉시 수정 내용을 확인하기 위한 모니터링
환경이다. **현재(작성 시점) 이번 취약점의 수정 코드는 공개 저장소에 아직 없다.**

## 결과 분류 (2026-11-24 — 이 표가 최신 판정)

| 범주 | 이 저장소의 판정 | 근거 |
|---|---|---|
| Java4Shell OOB 쓰기 | **실측** — 인접 객체 헤더 length 손상 관측, 완화·수정 빌드에서 CLEAN | `OOB-OBSERVATION-2026-11-18.md`, `CORRECTION-3.md` |
| Java4Shell → JVM 크래시 (DoS) | **실측 + 인과 확인** — 취약 6/10 vs 패치·완화·정상 입력 0/10 | `research/RESULTS-2026-11-23.md` |
| Java4Shell → 정보 유출 | **실측(랩 모델, 11/24)** — 손상된 length로 힙 449 MiB를 읽어 인접하지 않은 객체의 ops 세션 토큰 회수. 실앱 대상 아님 | `exploit/E2E-EXPLOIT-SUITE.md` 체인 5 |
| Java4Shell → 코드 실행 (RCE) | **실측(랩 모델, 11/24)** — 두 경로. ① 메모리 손상만: OOB 쓰기 3건으로 피해자의 `Method.invoke`를 `Runtime.exec`로 바꿔 호출(체인 6, 취약 JDK 8/8, 완화·패치 0/2). ② 앱 로직 승격: OOB 읽기로 ops 토큰을 회수해 토큰 보호 exec 인터페이스 호출(체인 5, 취약 JDK 17/17). 실앱 대상 아님. 외부 보고는 REPORTED (Calif·Hadrian·VulnCheck) | `exploit/E2E-EXPLOIT-SUITE.md` 체인 5·6, `CORRECTION-3.md` C-7 |
| 역직렬화 체인 (RMI/LDAP → TemplatesImpl) 코드 실행 | **실측** — 단 CVE-2026-114938과 **별개**, serialFilter=null·add-opens/exports 조건 | `exploit/E2E-EXPLOIT-SUITE.md` 체인 1·2·1+ |

두 체인 모두 **GC가 없는 구간 안에서만** 성립한다 — 손상 뒤 GC가 오면 JVM은 죽는다(체인 5 §왜 되는가 6).

11/23까지는 정보 유출·코드 실행 둘 다 "입증 안 됨"이었다(`ESCALATION-STATUS-2026-11-18.md`, `CORRECTION-3.md` C-7). 11/24에 바뀐 것과 그 전제·한계는 체인 5 절에 있다.

문서 곳곳의 "PWNED"는 체인 3·4(Java4Shell)에서는 **JVM 사망(DoS)**을 뜻한다 (CORRECTION-3 C-11).

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

## 현재 상태 (2026-11-17)

- **비정기 패치 준비 정황 있음.** `jdk17u`에 `jdk17.0.21.1` 브랜치(10/30 생성)와
  `jdk-17.0.21.1+1` 태그 존재. jdk11u·21u·25u에도 `.1` 비정기 브랜치가 동시에 열림
  (`jdk11.0.33.1`, `jdk21.0.13.1`, `jdk25.0.5.1`). 8월 OOB 패치 직전과 동일한 모습.
- **수정 커밋은 아직 없음.** 현재 브랜치에는 tzdata2026f, libpng 1.6.59, FreeType 2.15.0
  업데이트와 테스트 수정만 있음. `-ga` 태그도 미발행.
- Oracle 보안 공지 페이지(oracle.com/security-alerts)는 403으로 확인 불가.
- 이번 공지와 `jdk17.0.21.1` 브랜치의 연관성은 **확인되지 않음**(정황상 추정일 뿐).

## 저장소 구성

- `jdk17u/` — `openjdk/jdk17u` blobless clone(`--filter=blob:none --no-checkout`).
  이력만 받아 가볍다. 패치 공개 시 `git show <hash>`로 diff + 회귀 테스트 열람.
- `check_patch.sh` — 최신 브랜치/태그를 fetch 후 `jdk-17.0.21.1-ga` 태그나
  `Enhance/Improve` 커밋이 생겼는지 확인.

## 사용법

```bash
cd ~/Downloads/OpenJDK2Shell
./check_patch.sh                      # 패치 공개 여부 확인(현재 모두 "아직 없음")
# 커밋이 보이면:
git -C jdk17u show <hash>             # 수정 코드 + 추가된 회귀 테스트 diff
git -C jdk17u log jdk-17.0.21.0.3-ga..origin/jdk17.0.21.1 --stat
```

패치 공개 후 분석 순서:
1. `jdk-17.0.21.0.3-ga..jdk-17.0.21.1-ga` diff에서 `Enhance/Improve` 커밋 식별
2. 공지 대상("17.0.6 이상")과 겹치는 컴포넌트 우선 확인
3. 추가된 회귀 테스트가 공격 조건·입력 형태를 드러내므로 먼저 읽기

## 참고

- https://github.com/openjdk/jdk17u (릴리스 브랜치 — 패치가 여기 올라옴)
- https://github.com/openjdk/jdk17u-dev (유지보수 개발)
- 8월 OOB 선례: 브랜치 생성 후 약 2주 뒤 패치 공개

## 산출물 (2026-11-17 분석·구현 완료)

NCSC 공지 대응 3단계 수행 결과. 전 과정은 `vuln-analysis-2026-11-17.md` 참조.

| 경로 | 내용 |
|---|---|
| `vuln-analysis-2026-11-17.md` | 사전분석 보고서 — 사실/전제 분리, 가설 순위(H2 Base64 AVX-512 intrinsic > H5 HotSpot 문자열), Oracle CSPU 교차검증, 출구 규칙 |
| `check_patch.sh` | 패치 공개 수동 확인 (git 기반) |
| `ops/monitor.sh` (+cron 30분) | 공개 감시 자동화 — GitHub API 폴링(blob fetch 없음) |
| `ops/inventory.sh` | JDK 버전 × AVX-512 × 플래그 노출 판정 |
| `ops/mitigate.sh` | 임시 패치: `-XX:-UseBASE64Intrinsics` (product 플래그, 소스 검증) / WAF 스니펫 |
| `ops/scan_hs_err.sh` | 공격 시도/크래시 tripwire |
| `exploit/` | E2E 검증 하니스 — 인증 전 디코드 희생서비스 + 트리거 **231케이스**(directed 포함) + `--diff` differential + 실측 증거(`results/`). 프리미티브 확정 전 무기화 없음(캐나리 정책) |
| `ops/docker/` | x86_64 검증 러너 (Temurin 17.0.8 이미지 + `run_x64.sh`) — AVX-512 호스트 공용 |
| `jdk17u/` | blobless clone (gitignore — 저장소에 미포함) |

현재 상태: **17.0.21.1 GA 대기** (Oracle CSPU 2026-11-17 릴리스 예정). 감시 자동화 동작 중.
H2는 AVX-512 실리콘(사내 DFIRtx 클러스터) 차등 테스트에서 무관측 — **약화됨, 최종 판정은 패치 diff** (상세: `vuln-analysis-2026-11-17.md` §9.5).
