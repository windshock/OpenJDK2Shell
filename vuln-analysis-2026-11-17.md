# 타깃 취약점 사전 분석 — NCSC 2026-11-16 OpenJDK RCE 공지

작성일: 2026-11-17 · 작성자: windshock (ZCode 분석 보조)
전제 문서: README.md (모니터링 환경) · 상태: **패치 미공개, 추정 단계**

---

## 1. 질문 정의

NCSC 공지(2026-11-16): "OpenJDK Java 17.0.6 이상, 인증 없는 RCE, CVSS 9.2, CVE 미지정,
Oracle 패치 공개 예정" — **수정이 공개되기 전에, 저장소 이력만으로 취약 컴포넌트와
메커니즘의 후보를 좁혀 패치 공개 즉시 검증할 수 있게 한다.**

## 2. 확정 사실 (fact — 직접 확인)

| # | 사실 | 확인 수단 |
|---|---|---|
| F1 | jdk17u 수정 커밋·GA 태그 없음 (11/17 현재 2회 확인) | `check_patch.sh` |
| F2 | 4개 LTS(jdk11u/17u/21u/25u)에 `.1` OOB 브랜치 동시 개설 (10/30) | README + GitHub API |
| F3 | **jdk11u OOB 브랜치에 11/11자 범프 커밋**(`8396904`) 추가 — 릴리스 준비 진행 중 | GitHub API |
| F4 | 10월 사건(CVE-2026-91403) = eMudhra CA 키 유출·MitM(9.1), 10월 OOB(17.0.21.0.2/.0.3)로 이미 처리 — **타깃과 별개** | 보안뉴스 10/23 기사, foxydog 11/2 글 |
| F5 | `jdk17.0.21.1` 브랜치 최신: tzdata/libpng/FreeType/테스트뿐 | git log |
| F6 | Base64 AVX-512 decode intrinsic(`8268276`, Intel)은 **17.0.6에 도입**(2022-11 커밋 → 2023-01 릴리스) | git log `jdk-17.0.5-ga..jdk-17.0.6-ga` |
| F7 | 동 intrinsic에서 **실제 버그 전력**: `8321599 "Data loss in AVX3 Base64 decoding"`(2024-01, 17.0.11 수정) — ByteBuffer 슬라이스 offset 미반영으로 패딩 검사가 잘못된 위치 참조 | git show 1f95796210 |
| F8 | intrinsic 계약: *"no length check is possible on dst, so dst is assumed to be large enough"* — **dst 무검사 쓰기 네이티브 코드** | Base64.java decodeBlock 주석 |
| F9 | decode intrinsic이 11u/17u/21u/25u **전 라인에 존재** — F2의 4개 라인 동시 OOB와 정합 | raw 파일 확인 (stubGenerator 9/—/33/84건) |

## 3. 전제 (premise — 미검증)

- P1: 공지의 "17.0.6 이상" = 취약 코드의 **도입 시점**이 17.0.6이라는 해석.
  (반대 해석: 지원 버전 표기 단순화. 이 경우 후보가 전 범위로 넓어짐)
- P2: "인증 없는 RCE" = JDK 라이브러리가 공격자 데이터를 인증 이전에 파싱하는 경로.
  (애플리케이션이 java.util.Base64로 미인증 토큰을 디코드하는 것이 전형적)
- P3: NCSC 공지와 jdk17.0.21.1 OOB 브랜치의 연관 (README 명시대로 미확정)

## 4. 가설 평가

| 가설 | 컴포넌트 | 판정 | 근거 |
|---|---|---|---|
| **H2** | **Base64 AVX-512 decode intrinsic** | **채택(최우선)** | F6~F9 전부 부합. 네이티브 asm + dst 무검사 쓰기 + 길이/패딩 오판 전례 + 인증 이전 데이터 경로 + 4라인 존재 |
| H1 | DH Key Exchange (`8293554`, 17.0.6) | 기각 | 순수 Java 파라미터 로직 — 결함 형태가 약한 키/DoS지 메모리 커럽션 아님 |
| H3 | JDWP 백엔드 (`8256811`, 17.0.6) | 보류 | 인증 없는 리스너이나 `-agentlib:jdwp` 비기본 활성화 — 무조건 9.2와 불일치 |
| H4 | 폰트/사운드 파서 (`8288516`) | 기각 | 로컬 파일 필요, 네트워크 사전 인증 경로 아님 |

### H2 상세 메커니즘 (패치 공개 시 검증 대상)

`stubGenerator_x86_64.cpp::generate_base64_decodeBlock` (jdk17.0.21.1 기준 ~5944–6360행):

1. **메인 루프**: `evmovdquq`로 `source+start_offset`에서 256바이트씩 비마스크 로드
   (6062–6065행). MIME 스킵 로직(`cmpl(isMIME, 0)`, 6032행)이 길이 산정을 틀리면
   **소스 끝 넘어 읽기(OOB read)** 가능.
2. **패딩 처리**: `8321599` 수정부(6192–6197행의 addq/subq 짝) — 이 영역의 또 다른
   변종 시 길이 오판 → `chars_decoded` 역산 오류 → `sp` 디싱크 → 이후 블록이
   **짧은 dst에 과다 쓰기**(F8: dst 무검사) = 힙 오버플로.
3. **MIME 모드**: 불법 문자 무시 로직은 상태가 가장 복잡하고 2025년까지 벤치
   수정(`8338595`)이 있던 활성 영역 — 변종의 1순위 서스펙트.

공격 경로(P2 하에서): HTTP Basic 인증 헤더, API 토큰/JWT, SASL 등 **인증 전**에
base64 디코드하는 서비스. 발동 조건: AVX-512 CPU + C2 컴파일된 decodeBlock +
fast-path 길이(`sp < sl - 4`) 충족 입력. → "네트워크 / 권한 불필요 / UI 불필요"의
CVSS 9.2 프로파일과 부합.

## 5. 반증·검증 절차 (패치 공개 시)

```bash
./check_patch.sh                       # 1. 공개 감지
git -C jdk17u log jdk-17.0.21.0.3-ga..origin/jdk17.0.21.1 --stat
```

- diff에 `stubGenerator_x86_64.cpp` / `Base64.java` / `stubRoutines_x86*` 포함 → **H2 확정**,
  회귀 테스트(신규 `TestBase64*`)가 슬라이스/MIME/길이 경계 케이스면 메커니즘까지 확정
- `java.rmi`/직렬화 → H3 부활, `sun/security/ssl` DH → H1 부활
- 전부 아님 → P1(버전 하한 해석)부터 재검토

## 6. 임시 대응 (P1·P2·P3 하에서, 패치 전)

- AVX-512 CPU 사용 여부 확인(`sysctl -a | grep avx512` / `lscpu`) — 해당 없으면 이 경로 노력가치 급감
- 인증 전 base64 디코드 지점 인벤토리화(게이트웨이·인증 필터·토큰 파서)
- 패치 공개 즉시 17.0.21.1 적용 (jdk11u 11/11 범프 커밋=F3 감안, 릴리스 임박)

## 7. 한계

- NCSC 원문(boho.or.kr)은 포털 렌더링 문제로 미확보 — README 요약 신뢰
- 전체가 **사전 공개 저장소 이력만으로 만든 추정**이며, H2는 "가장 잘 맞는 후보"일 뿐
  확정 아님. 확정은 §5 절차로만 가능.

---

## 8. 2차 교차검증 (외부 시드 반영, 2026-11-17 오후)

입력: 외부 사전분석 2건(Oracle CSPU 사전공지 정보, CVE-2024 HotSpot 선례 표 + 도달성 프레임).
모든 주장을 저장소·원문으로 재확인한 결과:

### 8.1 새로 확보한 사실

| # | 사실 | 확인 |
|---|---|---|
| F10 | **Oracle CSPU 2026-11 사전공지**(페이지 갱신 11/12): 릴리스 **2026-11-17(화) = 오늘**. Java SE 수정 **11건, 전건 인증 없는 원격 악용 가능**, 최고 CVSS v3.1 **8.1**. 영향: 8u511, 11.0.33, **17.0.21**, 21.0.13, 25.0.5, 27.0.1 + GraalVM/JavaFX | oracle.com/security-alerts/cspunov2026.html 원문 |
| F11 | NCSC 9.2는 **CVSS 4.0** — Oracle 8.1(v3.1)과 모순 아님(동일 취약점의 다른 척도로도 성립). 단, 동일 취약점이라는 것 자체는 미확인 | 시드 문서 |
| F12 | 시드의 17.0.6 시딩 후보 5건 **전부 실재·17.0.6 포함 확인**: `8287411 Enhance DTLS performance`(04f32aac), `8273553 closeInbound`(b75b9320), `8277881 TLS1.3 SessionID`(5ff0ebd5), `8293734 Improve BMP image handling`(2b6f063c), `8295687 Better BMP bounds`(adeba02e0) | git log |
| F13 | CVE-2024-211xx 계열(HotSpot unauth-RCE 선례)과 정합하는 embargo형 커밋이 17.0.11(2024-04 CPU) 창에 실재: `8322122 Enhance generation of addresses`(hotspot), `8318340 Improve RSA key implementations`(java.base), `8323243 JNI invocation ... corrupts the stack` — **수정 커밋 식별 템플릿 + repo가 실CVE 이력의 ground truth임을 입증** | git log |
| F14 | `CVE-2026-114938` 공개 검색 결과 없음 — 미확인 식별자로 분류 (시드 문서 자체 경고와 일치) | web search |
| F15 | jdk17.0.21.1 헤드 변화 없음(11/17 기준, tzdata가 최신). Oracle 정식 매트릭스는 아직 사전공지 상태 | git + 원문 |

### 8.2 시드 평가 — 수용/보류

- **수용(프레임)**: "도달성 4단계"(진입→도달→결함→실행제어)와 "RCE ≠ 메모리 커럽션만"
  (신뢰경계·코드 로딩 포함). §4 가설 평가의 잠재 전제였던 것을 명시적 프레임으로 승격.
- **수용(방법론)**: "17.0.6 이상 ≠ 17.0.5 안전 실증" — P1은 전제 유지. 단 Oracle 관례상
  영향버전은 '라인 최신(17.0.21)'만 기재하므로, NCSC의 17.0.6 하한은 여전히 **도입 시점
  정보가 있다는 신호**로 가치 있음(해석 2가지 병기).
- **보류(후보)**: 시드의 DTLS·closeInbound·SessionID·BMP 4건 — 실재는 확인(F12)했으나
  전부 **순수 Java 계층**(JSSE 상태처리·이미지 파서)으로 메모리 커럽션 RCE의 형태가 아님.
  H1(DH)과 같은 사유로 낮은 순위. DTLS `8287411`은 pre-auth 서버 핸드셰이크 경로라
  **DoS·상태혼동형** 후보로는 유효 — RCE 공지와 어긋나므로 보류.
- **신설 H5(선례 기반)**: CVE-2024-21131형 **HotSpot 문자열/UTF-8 처리 결함에 외부 데이터
  도달** — Oracle이 해당 건에 "웹서비스가 외부 데이터를 취약 API에 전달" 경로를 명시한
  선례(F13 템플릿)가 있음. 단 17.0.6 도입 연결고리 없음 → 순위는 H2 다음.

### 8.3 가설 순위 (갱신)

1. **H2 Base64 AVX-512 decode intrinsic** — 도입·네이티브·pre-auth 도달성·전 라인 정합 유지
2. **H5 HotSpot 문자열/UTF-8 + 외부 데이터 도달** (CVE-2024-21131 선례 클래스)
3. H3 JDWP / H1 DH / 시드 4건 — 형태 불일치로 보류

### 8.4 출구 규칙 갱신 (오늘 밤 릴리스 대응)

CSPU가 Java SE **11건**이므로 release-day에 브랜치에는 **여러 Enhance/Improve 커밋이
한꺼번에** 올라온다(README의 8월 OOB 3커밋 패턴의 확대판). 절차:

1. `./check_patch.sh` — `-ga` 태그 또는 신규 커밋 감지
2. `git -C jdk17u log jdk-17.0.21.0.3-ga..origin/jdk17.0.21.1 --stat` — **전 커밋 목록화**
3. 우선순위: `stubGenerator_x86_64.cpp`/`Base64.java` → H2 확정 /
   `hotspot` 문자열·인트린식 → H5 / `java.rmi`·직렬화 → H3
4. Oracle 정식 매트릭스 갱신 후 CVE 표와 커밋 1:1 대조(11건 전수)
5. 회귀 테스트 파일명·케이스가 공격 조건을 직접 설명 — 테스트가 말하는 입력 축 기록

### 8.5 운영 비고

- 이 저장소(blobless)에서 `git grep`(트리 전체)·광역 `git show`는 **전 blob을 주문 다운로드
  해 디스크를 채움** (11/17 ENOSPC 사고, auto-gc가 repack 시도로 악화). `git config gc.auto 0`
  조치 완료. 향후 경로 한정 `git show`만 사용.
- jdk11u OOB 브랜치의 11/11 범프(F3)와 CSPU 공개일(11/17) 정합 — 릴리스 파이프라인 가동 중.

---

## 9. 구현 산출물 (2026-11-17 3차 — 모니터링/임시패치/E2E 하니스)

### 9.1 아키텍처 정정 (H2 정밀화)

- aarch64에도 Base64 decode intrinsic 존재(`8256245`, **GA 17.0.0부터** — 태그 실측).
  NCSC "17.0.6 이상" 하한은 **x86 도입(8268276, 17.0.6)** 과만 정합 →
  **H2 주 타깃 = x86 AVX-512 스텁**, aarch64 대응물은 부차 표면.
- 스텁 생성 게이팅 실측: `if (UseBASE64Intrinsics)` (globals.hpp **product** 플래그)
  → `-XX:-UseBASE64Intrinsics` 로 전 아키텍처에서 intrinsic만 차단 가능.

### 9.2 산출물

| 경로 | 내용 | 검증 |
|---|---|---|
| `exploit/` | E2E 검증 하니스: victim(인증 전 디코드 3경로) + 트리거 4패밀리 193케이스 + Python 오라클 대조 + hs_err 감시 | **로컬 17.0.7 arm64 전 스윕 0 이상** (aarch64 무관측 = x86 국한 가설 지지) |
| `ops/monitor.sh` (+워크스페이스 cron 30분) | GitHub API 폴링 감시, blob fetch 없음 | 1회 실행 OK |
| `ops/inventory.sh` | 버전×AVX-512×플래그 노출 판정 | 로컬 판정 OK |
| `ops/mitigate.sh` | **`-XX:-UseBASE64Intrinsics`** (systemd drop-in / JAVA_TOOL_OPTIONS / WAF 스니펫) | `verify` 모드로 플래그 확인 OK |
| `ops/scan_hs_err.sh` | 크래시 tripwire(Base64 관련 hs_err 탐지) | — |

### 9.3 익스플로잇에 대한 원칙적 입장

실제 메모리 커럽션 익스플로잇은 **프리미티브(수정 diff) 공개 전작성 불가**하며, 섣부른
작성은 검증 불가능한 연극이 된다. 따라서 E2E는 "인증 없는 입력 → 취약 코드 도달 →
관측 가능한 신호" 파이프라인을 **지금** 증명해 두고, 패치 공개 즉시 트리거를 정밀 조정한다.
영향 입증은 캐나리 마커(`exploit/payloads/canary.py`)로 충분하다. 역방향 소켓 스테이징
(참고 제시됨: windshock/Linux-Reverse-Socket-Stagers, ret2csu+angrop)은 프리미티브 확정
후 승인된 랩에서만 payloads/ 슬롯에 통입한다.

### 9.4 x86_64 컨테이너 실측 (2026-11-17 4차 — colima x86_64 VM + Temurin 17.0.8)

스텝 전체 오딧트(§8 절차 후속)로 후보 3곳 특정 → directed 트리거 38케이스 추가(총 231) →
`e2e --diff`(intrinsic 강제 on/off 비교) 모드 탑재 → colima x86_64 VM(QEMU)에서 실행.

| 실측 | 값 |
|---|---|
| 컨테이너 CPU 플래그 | `avx avx2` — **avx512 없음** (에뮬레이션 한계, 예측과 일치) |
| UseBASE64Intrinsics 기본값 | **false** (AVX-512급 CPU에서만 기본 활성 확인 — §9.1 완화 전제의 경험적 뒷받침) |
| differential 결과 | 231케이스 × on/off: **이상 0 / 0 / DIVERGENT 0** — brute-force intrinsic == Java 폴백 |
| 오라클 보정 | Java basic 실측 시맨틱 반영: 꼬리 r=2→+1B·r=3→+2B 허용, r=1·비정상 패딩·불법 문자 거부 |

결론: VBMI fast path(오딧트 후보 3곳의 소재)는 **AVX-512 실리콘에서만 검증 가능**.
`ops/docker/run_x64.sh` 한 줄이 AVX-512 호스트(클라우드 c5/c6i 계열, 사내 인텔 서버)에서
동일하게 재사용된다. 패치(17.0.21.1) 공개 시 §8.4와 병행.

### 9.5 AVX-512 실리콘 실측 (2026-11-17 5차 — 사내 DFIRtx dev 쿠버네티스)

**방법(기술 요약)**: JVM의 Base64 디코드는 구현이 두 벌이다 — AVX-512(VBMI) CPU에서만
실행되는 손으로 쓴 어셈블리 루틴(**[A]**, stubGenerator가 생성)과 항상 존재하는 Java
참조 구현(**[B]**, Base64.java). 양자는 임의의 입력에 대해 항상 동일한 결과를 내야
하므로, 같은 입력을 [A] 강제 환경과 [B] 환경에 각각 먹이고 **결과가 갈리는 순간 = [A]의
버그가 직접 증명**된다(차등 테스트). [A]는 버그 전례(8321599)가 있는 코드로, NCSC 버전
하한(17.0.6)이 [A]의 도입 시점과 일치해 H2의 대상이었다.

- **환경**: DFIRtx dev 클러스터 — 전 노드 AMD EPYC-Genoa(`avx512vbmi/bw/vl` /proc/cpuinfo
  실측 확인). Temurin 17.0.8 Pod + 클래스 ConfigMap + NodePort 31808, Mac에서 발사.
  `UseBASE64Intrinsics` on/off를 JAVA_TOOL_OPTIONS로 양팔 확인(true/false)
- **결과**: 231케이스 × (on/off) — **MISMATCH 0/0, DIVERGENT 0, 크래시 없음**
- **증거**: `exploit/results/oj2s_genoa_{on,off}.jsonl` (커밋 36ad7d1)
- **판정 (2026-11-17 외부 검토 반영 교정)**: 오딧트 후보 3곳은 이 입력 공간에서 무결 →
  **"이 입력 공간·이 관측축(출력 차등)에서 H2 데이터커럽션 가설은 지지되지 않음"** —
  종전 표기 '약화'는 과한 서술이었다. 단 차등시험은 조용한 힙 커럽션을 구조적으로 못 보므로
  **기각도 불가**. 아울러 H2 전체가 미검증 전제 P1("17.0.6 = 도입 시점", 출처는 NCSC 요약뿐)
  위에 서 있음 — Oracle 표기(17.0.21=라인 최신)는 도입 시점 정보가 아니다.
  **최종 판정은 패치 diff(§8.4) 또는 Oracle 매트릭스 Component 열** — 후보 전체 균등
  심층 분석은 `GOAL-deep-analysis.md` 로 이관.
- 검증 3계층 완결: arm64(도구) → x86 에뮬레이션(brute-force 경로) → AVX-512 실리콘(VBMI 경로)
- 운영: 테스트 후 `oj2s-test` 네임스페이스 삭제로 클러스터 원상복구
