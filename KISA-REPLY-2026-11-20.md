# KISA 회신 초안 — CVE-2026-114938 (Java4Shell)

> **⚠ 2026-11-23 정정 반영** — `CORRECTION-3.md` 참조 (정정 전 문장은 그 문서에 원문 보존).


작성: 2026-11-18 · 회신 기한: 2026-11-20
모든 항목 소스 레벨 검증 완료 (jdk17u 클론, blobless 경로 한정 git show 기준).

---

## 1. 컴포넌트 판정: **hotspot/compiler** (security-libs 아님)

| 근거 | 내용 |
|---|---|
| 패치 파일 | `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp` — JIT 스텁 생성기 (commit `8ea73158af`) |
| 소속 트리 | `src/hotspot/` — JBS 컴포넌트 체계에서 hotspot 하위. intrinsic 스텁 버그는 **hotspot/compiler** |
| Advisory 대조 | OpenJDK Advisory 2026/11/17 Risk Matrix: CVE-2026-114938 = hotspot/compiler, CVSS 8.1 (v3.1) |
| 제외 근거 | `security-libs/javax.net.ssl`는 CVE-2026-114940(8393456)이 담당 — CVE-2026-114938과 무관 |
| 참고 | JDK-8389989(C2 루프 최적화)는 **별개 계산정확성 버그** — CORRECTION-2.md 참조. CVE-2026-114938의 수정 커밋은 8393212 |

## 2. 취약 버전 범위: 17.0.6 ~ 17.0.21.0.3

**코드 아키폴로지로 하한 확정 (11/18 검증)**:

| 태그 | Base64 intrinsic 상태 | 판정 |
|---|---|---|
| 17.0.5-ga | `generate_base64_encodeBlock`만 존재 (encode-only) — decode intrinsic 없음 | **decode 경로 무취약** |
| 17.0.6-ga | `generate_base64_decodeBlock` 신규 도입 — commit `07050b000c` (JDK-8268276, "Base64 Decoding optimization for x86 using AVX-512") + `7884eabfc9` (JDK-8269404, encode 최적화) | **취약 시작점** |
| 17.0.21.0.3-ga | 취약 테일 처리(`L_finalBit`, length<4 분기 없음) 유지 | 취약 |
| 17.0.21.1-ga | `8ea73158af` (JDK-8393212) — `cmpl(length,4); jcc(L_bruteForce)` 4줄 경계검사 | **수정** |

트리거가 `Base64.getDecoder().decode()` (decode 경로)이므로 하한 = decode intrinsic 도입 버전 = **17.0.6**. NCSC 하한과 정합.

**보강 (11/19 외부 검토 반영)**:
- upstream 커밋: `5177a70b385c16f26ede191fdac7aaba0bed0f8b` (JDK mainline, Tobias Hartmann,
  2026-10-13 작성 — 엠바고 후 11/17 공개). 17u backport가 위 8ea73158af.
- **Java 8**: 일반 8u는 디코드 intrinsic이 없어 무영향 — 단 **Oracle Java SE 8 Performance
  Pack(8u511b33-perf)** 만 취약 코드 포함, 8u513-perf에서 수정 (회신 시 8 라인 서술 주의).
- 벤더 수정 현황(11/18 확인): Oracle CSPU(17.0.21.1 등)·Corretto·Zulu released,
  Microsoft/RHEL pending(11/18 기준, 재확인 필요), Debian stable 취약 — 회신 시 벤더별 .1 빌드 명시 요망
  (`17.0.21` base 빌드는 미수정).
- **Temurin (11/23 갱신)**: Adoptium 11/18 공지 — 수정 빌드 17.0.21.1+2 / 21.0.13.1+2 / 25.0.5.1+2 /
  27.0.1.1+4. Docker Hub `eclipse-temurin:17.0.21.1_2-jdk(-jammy)` 11/20 게시 확인(11/23).
  플랫폼·채널별 상태는 adoptium/temurin#326에서 개별 확인 (일괄 완료로 일반화하지 않음).

## 3. 완화 플래그: `-XX:-UseBASE64Intrinsics` (product, 전 아키텍처 유효)

**활성 메커니즘 (소스 검증)**:
- `src/hotspot/share/runtime/globals.hpp`: `product(bool, UseBASE64Intrinsics, false, ...)` — 정적 기본값 **false**
- `src/hotspot/cpu/x86/vm_version_x86.cpp:951-954`: **CPU 에르고노믹스** — `UseAVX>2 && avx512vl && avx512bw`이면 `FLAG_IS_DEFAULT`인 경우 `true`로 동적 활성화
- ⇒ **AVX-512VL+BW CPU(AMD EPYC Genoa 등)에서는 기본 활성 = 기본 취약**
- `-XX:-UseBASE64Intrinsics`는 명시 플래그 → 에르고노믹스 무시(`FLAG_IS_DEFAULT` false) → 모든 CPU에서 intrinsic 차단
- 비 AVX-512 CPU에서는 명시 `+` 플래그도 에르고노믹스가 강제 해제(경고 출력)

## 4. 트리거 요약

- 입력: Base64 디코드 입력 끝에 4바이트 미만 패딩 테일 (예: `A`×128 + `=` = 129바이트)
- 경로: `java.util.Base64.getDecoder().decode()` → C2 intrinsic → AVX-512 스텁 `generate_base64_decodeBlock`
- 결함: `L_finalBit` 테일(1~63바이트) 처리에서 length<4 패딩 조각의 `output_size`가
  `0 - 패드수`로 **음수 언더플로** → `bzhiq`가 index 하위 8비트(255/254 ≥ 64)를 받아 마스크를
  지우지 않음(all-ones) → masked store가 현재 출력 위치에서 **64바이트** 쓰기, 그중
  계산된 dst 끝을 넘는 양은 62B(패드 1) / 63B(패드 2) (11/23 정정 — `CORRECTION-3.md` C-1·C-2)
- **OOB 직접 관측 완료 (11/18, DFIRtx/EPYC Genoa)**: 힙 커널리 기법으로 취약 빌드에서
  canary 헤더 length 필드 뭉개짐 관측, `-XX:-UseBASE64Intrinsics`에서 동일 실험 CLEAN
  — 상세: `OOB-OBSERVATION-2026-11-18.md`
- 무인증 트리거 조건: **공격자가 Base64 디코드가 적용되는 입력을 서버에 전달 가능**해야 함 (JSON 프로토콜의 base64 필드, HTTP Basic Auth, JWT, 멀티파트 업로드 디코딩 등)

## 5. 조치 (KISA 양식 순서)

1. **근본**: 17.0.21.1 (라인별 .1) 업그레이드 — JDK-8393212 포함 빌드
2. **임시(패치 전)**: `JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"` — 성능 영향 극히 제한
   (intrinsic 꺼짐 → Java 스칼라 경로 fallback; C2 비활성(TieredStopAtLevel=1)과 달리
   전체 JIT 성능 저하 없음. 이 때문에 §4-E C2 비활성은 임시 완화에서 제외 권장)
   **실효 대조 실험으로 입증** (취약빌드 OOB 관측 vs 플래그 OFF CLEAN — 11/18)
3. **탐지**: 실패한 OOB 시도 → hs_err_pid*.log (SIGSEGV), JFR ObjectAllocationSample 이상,
   Base64 디코드 후 예상 길이 불일치/히프 커럽션 징후. 실측에서 성공한 OOB 직후
   JVM이 SIGABRT로 사망(뭉개진 헤더 접촉) — **갑자기 죽는 Java 프로세스 + hs_err/코어**
   가 유력한 운영 탐지 신호
4. 방어 가이드 v4: DEFENDER-GUIDE.md 참조 (Base64 확정 반영)

## 6. 회신 외 유의사항

- CVE↔커밋 매핑: 공개 Advisory 커밋 컬럼과 실수정 커밋이 다른 점(8389989 vs 8393212)은
  CORRECTION-2.md에 정정 이력 보관. 회신에는 실수정 커밋(8393212) 기재.
- 8·11·21 등 타 라인 하한은 본 검증(17 라인)과 동일 논리로 별도 확인 필요
  (decode intrinsic 백포트 시점). 회신 전 타 라인 대표 태그 1개씩 아키폴로지 스폿 체크 권장.
