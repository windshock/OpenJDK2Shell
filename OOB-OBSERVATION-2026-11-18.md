# OOB 실측 승격 — CVE-2026-114938 힙 커널리 직접 관측 (2026-11-18)

HANDOFF §6-1 과제 완수: "Java 레벨 예외만으로는 커럽션 미관측" 한계를 극복하고
**OOB 쓰기를 Java 레벨에서 직접 관측**했다. 네이티브 디버거·ASAN 없이
G1 humongous 리전 그루밍 + 힙 커널리 기법.

---

## 1. 스텁 레벨 메커니즘 (소스 확정)

`jdk-17.0.21.0.3-ga` `stubGenerator_x86_64.cpp` `generate_base64_decodeBlock()`:

```
L_finalBit:  // 남은 입력 length = 1..63
  output_size = (length / 4) * 3
  // 패딩 스트립: 트레일링 '=' 1개당
  L_padding: output_size -= 1  (최대 2회)
```

**결함**: 남은 바이트 `r < 4` + 트레일링 패드 `p`개 → `output_size = 0 - p = **음수**`.
이후 `bzhiq(output_mask, -1, output_size)`는 index를 **mod 64**로 해석 →
`output_mask = (64-p) 비트` (p=1 → 63B, p=2 → **62B** — 공개 주장 크기와 일치).
`evmovdqub(dest+dp, output_mask, ...)` masked store가 dst 데이터 끝(`dp`)에서
쓰기를 시작 → **패드 수만큼의 OOB 쓰기**. 쓰여지는 값 = 입력이 전부 `'a'`(0x61)로
merge된 것의 디코드 결과(에러체크를 통과하는 가짜 유효 패턴).

트리거는 **반드시 invalid 입력**(len%4 ∈ {1,2}, 트레일링 패드) — `decode0`의
fast path(`shiftto==18 && sp < sl-4`)에서 intrinsic 호출 → 스텁이 전부 처리 후
반환 → Java slow path에서 IAE throw. **쓰기는 throw 이전에 완료됨**.

## 2. 관측 레시피 (OobCanary.java)

3가지 제약의 교점을 맞춰야 한다:

| 제약 | 조건 | 해법 |
|---|---|---|
| 버그 경로 진입 | `4k ≡ 0 (mod 64)` → 스텁 final-bit r<4 | `k = 1747616` (16의 배수) |
| Java 레벨 가시성 | 쓰기가 **살아있는 객체**에 닿아야 함 | humongous dst를 리전 경계에 배치 |
| 갭 적중 | dst 객체 ≤ 갭, 쓰기 끝 > 갭 끝 | **5리전 갭**, dst=3k+1 (객체 5리전), 쓰기 [obj+5242864, +62) vs 갭 끝 5242880 → **46B canary 직격** |

**절차**:
1. C2 워밍업 — 4종 valid 형태 인터리브 240K 호출 (§3-3 참고: **throwing 입력 절대 금지**)
2. 필러 `byte[5MB-16]`(객체 = 정확히 5리전) × 140, 0xAA 채움 (700MB)
3. 동시 마킹 사이클 유도 (GC 로그 폴링으로 완료 감지)
4. `fillers[70] = null` → 다음 사이클로 회수 → **정확히 5리전 갭** (컴팩션 없음)
5. 트리거 `"A"×(4k) + "=="` → decode가 할당하는 dst = `byte[5242849]` → 갭에 배치
6. canary = `fillers[71]` — 62바이트 스토어가 canary 헤더+데이터 직격

## 3. 시행착오 (4번의 음성 → 설계 교정)

1. **C2 컴파일 부재**: decode 2회 호출 → `decode0` 인터프리터 → 스텁 미실행.
   → 워밍업 루프 필수. intrinsic은 C2-컴파일된 decode0의 decodeBlock 호출점에서만 발동.
2. **dst 크기 오판**: `decodedOutLength`는 `3*((len+3)/4) - pads` — 초기 k 선택이
   5리전 객체를 만들어 갭(4리전)에 못 들어감. 또한 4리전 갭 설계는 쓰기가
   갭 자체 패딩에 흡수(14B 헤더만). → **5리전 갭 + k 재계산**으로 46B 직격.
3. **워밍업 중 deopt**: invalid(w5) 호출 20회가 컴파일된 decode0의 미프로파일
   throw 경로를 트리거 → uncommon trap → tier4 decode0 not-entrant → 트리거가
   인터프리터 실행. → **워밍업에서 throwing 입력 제거** (트리거의 throw는
   스텁 실행 후이므로 무해).
4. **프로브 오입력**: `"xx="`(3자)는 invalid — 유효 1패드 테일은 `"xx=="`(4자).

## 4. 결과 매트릭스 (DFIRtx worker-dev01, AMD EPYC Genoa, AVX-512)

| 셀 | 빌드 | 플래그 | 트리거 | 결과 | exit |
|---|---|---|---|---|---|
| 1 | temurin 17.0.8 | intrinsic ON (에르고노믹스 기본) | pad2 (62B) | **★★★ OOB-OBSERVED ★★★** | 42→134 |
| 2 | temurin 17.0.8 | intrinsic ON | pad1 (63B) | **★★★ OOB-OBSERVED ★★★** | 42→134 |
| 3 | temurin 17.0.8 | **`-XX:-UseBASE64Intrinsics`** | pad2 | **CLEAN** (완화 실효 입증) | 0 |
| 4 | temurin 17.0.8 | fresh small heap | pad2 | survived (흡수, 음성 — 스텁 미실행 가능성 포함) | 0 |
| 5 | 자체 빌드 17.0.21.0.3-ga | intrinsic ON | pad2 | **(빌드 진행 중 — 양성 대조)** | — |
| 6 | 자체 빌드 **17.0.21.1-ga** | intrinsic ON | pad2 | **(빌드 진행 중 — 수정빌드 대조)** | — |

**관측 포렌식 (셀 1·2 공통)**:
```
canary.length=-1503028570 (expected 5242864) ★ HEADER LENGTH FIELD SMASHED ★
★★★ OOB WRITE OBSERVED AT JAVA LEVEL — canary[71] corrupted ★★★
integrity map: ......................................................................X!....................................................................
canary deep-offset sanity (1MiB,2MiB): intact
VERDICT: OOB-OBSERVED (62B write)
```
- canary 헤더 **length 필드가 디코드 가비지 값(-1503028570)으로 덮임** → 스텁의
  masked store가 canary 객체 헤더를 직접 쓴 것 (mark+klass+length+데이터 30B = 46B)
- integrity map: 갭 바로 다음(`X` 다음 `!`) 정확히 히트, 나머지 138개 필러 전부 온전
- 1MiB/2MiB 심층 오프셋 온전 → **쓰기 범위가 정확히 ≤62B로 국한** (쓰기 폭 실측)
- 셀 1·2 모두 관측·보고 후 JVM이 SIGABRT(exit 134) — 뭉개진 canary 헤더를
  이후 GC/종료 과정이 접촉 → **커럽션의 후속 파괴력까지 실측**
- PrintCompilation: 트리거 시점에 tier4 decode0이 not-entrant 된 것은
  **스텁 실행 후**의 slow-path throw에 의한 deopt (쓰기에는 영향 없음 — §3-3)

## 5. 의의

| 이전 (HANDOFF §6-1 이전) | 이후 |
|---|---|
| Java 레벨 예외(IAE) 관측만 가능, 커럽션 미관측 | **OOB 쓰기 자체를 Java 레벨에서 직접 관측** |
| "62바이트 OOB" = 공개 주장 인용 | **쓰기 폭·위치·내용 실측** (62/63B, dst 끝, 디코드 가비지 패턴) |
| 완화 플래그 = 소스 근거만 | **완화 실효 대조 실험 입증** (셀 1 vs 3) |

→ KISA 회신(§5-탐지/조치), DEFENDER-GUIDE v4에 반영 완료.

## 6. 자산

| 파일 | 내용 |
|---|---|
| `exploit/src/OobCanary.java` | 관측 도구 (gap/segv 모드, 셀프 프로브) |
| `exploit/oobcanary.jar` | 빌드 산출물 |
| `exploit/oob_run.sh` | 매트릭스 러너 (ns 사이클 원상복구 포함) |
| `exploit/results/oob_*.log` | 셀별 전체 로그 (GC log·PrintCompilation 포함) |
| `ops/build_jdk17u.sh` | 셀 5·6용 자체 빌드 스크립트 (공개 jdk17u 태그 2종) |

## 7. 남은 것

- 셀 5·6 (자체 빌드 취약 vs 패치 대조) — 파드 `java4shell-build/jdk-build` 진행 중
  (~2-3h). 완료 시 본 문서 §4 갱신.
- segv 경로(커밋 경계 SIGSEGV)는 미달성 — canary 관측이 결정적이므로 불필요 판단.
- JFR ObjectAllocationSample 기반 탐지 검증은 DEFENDER-GUIDE §3-D 수준으로 충분.
