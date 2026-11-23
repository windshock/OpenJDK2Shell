# 중간 기전 확인 — 결과 (2026-11-23)

계획: `MECH-PLAN.md` · 도구: `MechProbe.java` · 로그: `research/mechanism/out/` · 환경: DFIRtx dev03/dev04 (AMD EPYC-Genoa, avx512 vbmi+bw)

## 요약

| 기전 단계 | 방법 | 판정 |
|---|---|---|
| M1 OOB 쓰기 → 인접 live 객체 헤더 손상 | A (실제 취약 빌드, Unsafe 원시 읽기) | **관측** — 48바이트 연속 [0..47] |
| M2 어느 필드가 손상되나 | A | **관측** — mark(0–7) + narrowKlass(8–11) + length(12–15) + body[0..31] 전부 |
| M3 GC가 손상 객체를 밟음 | A (같은 run 크래시) + B (fastdebug 검증기) | **관측** — A: 동일 서명 크래시 · B: VM이 손상 klass를 값과 함께 지목 |

→ 실험 A가 비워 둔 "기전 미관측" 칸과 CORRECTION-3 C-3("쓰기 폭 실측 아님")을 **직접 측정으로** 메움.

## Method A — 실제 취약 빌드(Temurin 17.0.21+9)에서 헤더 바이트 diff

grooming은 OobCanary와 동일(5리전 갭, dst=3k+1, trigger `A×4k+"=="`). 인접 canary 헤더를
`jdk.internal.misc.Unsafe`로 **원시 읽기**(손상 klass를 역참조하지 않음), trigger 전 pristine과 diff.

```
ARRAY_BYTE_BASE_OFFSET=16  (mark@0·8B  narrowKlass@8·4B  length@12·4B  body@16)

필드      pristine              post
mark      0x1                   0x9aa6699aa6699aa6     ★
klass     0x6838                0x699aa669             ★
length    5242864 (0x4ffff0)    -1503028570            ★ (음수)

바뀐 바이트: n=48, span=[0..47], width=48B
  off 0..7   mark    01 00 00 00 00 00 00 00  →  a6 9a 69 a6 9a 69 a6 9a
  off 8..11  klass   38 68 00 00              →  69 a6 9a 69
  off 12..15 length  f0 ff 4f 00              →  a6 9a 69 a6
  off 16..47 body    aa × 32                  →  (디코드 가비지 0x9aa669… / 9a)
deep-offset (1MiB,2MiB): intact
VERDICT: MECHANISM-OBSERVED (fields=mark klass length +body)
```

판독:
- **64바이트 masked store의 꼬리 48B가 인접 live 객체의 선두를 덮었다.** store 64B 중 16B는 갭 쪽(dst 리전)에,
  48B는 canary 리전 선두에 떨어졌다 → C-2 계산(갭 끝 넘어 접촉)과 정합하며, **폭을 추정이 아니라 실측**(48B 연속)으로 확정.
- 덮인 값은 입력('A'…)의 디코드 가비지 패턴(0x9aa669 주기) — 공격자 데이터이되 **헤더로서는 의미 없는 값**.
- **length가 음수**(-1503028570)로 떨어졌다. 유출에 필요한 "큰 양수 length"가 아니다 → 11/18 부호 제어 실패와 일치,
  이 배치에서 유출로 가는 첫 관문이 막힌다는 메커니즘 증거(승격의 구조적 장애).
- deep-offset 온전 → 손상은 store 발자국(48B)에 국한, 광역 아님.

**M3도 같은 run에서 관측:** 관측 직후 JVM이 `G1CMTask::process_grey_task_entry` SIGSEGV(exit, hs_err_pid31)로 사망.
40-episode 실험의 크래시 6건과 **동일 프레임**. 즉 "헤더 손상 → GC가 그 객체를 밟음 → 크래시"가 한 run에서 연결 관측됐다.

## Method B — fastdebug + VerifyBeforeGC/AfterGC (VM이 손상 klass를 지목)

jdk-17.0.21.0.3-ga를 `--with-debug-level=fastdebug`로 빌드(dev04)해 `-XX:+UnlockDiagnosticVMOptions
-XX:+VerifyBeforeGC -XX:+VerifyAfterGC -Xlog:gc+verify`로 실행. 매 GC마다 힙 검증 패스가 돈다
(`Verifying Before/After GC` GC(0)..GC(48)). trigger 후 강제 GC에서 **VM 자신의 어서션이 손상 klass를 잡았다**:

```
# Internal Error (hotspot/share/oops/compressedOops.inline.hpp:135)
#  assert(check_alignment(result)) failed: address not aligned: 0x00007f4c3c9aa669
# Problematic frame:
#  V CompressedKlassPointers::decode_not_null(unsigned int, unsigned char*)+0x97
# fastdebug build 17.0.21.0.3-internal
```

판독:
- VM이 객체의 **compressed klass 포인터를 디코드**하다 `0x…9aa669`를 얻었다 — Method A가 측정한 손상 klass
  값(post klass=0x699aa669 → 디코드 → `…9aa669`)과 **정확히 일치**. fastdebug의 `check_alignment` 어서션이
  그 값을 잡고 코드 위치(`decode_not_null`, `compressedOops.inline.hpp:135`)까지 지목했다.
- 제품 빌드의 무작위 SIGSEGV 대신, **VM이 손상 klass를 값·위치와 함께 결정적으로 지목**한 것 = "GC가 손상
  객체를 밟는다"의 VM-authored 증거. M2(klass 손상)·M3(그 klass를 따라가다 치명)을 한 번에 확정.
- 로그: `research/mechanism/out/build-b.log`.

## 결론

세 단계가 **독립 두 방법으로 교차 확인**됐다: OOB 64B store의 꼬리 48B가 인접 live 객체 헤더
(mark+klass+length+body)를 디코드 가비지로 덮고(M1·M2, Method A 바이트 실측), GC가 그 객체의 klass를
따라가다 사망한다(M3 — Method A 동일-서명 크래시 + Method B fastdebug 어서션이 손상 klass 값 지목).
실험 A의 인과(취약 6/10 vs 대조 0/10)에 **기전**이 붙었다. length는 이 배치·이 입력에서 음수였고, 우리가
시도한 입력 문자 축으로는 바꾸지 못했다(아래 절). 유출 가능/불가능은 우리 손으로 판정하지 못했다(UNESTABLISHED).

## 유출 "불가능 아님" 검토 — 정직한 결과 (입력 의존성 실험)

"length가 음수 → 유출 불가능"이 아님을 **외부 보고가 아니라 코드+동적 관측으로** 세우려 했다.
가설: length 필드를 덮는 값이 공격자 입력에 좌우되면 "항상 음수라 불가능"은 깨진다.

**실험 (vary-a/b/q):** 트리거 fill 문자를 A·B·Q로 바꿔 각각 grooming→trigger, length 필드 값 비교.

| 입력 | length 필드 MSB | 판정 |
|---|---|---|
| A | 0xa6 (음수) | — |
| B | 0xa6 (음수) | 동일 |
| Q | 0xa6 (음수) | 동일 |

→ **fill 문자를 바꿔도 length 값이 안 바뀐다. 가설 기각.**

**왜 (코드):** 스텁 테일은 레지스터를 `'a'`(0x61)로 채운 뒤 **유효 입력 레인만** 실제 바이트로 덮는다
(`input_initial_valid_b64` ← 0x61 broadcast, `evmovdqub(..., input_mask, source)`). 짧은 패딩 테일은
유효 레인이 몇 개뿐 → 64B store의 **뒤쪽**(length 필드가 떨어지는 offset 28~31)은 0x61-fill 디코드 =
고정 패턴(0xa6 9a 69…). 공격자 fill 문자는 store **선두**(mark word, offset 0–7)만 바꾼다.

**결론 (정직):**
- 우리가 시도한 **쉬운 축(입력 문자)은 length 필드에 닿지 못했다** → 동적 관측으로 "불가능 아님"을 세우지 못했다.
- length에 닿으려면 **정렬 제어**(dst 크기·grooming로 store 겹침을 옮겨 유효 레인 바이트를 offset 12~15에 올림)가
  필요하다. 이는 조준=승격이므로 **하지 않았다**(범위 밖).
- 따라서 유출은 **우리 손으로 입증도 반증도 안 됨(UNESTABLISHED)**. "불가능"은 여전히 증명되지 않았다:
  (a) 코드상 손상 값은 **위치 의존**이고 어떤 바이트가 target offset에 오는지는 공격자가 영향 주는 정렬로 정해지므로
  "모든 공격 전략에서 음수 강제"는 성립하지 않는다; (b) 외부 독립 재현 보고(REPORTED); (c) 벤더 기밀성 영향 High.
  단 이 세 근거는 코드·외부이고, **우리 동적 데이터만으로는 세우지 못했다**(fill 축 무효). 공개 분석의
  "per-target grooming이 관문"과 정합.

## 범위 (불변)
값·부호 **제어**, 읽기/쓰기 primitive, 정보 유출, 코드 실행은 하지 않았다. 본 결과는 "손상이 어디에
어떻게 났고 GC가 그걸 밟는다"의 **관측**이며, 승격 가능성을 입증하지 않는다 (오히려 length 음수는 유출 장애를 재확인).
