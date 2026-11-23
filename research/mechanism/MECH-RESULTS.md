# 중간 기전 확인 — 결과 (2026-11-23)

계획: `MECH-PLAN.md` · 도구: `MechProbe.java` · 로그: `research/mechanism/out/` · 환경: DFIRtx dev03/dev04 (AMD EPYC-Genoa, avx512 vbmi+bw)

## 요약

| 기전 단계 | 방법 | 판정 |
|---|---|---|
| M1 OOB 쓰기 → 인접 live 객체 헤더 손상 | A (실제 취약 빌드, Unsafe 원시 읽기) | **관측** — 48바이트 연속 [0..47] |
| M2 어느 필드가 손상되나 | A | **관측** — mark(0–7) + narrowKlass(8–11) + length(12–15) + body[0..31] 전부 |
| M3 GC가 손상 객체를 밟음 | A (같은 run 크래시) + B (fastdebug 검증기) | A: **관측** (동일 서명) · B: 빌드 중 |

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

## Method B — fastdebug + VerifyBeforeGC/AfterGC (빌드 중)

jdk-17.0.21.0.3-ga를 `--with-debug-level=fastdebug`로 빌드해 `-XX:+VerifyBeforeGC/+VerifyAfterGC`로 실행.
힙 검증기가 손상 객체를 **주소·필드와 함께 지목**하는 VM-authored 증거를 추가 예정. (dev04, ~2h)

## 범위 (불변)
값·부호 **제어**, 읽기/쓰기 primitive, 정보 유출, 코드 실행은 하지 않았다. 본 결과는 "손상이 어디에
어떻게 났고 GC가 그걸 밟는다"의 **관측**이며, 승격 가능성을 입증하지 않는다 (오히려 length 음수는 유출 장애를 재확인).
