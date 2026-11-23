# 3차 정오표 — 마스크 해석·OOB 바이트 수·URL 디코더·TLAB 일반화·외부 재현 현황 (2026-11-23)

근거 출처: Issue #1 댓글 2 (2026-11-22, "공개자료 재검토"), 댓글 3 (2026-11-22, "RCE Chain 가능성 심층 분석").
계획 위치: `RESEARCH-PLAN-2026-11-23.md` 트랙 C (C-1~C-9).
원칙: 원시 로그(`exploit/results/`)는 수정하지 않는다. 문서 본문은 정정하고, **정정 전 문장은 아래에 원문 그대로 보존**한다.

---

## 0. 이번 정정에서 직접 재확인한 소스

`openjdk/jdk17u` 태그 `jdk-17.0.21-ga`, `src/hotspot/cpu/x86/stubGenerator_x86_64.cpp`
`generate_base64_decodeBlock()` L_finalBit~L_padding (원문 6177~6281행, 2026-11-23 raw 조회):

```
L_finalBit:                                  // 1..63 바이트 남음
  rax = bzhiq(-1, length)                    // 입력 마스크
  output_size = (length >> 2) * 3
  if src[length-1] == '=' → L_padding:       // ← 문자 비교. URL/표준 모드 구분 없음
      output_size -= 1; rax >>= 1
      if src[length-2] == '=': output_size -= 1; rax >>= 1
L_donePadding:
  output_mask = bzhiq(-1, output_size)       // ← output_size 하위 8비트가 index
  (입력은 'a'(0x61)로 채운 벡터에 rax 마스크로 병합 → 에러 검사 → 디코드)
  evmovdqub [dest + dp], k1=output_mask      // masked store
  dest += output_size
```

남은 바이트 r < 4이고 패드 p개면 `output_size = 0 - p` → 하위 8비트 255(p=1) / 254(p=2).
Intel SDM BZHI: index(bits 7:0) ≥ 64(operand size)면 원본을 보존 → `output_mask = all-ones`
→ **64바이트 store가 현재 출력 위치 dp에서 시작**한다.

## 1. 정정 항목

### C-1. BZHI 해석 (mod 64 → 하위 8비트·≥64 원본 보존)

| 위치 | 정정 전 원문 |
|---|---|
| `OOB-OBSERVATION-2026-11-18.md` §1 | "이후 `bzhiq(output_mask, -1, output_size)`는 index를 **mod 64**로 해석 → `output_mask = (64-p) 비트` (p=1 → 63B, p=2 → **62B** — 공개 주장 크기와 일치)." / "masked store가 dst 데이터 끝(`dp`)에서 쓰기를 시작 → **패드 수만큼의 OOB 쓰기**." |
| `KISA-REPLY-2026-11-20.md` §4 | "`bzhiq`의 mod-64 해석으로 출력 마스크가 62/63비트로 부풀어 masked store가 dst 끝에서 62/63바이트 쓰기 (11/18 스텁 소스 분석 확정)" |
| `exploit/src/OobCanary.java` 헤더 주석 | "`bzhiq(output_mask, -1, -p) → mask = 64-p bits (p=1: 63B, p=2: 62B write)`" |

**정정:** 마스크는 all-ones, 명령어 저장 폭은 **항상 64바이트**. "11/18 스텁 소스 분석 확정"이라는 표현은 철회한다 (BZHI 의미를 잘못 적용했음).

### C-2. 바이트 수 4항목 분리 + pad1/pad2 라벨 반전

`decodedOutLength` = `3*((len+3)/4) - paddings`, store 시작 = dp(마지막 64바이트 블록까지 디코드한 출력 길이).

| 항목 | 공개 사례 `A×64+"="` (65자) | 우리 pad1 `A×4k+"="` | 우리 pad2 `A×4k+"=="` |
|---|---|---|---|
| ① 명령어 저장 폭 | 64B | 64B | 64B |
| ② 계산된 목적지 크기 | 50 | 3k+2 | 3k+1 |
| store 시작(dp) | 48 | 3k | 3k |
| ③ 논리 경계 초과량 = dp+64−② | **62B** | **62B** | **63B** |
| ④ 실제 관측 변경 범위 | (외부: 4096B 배열 내부 표시값) | canary 헤더 length 필드 손상 (아래 C-3) | 동일 |

**기존 라벨은 반대였다** (pad1=63B, pad2=62B로 기재). 정정 전 원문:
- `OOB-OBSERVATION` §4 표: "셀 1 … pad2 (62B)", "셀 2 … pad1 (63B)", "셀 5 … OOB-OBSERVED (62B)"
- `OobCanary.java` `buildTrigger` 주석: "pad1 … → 63B write", "pad2 … → 62B write"
- `OobCanary.java` 판정: `"VERDICT: OOB-OBSERVED (" + ("pad1".equals(trig) ? "63B" : "62B") + " write)"`
- `E2E-EXPLOIT-SUITE.md`: "62B OOB → 캐시 유지 f71 헤더 직격", "62B masked store", "스텁 final-bit r=2·패드 2 → 62B OOB 쓰기"
- `ESCALATION-STATUS` §9: "OOB 62B → 캐시 배열 헤더 파손 지속"
- `WAS-LOG-CRASH-ANALYSIS` §2-3 리전표: "★ 62B OOB 쓰기가 때린 다음 필러의 헤더"
- `DEFENDER-GUIDE` §부록: "canary 헤더 length 필드 뭉개짐(62/63B 스토어)"
- `HANDOFF` §6: "62/63B 관측"

우리 트리거는 대부분 pad2(`==`)이므로 **논리 경계 초과량은 63B**가 맞다.

**캐너리 레시피 재계산 (k=1747616, 리전 1MiB, 배열 헤더 16B):** store = [obj+16+3k, +64) = [obj+5242864, obj+5242928).
갭 끝 5242880 → 다음 리전(canary) **선두 48B** 접촉 (헤더 16B + 데이터 32B). 정정 전 원문: "쓰기 [obj+16+3k, +62) = [5242864, 5242926) vs gap end 5242880 → 46B canary hit".
pad1/pad2 모두 store 위치가 같으므로 canary 접촉 범위도 같다 (셀 1·2 결과가 동일했던 것과 정합).

**기록된 로그는 수정하지 않는다:** `exploit/results/oob_*.log`, `jdk17u-build-and-canary.log` 등의 `VERDICT: OOB-OBSERVED (62B write)` 문자열은 당시 도구가 출력한 원문이다. 판정(헤더 손상 관측)은 유효하고, 괄호 안 바이트 수만 C-2 표로 읽는다. 도구 판정 문자열은 이번 정정부터 `OOB-OBSERVED (header corrupted; logical overrun=NB)`로 바꾼다. `exploit/oobcanary.jar`는 다시 빌드하기 전까지 옛 문자열을 출력한다.

### C-3. "쓰기 폭 실측" 주장 철회

정정 전 원문:
- `OOB-OBSERVATION` §4: "1MiB/2MiB 심층 오프셋 온전 → **쓰기 범위가 정확히 ≤62B로 국한** (쓰기 폭 실측)"
- `OOB-OBSERVATION` §5 표: "**쓰기 폭·위치·내용 실측** (62/63B, dst 끝, 디코드 가비지 패턴)"
- `WAS-LOG-CRASH-ANALYSIS` §4: "1MiB/2MiB 심층 오프셋 온전 → **파손이 62~63B로 국한** — 광역 커럽션 아님."

**정정:** 멀리 떨어진 두 오프셋이 온전하다는 사실은 쓰기 폭의 상한을 확정하지 못한다. 실측된 것은 **canary 헤더 length 필드 손상(위치)**과 **값이 디코드 가비지 패턴이라는 것(내용)**이다. 폭은 소스 계산값(C-2)이고 `UNESTABLISHED (실측 아님)`으로 표기한다.

### C-4. EXTERNAL-REVIEW "완전 일치" 판정

정정 전 원문 (§3 표): "근본원리 (bzhi full-mask, 62-63B) | … | 스텁 역어셈 분석 동일 (p=2 → 62B 포함) | ✅ 완전 일치"
**정정:** 원인 위치(L_finalBit 언더플로)는 일치했다. 마스크 해석은 외부 문서("all 64 lanes")가 옳고 우리 설명(mod 64)이 틀렸다 → ⚠️ 부분 일치. 우리 측 정정 대상이었다.

### C-5. URL 디코더 / JWT 제외 근거 철회

정정 전 원문:
- `EXTERNAL-REVIEW` §3: "URL 모드는 `=`를 illegal로 처리 → masked store 미실행(스텁 분석). **JWT 무패딩은 트리거 자체가 안 됨** … 우리 판정 유지"
- `E2E-EXPLOIT-SUITE.md` 체인 4-한계: "JWT/OIDC 파싱 (Nimbus) | base64**url** — JDK URL 디코더는 `=`를 illegal로 처리 → 에러 경로 → 스텁 masked store 미실행 → **트리거 불가**"
- `HANDOFF` §6: "base64url은 패딩 미허용"

**정정 (근거 2개):**
1. Java 레벨: 패치 직전 `Base64.java`(@529f066)에 `fromBase64URL['='] = -2`. URL 디코더도 같은 `Decoder` 클래스이고, API 문서상 올바른 개수의 패딩을 허용한다.
2. 스텁 레벨 (§0, 이번 재확인): 패딩 제거는 `cmpb(src[..], '=')` **문자 비교**이고 URL/표준 lookup과 무관하다. 패드 문자는 입력 마스크에서 빠지고 `'a'`로 채워지므로 에러 검사에도 걸리지 않는다. → **URL 모드에서도 같은 masked store가 실행된다.**

남는 것: 무패딩 JWT 세그먼트는 트리거 조건(끝의 `=`)이 없다. 다만 **라이브러리가 패딩을 거부·정규화하는지, 입력을 그대로 넘기는지는 제품별로 검증해야 한다** (계획 E-2). "모든 JWT 경로 취약"도 주장하지 않는다.

### C-6. TLAB·humongous 결론을 랩 조건으로 한정

정정 전 원문:
- `ESCALATION-STATUS` §7-2: "**결론: Basic auth/JWT/SAML 헤더류(작은 dst) 표면은 본 CVE의 승격이 구조적으로 불가.**"
- §7-3 제목: "승격 가능 유일 경로 재확인"
- §8 표: "HTTP Basic/JWT/SAML (헤더, ≤8KB) | ≤6KB (TLAB) | 소거됨 (할당 시 헤더 재기록) | **불가 (DoS만)**"
- `EXTERNAL-REVIEW` §4-2: "작은 dst 표면(Basic auth/JWT)의 승격이 구조적으로 불가하다는 확정"
- `E2E-EXPLOIT-SUITE.md` 체인 4-한계: "HTTP Basic | … 헤더 크기 한계(수십 KB) → 512KB+ humongous 불가", "→ Keycloak은 본 CVE의 현실적 표적이 아님"

**정정:** 관측 사실은 "Spring Boot/Tomcat 랩, G1, 힙 1.25GB, 이 앱의 할당 패턴에서 작은 dst 150발 → 헤더 파손 0, JVM 생존"이다. TLAB 전방 쓰기 소거는 **이 조건에서 관측과 맞는 설명 가설**일 뿐이다. 다음 경우는 다루지 못했다: dst가 TLAB 잔여보다 커서 TLAB 밖에 할당되는 경우, TLAB 끝 경계, 다른 스레드나 다른 GC. Calif 공개 설명도 할당 경로가 크기와 TLAB 잔여 공간에 따라 달라진다고 한다. → "구조적 불가"와 "유일 경로"를 철회하고 **"우리 랩 조건에서 음성"**으로 표기한다. Hadrian은 HTTP Basic 경로 크래시를, Red Hat/Keycloak 공지는 pre-auth 영향을 보고했으므로(REPORTED) "Keycloak 부적합" 판정도 철회한다.

### C-7. 외부 재현 현황 ("Calif 단독"·"유일" 표현)

정정 전 원문:
- `EXTERNAL-REVIEW` §6: "커뮤니티 합의: **overflow·DoS 확정, RCE는 Calif 주장 단독(비공개, 미독립재현)**"
- 같은 곳: "…메커니즘 근거(…)를 제공한 유일한 공개 문서"
- §3 표: "서명 상세는 우리가 유일", "우리만 문서화", "우리 유일 분석"
- §5 표: "우리가 유일한 상세 공개 실측 중 하나"

**정정:** 아래 표로 대체한다. "유일"류 표현은 검증할 수 없으므로 삭제한다.

| 주체 | 게시일 / 표시 갱신일 / 우리 확인일 | 환경 | 보고 성과 | 공개 증거 | 우리 독립 검증 |
|---|---|---|---|---|---|
| Calif | 11/17 / — / 11/22(댓글 3 경유) | Elasticsearch(post-auth), Jenkins·Keycloak(pre-auth) | RCE PoC를 Oracle에 제공 | 트리거 PoC·데모 공개, 앱 체인 보류 | 아니오 (REPORTED) |
| Hadrian | 11/17 / 11/19 15:15 CET / 11/22 | Temurin 17.0.21+9, Spring Security/Tomcat Basic; 별도 본문 디코딩 랩; Jenkins(약 11/21) | Basic 경로 pre-auth 크래시, 별도 랩 pre-auth 코드 실행 + 이후 정상 처리 지속, Jenkins pre-auth RCE | 서술·메모리 관측 결과 | 아니오 (REPORTED). Basic 크래시와 본문 랩 RCE는 서로 다른 경로이므로 합산하지 않음 |
| VulnCheck | 11/17 / — / 11/22 | Ice Lake | 11/17 18:00 EST부터 상용 RCE 익스플로잇 제공 공지 | 비공개 | 아니오 |
| Akamai | 11/19 / — / 11/22 | 패치 분석 | 원인·패치 분석, 코드 실행 경로 추론 | 분석 공개 | 자체 RCE 재현으로 승격하지 않음 |
| JFrog | 11/17, 이후 갱신 / — / 11/22 | — | Calif 체인 해설·조건 분석 | 공개 | 독립 재현 건수에 산입하지 않음 |
| Deep Kondah | 11/22 / — / 11/22 | 디버거 | BZHI·64B/62B 해설, 4096B 배열 내부 표시값 관측 (배열 물리 경계 밖 손상의 증거는 아님) | 공개 | 원리는 §0 소스로 교차 확인 |

정확한 서술: **Calif 외에도 자체 재현 보고와 상용 제공 공지가 있다. 이 저장소는 공개된 완성 체인이나 원시 증적으로 이들을 독립 검증하지 못했다.**

### C-8. Temurin 수정 빌드

정정 전 원문 (`KISA-REPLY` §2): "Temurin/Microsoft/RHEL pending"
**정정:** Adoptium 11/18 공지 기준 수정 빌드는 17.0.21.1+2 / 21.0.13.1+2 / 25.0.5.1+2 / 27.0.1.1+4이다. Docker Hub에 `eclipse-temurin:17.0.21.1_2-jdk`, `-jdk-jammy`가 11/20 게시된 것을 11/23 확인했다. 플랫폼·채널별 배포 상태는 adoptium/temurin#326에서 개별 확인하며, 모든 플랫폼에서 동시에 배포가 끝났다고 일반화하지 않는다. Microsoft/RHEL 상태는 이번 정정에서 재확인하지 않았다 (11/18 기록 유지, 확인일 명시).

### C-9. 크래시 프레임 ≠ 원인 컴포넌트

점검 결과: `WAS-LOG-CRASH-ANALYSIS`의 "G1 CM이 여기서 사망" 등 G1 프레임 서술은 **같은 run의 캐너리 손상 관측과 함께** 쓰였다. 그래서 단독 인과 주장은 아니다. 다만 원칙을 명시하는 주석을 추가한다: G1/GC 프레임 크래시만으로 원인 컴포넌트를 확정하지 않는다. Adoptium support#1480(6월, Parallel GC 운영 크래시)은 "운영 결함 선행 기록"으로만 인용하고 공격 악용 사례로 분류하지 않는다.

### C-10. CPU 조건 — "AVX-512VL+BW = 기본 취약" 과잉 (트랙 D 중 발견)

정정 전 원문:
- `KISA-REPLY` §3: "⇒ **AVX-512VL+BW CPU(AMD EPYC Genoa 등)에서는 기본 활성 = 기본 취약**"
- `DEFENDER-GUIDE` §4-E: "에르고노믹스 동적 활성 → **AVX-512 서버는 기본 취약**"
- `OPS-SHARING` §5: "**AVX-512VL+BW CPU**에서 기본 활성 (에르고노믹스) — 최신 서버일수록 기본 취약"
- `DEFENDER-GUIDE` §1: "(hotspot/compiler, 8·11·17·21·25·27 전 라인)"

**정정:** `vm_version_x86.cpp`는 VL+BW에서 `UseBASE64Intrinsics`를 켠다. 그러나 `stubGenerator_x86_64.cpp`의
취약 벡터 경로(L_process64/L_finalBit)는 `supports_avx512_vbmi() && supports_avx512bw()`일 때만 생성된다
(jdk-17.0.21-ga 재확인). VBMI가 없으면 같은 스텁이 brute-force 경로만 갖는다. → 기본 취약 조건은 **VBMI+BW**이다.
같은 블록의 `cmpl(length, 128); jcc(lessEqual, L_bruteForce)`가 JDK 17 최소 트리거 129자의 소스 근거다.
표준 OpenJDK 8/11은 무영향(8 Performance Pack 제외)이며, 이는 KISA-REPLY §2에 이미 기록돼 있었다. DEFENDER-GUIDE §1만 과잉 표기였다.

## 2. 정정이 바꾸지 않는 것

- OOB 쓰기 존재, 취약 ON=손상 / 완화 OFF=CLEAN / 수정 빌드=CLEAN 대조 결과 (판정 자체는 유효)
- 11/18 E2E·HBase·Spring 크래시 관측 (원시 로그 그대로)
- CORRECTION-1/2의 C2 JIT 버그 분류
