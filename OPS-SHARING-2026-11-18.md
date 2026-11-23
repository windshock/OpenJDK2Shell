# 관제 공유 자료 — CVE-2026-114938 (Java4Shell) E2E 실증 + 와이어 시그니처

> **⚠ 2026-11-23 정정 반영** — `CORRECTION-3.md` 참조.


작성: 2026-11-18 · 대상: 관제/SOC · 용도: 침해사고 대응 훈련·탐지룰 검증용 증거 세트

## 1. 요약

DFIRtx dev 클러스터(AMD EPYC Genoa, AVX-512)에서 **원격 무인증 E2E 실증 완료**:
공격자가 HTTP만으로 희생 JVM(17.0.8, 기본 설정 = intrinsic ON)의 힙을 조형하고
단 1회의 트리거 요청으로 JVM을 사망시켰다 (SIGSEGV, hs_err 생성, 5/5회 재현).
완화 플래그(`-XX:-UseBASE64Intrinsics`) 적용 victim은 동일 공격 전량 생존 (대조 입증).

## 2. 공개용 pcap 세트 (exploit/results/pcap/)

| 파일 | 크기 | 내용 |
|---|---|---|
| `j4s-e2e-vuln-attacker-full.pcap.gz` | 0.83MB | **공격 전체 13초** (필→사이클→드롭→트리거→사망 RST) — 1차 공유 권장 |
| `j4s-e2e-vuln-victim-flood.pcap.gz` | 0.81MB | victim 수신 관점, 필+사이클 구간 |
| `j4s-e2e-vuln-soc-r1.pcap` | 7.8MB | snaplen 192 (헤더만), run 1 — 와이어 흐름 파악용 |

wireshark/tshark 예: `tshark -r j4s-e2e-vuln-attacker-full.pcap.gz -Y "http.request"`

## 3. 와이어 시그니처 (탐지룰 후보)

공격은 "평범한 HTTP POST"지만 3단계 트래픽 패턴이 특징적:

| 단계 | 시그니처 | 예 (attacker-full pcap 타임스탬프) |
|---|---|---|
| ① 힙 조형 (필) | `POST /decode?id=f<N>` × 140회, `Content-Length: 6990482`, 본문 = `0x41` 연속 + `AB` 테일 | 09:56:43~ |
| ② 갭 만들기 | `DELETE /decode?id=f70` 1회 + `POST /pump?mb=64` 반복 | — |
| ③ 트리거 | `POST /decode?id=trig<N>`, **`Content-Length: 6990466`**, 본문 = `0x41` 연속 + **`==` 테일** | **09:56:56.408** |
| ④ 사망 | 트리거 직후 신규 연결 SYN에 대한 **RST(win 0)** — 프로세스 사망 | **09:56:56.469** |

범용 룰 관점 (앱 일반화):
1. **동일 엔드포인트로 6.99MB급 POST 반복(≈140회, 분당 수십 회) → 소수의 DELETE →
   즉시 대형 POST 1회 → 서버 프로세스 사망(RST/세션 드롭)** — 힙 조형+트리거 서명
2. 요청 본문이 **`0x41`('A')로 ~100% 채워진 7MB급 POST** — 유효 페이로드로 위장된
   힙 주입. 본문 엔트로피·반복 바이트 비율로 탐지 가능
3. **JVM 급사 후속 징후**: `hs_err_pid*.log` 생성 (Problematic frame =
   `OopOopIterateDispatch<G1CMOopClosure>::oop_oop_iterate` — G1 동시 마킹이
   뭉개진 객체 헤더 접촉), SIGSEGV/SIGABRT, 코어 덤프
4. 완화 확인: `-XX:-UseBASE64Intrinsics` 적용 시 동일 트래픽에 정상 400 응답 유지
   (대조 pcap은 별도 요청 시 제공 가능)

## 4. E2E 매트릭스 (7회 실행 전체)

| run | 셀 | 결과 |
|---|---|---|
| v1 | vuln | SURVIVED (본문 가비지 체런 문제 → 도구 개선) |
| v2 | vuln | 컴파일 오류 → decode(ByteBuffer) 경로 수정 |
| v3 | vuln | **PWNED** (트리거 1회, SIGSEGV in G1 CM) |
| B | mitig (`-XX:-UseBASE64Intrinsics`) | **SURVIVED** — 완화 실효 입증 |
| 4~5 | vuln | **PWNED ×2** (재현성; SEGV_ACCERR / SI_KERNEL 변형) |
| 6~7 | vuln + pcap | **PWNED ×2** + 관제용 pcap 확보 |

판정 스크립트 exit 42 = PWNED. 공격 원장: `ops/e2e_java4shell_attacker.sh`,
victim 서비스: `exploit/src/Java4ShellE2EVictim.java` (업로드 디코드 표면 모델),
러너: `exploit/e2e_java4shell.sh vuln|mitig [pcap]`.

## 5. 취약 조건 (관제 자산 선별 기준)

- Java **17.0.6~17.0.21.0.x** (decode intrinsic 도입 17.0.6 — 코드 아키폴로지 검증 완료)
- **AVX-512 VBMI+BW CPU**(Ice Lake+/Zen4+)에서 기본 취약 — VL+BW에서 intrinsic이 켜지지만 취약 벡터 경로는 VBMI 필요 (11/23 정정)
- 완화: `-XX:-UseBASE64Intrinsics` (실효 대조 입증) / 근본: **17.0.21.1** 업그레이드
- 자체 빌드 대조 (11/18): 17.0.21.0.3=OOB 관측 / **17.0.21.1=CLEAN** (동일 플래그,
  패치 8393212만의 차이) — 패치 효과 소스 레벨 입증
- 상세: `OOB-OBSERVATION-2026-11-18.md` · `DEFENDER-GUIDE.md` v4 · `KISA-REPLY-2026-11-20.md`
