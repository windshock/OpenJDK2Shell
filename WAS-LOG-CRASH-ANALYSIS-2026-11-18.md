# WAS 로그·크래시 덤프 패턴 분석 — CVE-2026-114938 (Java4Shell)

> **⚠ 2026-11-23 정정 반영** — `CORRECTION-3.md` 참조 (정정 전 문장은 그 문서에 원문 보존).


작성: 2026-11-18 · 대상: 관제/SOC/IR · 목적: **네트워크 pcap 없이도**
WAS(애플리케이션) 로그 + 크래시 아티팩트만으로 침해를 식별할 수 있음을 실증.

근거: E2E 실증 7회 중 PWNED 5회의 victim 로그 + hs_err + (신규 수집) full hs_err·GC 로그.
모든 관측은 DFIRtx dev (EPYC Genoa, temurin 17.0.8, G1, 1g 힙) 기준.

---

## 1. WAS 애플리케이션 로그 패턴 (공격 시퀀스)

victim(`Java4ShellE2EVictim` — 업로드 디코드 캐시 서비스 모델)의 stdout:
`results/e2e_j4s_victim_vuln.log` vs `e2e_j4s_victim_mitig.log`

### 1-1. 취약 victim의 마지막 로그 시퀀스 (vuln — 5회 전부 동일)

```
[victim] decode id=f137 in=6990482 out=5242861 cached=138
[victim] decode id=f138 in=6990482 out=5242861 cached=139
[victim] decode id=f139 in=6990482 out=5242861 cached=140   ← 대형 decode 성공 폭풍의 끝
[victim] drop id=f70 was=5242861                            ← 캐시 항목 1개 삭제 (갭 생성)
[victim] decode id=trig1 in=6990466 REJECTED: Input byte
         array has wrong 4-byte ending unit                 ← ★ 최종 로그 라인
(이후 로그 영구 단절 — shutdown 로그 없음, 프로세스 사망)
```

### 1-2. 완화 victim (mitig — 대조)

```
[victim] decode id=trig1 ... REJECTED: ...
[victim] decode id=trig2 ... REJECTED: ...                  ← REJECTED 5건
[victim] decode id=trig3 ... REJECTED: ...
[victim] decode id=trig4 ... REJECTED: ...
[victim] decode id=trig5 ... REJECTED: ...                  ← 로그 계속, 프로세스 생존
```

### 1-3. 앱 로그만의 탐지 규칙 (pcap 불필요)

| # | 조건 (정규화) | 의미 |
|---|---|---|
| A1 | 동일 엔드포인트의 초대형 decode/parse 성공 로그 반복 (~6.99MB in, ~5.24MB out) 100회+/분 | 힙 조형 (필러 주입) |
| A2 | 캐시/세션 삭제(삭제 로그) 직후 ≤ 수십 초 내 대형 입력 **거절(REJECTED/400)** 1건 | 트리거 (쓰기는 이미 발생) |
| A3 | **A2가 해당 서비스의 최종 로그 라인** + 이후 로그 부재 + 프로세스 부재/재시작 | 크래시 확정 |
| A4 | 같은 초대형 입력 REJECTED가 **연속 다수**인데 프로세스 생존 | 완화 적용 환경 (정상 동작) |

**핵심 통찰**: 트리거 요청은 앱 로그상 **정상 거절(IAE→400)** 로만 보인다.
OOB 쓰기는 **거절 응답을 반환하기 전에 이미 발생**했으므로, "거절 1건 후 로그 단절"
이 조합이야말로 사후(포렌식) 식별의 1차 단서. 예외 스택트레이스도 남지 않는다
(IAE는 정상 흐름의 일부이고, 크래시는 그 직후 GC 스레드에서 일어나 앱 로그와
시간적으로만 연결됨).

## 2. JVM 크래시 덤프 (hs_err) 패턴

### 2-1. 공통 서명 (PWNED 5회 모두 일치)

```
#  SIGSEGV (0xb) at pc=0x..., pid=..., tid=...
# V  [libjvm.so+0x6dd476/6dd490]  void OopOopIterateDispatch<G1CMOopClosure>::Table
#    ::oop_oop_iterate<InstanceKlass, narrowOop>(G1CMOopClosure*, oopDesc*, Klass*)
Current thread: ConcurrentGCThread "G1 Conc#0"          ← ★ 앱 스레드 아님 (GC 스레드)
siginfo: si_code: 2 (SEGV_ACCERR), si_addr: 0x...a671   ← 변형: 128 (SI_KERNEL), addr 0x0
elapsed time: ~14초 (공격 개시→사망)
Core dump will be written → abort() → 프로세스 exit 코드 134 (SIGABRT)
```

| 필드 | 값 | IR 판독 포인트 |
|---|---|---|
| Signal | SIGSEGV(11) | 메모리 접근 위반 — 힙 커럽션 계열 |
| Problematic frame | `V [libjvm.so]` G1CM oop_oop_iterate | **동시 마킹이 파손 객체 헤더를 순회** — 앱 코드 프레임 아님 |
| Current thread | `"G1 Conc#0"` | 크래시 시점에 요청 처리 스레드는 살아있어도 GC가 먼저 사망 |
| si_code | SEGV_ACCERR(2) / SI_KERNEL(128) — 변이 관측 | 커럽션 양상이 런마다 다름 (재현성 있으나 주소·코드 비결정론) |
| Command Line | G1 힙 옵션 (없으면 JVM 기본값) | 리전 크기·히프 크기별 서명 차이 확인용 |
| exit | 128+6 = **134** | systemd/journald: `Main process exited, code=dumped, status=6/ABRT` 계열 |

### 2-2. IR 키워드 조합 (감별 기준)

`hs_err_pid*.log` + 다음 3요소 동시 존재 → 본 CVE(CVE-2026-114938) 의심:

1. `G1CMOopClosure` 또는 `oop_oop_iterate` (G1 동시 마킹 크래시)
2. SIGSEGV in `"G1 Conc#N"` thread (앱 스레드가 아님)
3. 직전 앱 로그에 초대형 Base64/디코드 처리 기록 (§1-1 A2)

감별: 일반 힙 부족(OOM)은 hs_err 아님 → GC 알고리즘 크래시는 다른 원인도 가능하므로
3요소 조합 + 호스트 CPU가 AVX-512VL+BW(예: EPYC Genoa/4세대 이후, Xeon SP 4세대+)인지 확인.

### 2-3. hs_err Heap Regions = 공격 지형의 화석 (11/18 신규 발견, `results/crash-vuln/`)

full hs_err(194KB)의 Heap Regions 테이블을 humongous 블록별로 요약하면
**공격이 만든 힙 지형이 그대로 보존**된다:

```
블록 길이 분포: {9리전×1, 5리전×139, 4리전(99%)×1}  F(free)=0
```

| 화석 | 해석 |
|---|---|
| 9리전 × 1 | victim 서비스의 8MB 재사용 스크래치 버퍼 (이 도구 고유) |
| **5리전 × 139** | **공격자가 심은 캐시 페이로드 140개 중 139개** — 캐시 유지 디코드 결과 (공격자가 DELETE하지 않은 것들) |
| **4리전+99% 꼬리 × 1** | **트리거 dst** — 마지막 트리거 decode의 5242849B 할당. 리전 359~363: |

```
| 359|HS| 100%| ← dst 시작
| 360|HC| 100%|
| 361|HC| 100%|
| 362|HC| 100%|
| 363|HC|  99%| top=0x...d6bffff8  ← dst 꼬리: 객체 끝이 리전 끝 8B 전
| 364|HS| 100%| ← ★ OOB 쓰기(64B store, 논리 초과 63B)가 때린 다음 필러의 헤더 (G1 CM이 여기서 사망)
| 365~368|HC|   ←   (파손된 5리전 객체의 나머지)
```

**IR 시사점**: 크래시 덤프의 리전 테이블만으로 ① 힙이 humongous로 완전 점유(F=0),
② 5리전 humongous가 100개+ (대량 대형 캐시/업로드 — §1 A1의 힙 측 물증),
③ **4.x리전+99% 꼬리 블록 바로 옆 5리전 블록** (트리거 dst→파손 대상 인접 구조)
을 역산할 수 있다. 힙 덤프(jmap/jcmd GC.heap_dump)로 그 5리전 객체의 헤더
length 필드가 비정상 값(예: 음수)인지 확인하면 확정.

**덤**: 레지스터 덤프 섹션에 `[error occurred during error reporting ..., SIGSEGV]` —
hs_err 작성 자체가 2차 SIGSEGV로 일부 실패. **커럽션이 에러 리포터까지 파괴**하는
패턴은 일반 버그와 달리 강력한 커럽션 지표다.

### 2-4. 크래시 서명의 3단 구조 (시스템 로그 관점)

```
[1] java SIGSEGV → hs_err_pid<N>.log 생성 (워킹디렉토리·/tmp)
[2] JVM이 abort() 호출 → core dump 시도 (컨테이너: /app/log/coredump/... 관측됨)
[3] 프로세스 종료 exit 134 (SIGABRT) — systemd: status=6/ABRT, k8s: Last State: Terminated Reason:Error Exit Code:134
```

→ 관제 룰: "java 프로세스 exit 134 + hs_err 신규 생성 + G1CM 프레임" 트리플.

## 3. GC 로그 패턴 (`-Xlog:gc:file=...`, 실측: `results/crash-vuln/gc.log`)

공격 자체가 **동시 마킹 사이클을 인위적으로 연쇄 유도** (힙 조형의 부산물).
전체 279줄 중 **Concurrent Mark Cycle 105회** — 실행 20초 동안 **초당 ~5회**
(정상 서비스는 수 분~수십 분에 1회):

```
[20.389s] GC(111) Concurrent Mark Cycle 6.569ms
[20.473s] GC(112) Pause Young (Normal) 761M->711M(1024M) 0.428ms
[21.504s] GC(113) Pause Young (Concurrent Start) ...      ← 매초 사이클 개시
[21.504s] GC(114) Concurrent Mark Cycle
...
[23.619s] GC(119) Pause Young (Concurrent Start) (G1 Humongous Allocation) 716M->706M
[23.619s] GC(120) Concurrent Mark Cycle                   ← ★ 최종 라인: 완료 시각 없음
```

| 패턴 | 의미 |
|---|---|
| Concurrent Mark Cycle 초당 수 회 연쇄 | humongous 대량 할당(5MB×140) 폭풍 — 힙 조형 서명 |
| `(G1 Humongous Allocation)` 유발 표기 반복 | 리전 절반 초과 할당이 사이클을 직접 유발 |
| 힙 사용 761M→711M 반복 (해소 안 됨) | 캐시 유지(필러)가 live로 상주 — 조형 성공 |
| **최종 라인이 개시만 있고 완료 시각 없는 Concurrent Mark Cycle** | **사이클 도중 프로세스 사망** — §2 크래시와 시간 일치 |

→ GC 로그 관제 룰: "Concurrent Mark Cycle 빈도 임계(예: 분당 >20) 초과 + 로그
갑작 종료" → humongous 폭풍+크래시 조합. JVM 플래그와 무관하게 `-Xlog:gc`만으로
관측 가능 (운영 JVM에 저비용 상시 적용 권장).

## 4. 캐널리 관측자 관점 (보조 — 코드 레벨 증거)

`exploit/results/oob_vuln-default-*.log` (같은 JVM에서의 힙 커널리 관측):

```
canary.length=-1503028570 (expected 5242864) ★ HEADER LENGTH FIELD SMASHED ★
★★★ OOB WRITE OBSERVED AT JAVA LEVEL — canary[71] corrupted ★★★
VERDICT: OOB-OBSERVED (62B write)  →  관측 직후 JVM SIGSEGV→abort, exit 134
(괄호 바이트 수는 당시 도구 출력 원문 — CORRECTION-3 C-2)
```

- 파손된 length 필드 값(-1503028570 = 0xA6536...)은 **디코드 가비지 패턴** —
  공격 입력('A')이 스텁의 유효문자 병합을 통과해 만든 값. 힙 덤프 분석 시
  파손 객체 헤더의 이런 "불가능한 length"가 직접 단서.
- 1MiB/2MiB 심층 오프셋 온전 → 원거리 광역 파손 없음. 쓰기 폭 상한은 이것으로 확정되지 않음 (CORRECTION-3 C-3).
- 크래시 프레임(G1CM)은 같은 run의 캐너리 손상 관측과 **함께** 해석한 것이다. G1 프레임 단독으로 원인 컴포넌트를 확정하지 않는다 (C-9).

## 5. 요약 — 관제/IR 3층 관측 포인트

| 층 | 아티팩트 | 트리플 시그니처 |
|---|---|---|
| 네트워크 | pcap | 7MB 0x41-POST ×140 → DELETE ×1 → 7MB `==`-POST → RST(win 0) |
| **애플리케이션** | WAS 로그 | 대형 decode 성공 폭풍 → 삭제 1건 → **REJECTED 1건이 최종 로그** |
| **JVM/시스템** | hs_err + exit code | SIGSEGV in `G1 Conc#N` + `oop_oop_iterate` + **exit 134** |

세 층 중 하나만 있어도 의심, 둘 있으면 확정, 셋이면 완결. pcap이 없는 환경에서도
§1(앱 로그)+§2(hs_err) 조합으로 사후 식별이 가능하다는 것이 이번 분석의 결론.
