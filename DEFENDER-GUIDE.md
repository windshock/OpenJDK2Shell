# 방어자 가이드 — OpenJDK 17.0.6+ Base64 OOB (Java4Shell) 대응 (v6 — 2026-11-25 코드 실행 단계 지표·적용 범위 보강)

> **⚠ 2026-11-23 정정 반영** — `CORRECTION-3.md` 참조 (정정 전 문장은 그 문서에 원문 보존).
> **v6 (2026-11-25)** — 코드 실행 두 체인(11/24)과 그 적용 범위(11/25)를 반영: §0 표, §1, §3-A, §3-E ⑥, §3-F·§4-E3 신설, §6, §8.
> 근거: `exploit/E2E-EXPLOIT-SUITE.md` 체인 5·6과 후속 절. 인프라·관제용 정리: `MONITORING-CHECKLIST-2026-11-25.md`.

작성일: 2026-11-17 · 갱신: 2026-11-25 (v6 — 코드 실행 단계 지표·적용 범위. v5 11/23 영향 조건·수정 빌드·완화, v4 11/18 CVE 확정)
· 대상: 인프라·SOC·서비스 담당
근거: KISA ISMS인증팀 공문(11/17) + OpenJDK Advisory 2026/11/17 + jdk17u 소스 검증(11/18)

> **진범 확정 (11/18)**: **CVE-2026-114938 = Base64 AVX-512 assembly OOB 쓰기 (Java4Shell)**,
> hotspot/compiler, CVSS 8.1 (v3.1). 수정 커밋 **JDK-8393212 (`8ea73158af`, 17.0.21.1)**.
> 취약 범위 **17.0.6~17.0.21.0.3** (decode intrinsic 도입 = JDK-8268276, 17.0.6 — 코드
> 아키폴로지 검증 완료). v3의 "C2 JIT 루프 최적화 = 진범" 서술은 **폐기** (JDK-8389989는
> 별개 계산정확성 버그 — CORRECTION-2.md).

---

## 0. 가장 중요한 한 가지

**진범은 `java.util.Base64.getDecoder().decode()`의 AVX-512 intrinsic 스텁 OOB다.
진입 조건은 단 하나 — "공격자가 Base64 디코드가 적용되는 입력을 전달 가능"해야 한다.**
(JSON의 base64 필드, HTTP Basic Auth, JWT, 멀티파트/이미지 디코딩, RMI/직렬화 내 문자열 등).
트리거 입력은 4바이트 미만 패딩 테일(예: `A`×128 + `=`) — 정상 데이터와 구분 불가한
"평범한 Base64"다. 특수 시그니처·프로토콜 위반이 없다.

| 클래스 | 크래시 | 자식프로세스 | 아웃바운드 | 탐지 가능성 |
|---|---|---|---|---|
| **Base64 OOB (본 CVE)** | 실패 시 hs_err. 코드 실행에 성공한 랩 실행은 JVM 생존·hs_err 0 | **승격되면 있음** — 랩 체인 6은 셸 없이 `touch`를 직접 실행 (v6) | 랩에서는 없음 | **§3-D/E/F** (hs_err·커럽션·길이 이상·응답 지표) |
| 역직렬화 가젯 | 없음 | 있을 수 있음 | 있을 수 있음 | §3-A/3-B |
| JNDI/LDAP | 없음 | 있을 수 있음 | 있음 | §3-B |
| C2 계산정확성 (8389989, 별개) | 없음 | 없음 | 없음 | 잘못된 계산 결과 모니터링 |

**완화는 §4-E: `-XX:-UseBASE64Intrinsics` — product 플래그 1개, 성능 영향 극히 제한(권장).**
참고: Base64 intrinsic 구현은 C2 전용(`src/hotspot/share/opto/library_call.cpp`)이므로
`-XX:TieredStopAtLevel=1`(C1-only)로도 차단되나, 성능 저하 20~50%로 임시 완화 부적합 —
v3 §4-E의 우선순위를 뒤집었다(해당 서술은 v4에서 폐기).
(§3-D의 JFR 기반 C2 관측 기법은 CVE-2026-114941 등 C2 계열 대비로 보존.)

### 0-1. 영향 판정 조건 (v5, 2026-11-23 — 소스 재확인)

아래 **전부**를 충족해야 취약 코드가 실행된다. 하나라도 아니면 해당 경로는 동작하지 않는다.

| 조건 | 확인 방법 | 근거 |
|---|---|---|
| x86-64 | `uname -m` | 스텁은 x86 전용 (ARM64·에뮬레이션 무관) |
| **AVX-512 VBMI + BW** (+VL, BMI2) | `grep -o -w -E 'avx512(vbmi\|bw\|vl\|f)\|bmi2' /proc/cpuinfo \| sort -u` | 취약 벡터 경로는 `supports_avx512_vbmi() && supports_avx512bw()`일 때만 생성 (`stubGenerator_x86_64.cpp`). Intel Ice Lake 이후 / AMD Zen4 이후. **VBMI 없는 AVX-512(Skylake-SP·Cascade Lake)는 intrinsic이 켜져도 이 경로를 타지 않음** |
| 영향 JDK | 실제 프로세스의 런타임 (§1 — 번들 JRE·컨테이너 포함) | 17.0.6~17.0.21.0.x 등, §5 수정 빌드 미만 |
| intrinsic 활성 | `jcmd <pid> VM.flags -all \| grep UseBASE64Intrinsics` | `UseAVX>2 && avx512vl && avx512bw`면 기본 true |
| 공격자 입력이 `java.util.Base64.Decoder`에 도달 | sink 인벤토리 (아래) | 끝에 `=` 패딩, 4바이트 미만 꼬리, JDK 17은 128자 초과 |

- **HTTP 버전·HTTP/2 설정은 조건이 아니다.** 결함은 디코더 안에 있고, 입력이 디코더에 닿는 경로라면
  프로토콜은 무관하다. 실측(2026-11-23, DFIRtx Genoa, Temurin 17.0.8): HTTP/2를 지원하지 않는 서버 2종
  (JDK `com.sun.net.httpserver`, Spring Boot/Tomcat 기본 설정)에 HTTP/1.1 요청만으로 트리거 →
  JVM SIGSEGV 사망. pcap에도 HTTP/1.1 요청만 기록됐다.
- **URL-safe 디코더(`getUrlDecoder`)도 해당**: `=` 패딩을 허용하고, 스텁은 URL 모드에서도 같은 쓰기를
  수행한다 (CORRECTION-3 C-5). 무패딩 JWT 세그먼트 자체는 트리거 형태가 아니지만, 라이브러리가 패딩을
  어떻게 처리하는지는 제품별로 확인해야 한다.
- **pre-auth Base64 sink 인벤토리**: HTTP Basic, JWT/OIDC, SAML, 쿠키, 업로드/첨부, JSON base64 필드,
  메시지 큐·RPC 페이로드. 각 sink가 표준 `java.util.Base64`를 쓰는지, 자체 구현인지 기록한다.

---

## 1. 자산 식별 (영향 선별)

- **진범(CVE-2026-114938) 영향**: Java 17.0.6~17.0.21.0.x (hotspot/compiler). 타 라인: 21·25·27은 §5 수정 빌드 미만이 영향.
  **표준 OpenJDK 8/11은 decode intrinsic이 없어 무영향**, 단 Oracle Java SE 8 Performance Pack(8u511b33-perf)은 영향(8u513-perf 수정).
  (v4의 "8·11 … 전 라인" 표기는 과잉 — v5 정정)
  - **11/25 실측**: Temurin 21.0.13+9(수정 전 빌드)에서도 같은 손상(인접 배열의 length)이 관측됐다 — 랩 모델 3회, 모두 첫 트리거 시도에서.
- **별개 실증 취약점 (우리가 발견)**:
  - TemplatesImpl 역직렬화 RCE: 17.0.0~17.0.20 (SecurityManager=null 기본값)
  - LDAP trustSerialData=true: 17.0.6~17.0.12 (기본값 true)
- **앱이 실제 사용하는 런타임** 식별: 번들 JRE·컨테이너 베이스이미지 포함
```bash
find / -name 'release' -path '*/lib/*' 2>/dev/null | while read f; do
  v=$(grep -h '^JAVA_VERSION=' "$f"); echo "$f  $v"; done
ps -eo pid,comm,args | grep -i '[j]ava' | awk '{print $1}' | while read p; do
  readlink -f /proc/$p/exe 2>/dev/null; done | sort -u
```

## 2. 노출면 축소 (KISA 5-나) — 즉시

**C2 JIT 버그의 진입 경로는 특정 포트가 아니라 "외부 입력이 처리되는 모든 자바 코드"다.**
즉, §2의 포트 차단은 C2 JIT에 직접 효과가 없으나, 역직렬화·JNDI 벡터 차단에는 유효.

| 포트/서비스 | 조치 | C2 JIT 효과 | 역직렬화 효과 |
|---|---|---|---|
| RMI 1099, jstatd, JMX | 외부 차단 | — | ✓ 진입 차단 |
| LDAP 389/636/1389 아웃바운드 | egress 제어 | — | ✓ 콜백 차단 |
| `jdk.httpserver` 직접 노출 | 리버스 프록시 | — | ✓ |
| 업로드→이미지/문서 파싱 | 격리/샌드박스 | — | ✓ |

## 3. 탐지

### 3-A. JVM 자식 프로세스 (역직렬화 RCE 페이로드 단계, Base64 OOB 코드 실행 단계)

```bash
# Linux auditd
-a always,exit -F arch=b64 -S execve -F exe=/bin/sh    -k java_child
-a always,exit -F arch=b64 -S execve -F exe=/bin/bash  -k java_child
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/curl -k java_child
```

> **v6 — 고정 경로 목록만으로는 놓친다.** 랩 체인 6은 `Runtime.exec(String)`로 **셸을 거치지 않고 `touch`를 직접** 실행했다.
> 위처럼 `sh`·`bash`·`curl`만 보는 규칙에는 걸리지 않는다. **부모가 java인 `execve`를 전부 기록**하고(auditd execve 전체 + ppid 연계,
> Falco·EDR의 프로세스 계보), 서비스별 평상 패턴과 비교한다. 자식 프로세스는 JVM의 권한을 그대로 물려받는다
> (랩에서는 컨테이너 root, uid 0). 상세: `MONITORING-CHECKLIST-2026-11-25.md`.

### 3-B. 예상 외 아웃바운드 (JNDI/RMI 콜백 — 페이로드가 콜백하는 경우 유효)

```bash
ss -tnp 2>/dev/null | grep -i java | grep -vE '127\.0.0\.1|::1|<내부대역>'
```

### 3-C. 로그 시그니처 (역직렬화·JNDI·XML 경유 공격에 유효)

```
java.io.InvalidClassException | filter status: REJECTED | TemplatesImpl
javax.naming.* lookup | trustURLCodebase | ldap:// rmi://
TransformerConfigurationException | ACCESS_EXTERNAL | DOCTYPE.*SYSTEM
```

### 3-D. Base64 OOB (CVE-2026-114938) + C2 계열(CVE-2026-114941 등) — JVM 런타임 이벤트

**탐지 원칙**: 전통적 시그니처(크래시·프로세스·네트워크)를 회피할 수 있으나,
JVM 런타임 레벨에서는 관측 가능한 흔적이 남는다.

| 관측 축 | 방법 | 신호 |
|---|---|---|
| **JFR 상시 수집** (최우선) | `-XX:StartFlightRecording=filename=...` 또는 `jcmd <pid> JFR.start` | Compilation 이벤트 급증, Deoptimization 폭증, 비정상 ObjectAllocationSample |
| **JIT 워밍업 시그니처** | 앱 로그·APM에서 특정 메서드의 비정상 반복 호출 패턴 모니터링 | C2 컴파일은 tiered threshold(~10K 회 호출)를 넘겨야 하므로, 공격 준비 단계에서 특정 메서드가 짧은 시간에 비정상적으로 반복됨 |
| **컴파일러 로그** | `-XX:+PrintCompilation -XX:+TraceDeoptimization` | 비정상 컴파일·디옵트 패턴 |
| **Code Cache 이상** | `-XX:+PrintCodeCache` / JFR CodeCacheStatistics | 코드 캐시 점유·무효화 급변 |
| **실패한 시도** | `hs_err_pid*.log` 모니터링 | JIT 익스플로잇은 불안정(힙 레이아웃·타이밍 민감) — 실패한 시도는 SIGSEGV/hs_err 덤프를 남김 |
| **런타임 예외** | AIOOBE·ArithmeticException 모니터링 | C2가 경계검사를 제거한 루프에서 발생 |

```bash
# JFR 상시 수집 (운영 오버헤드 < 1%):
java -XX:StartFlightRecording=duration=60s,filename=/tmp/jfr/health.jfr,maxsize=100m ...
# 분석: jfr print --events Compilation,Deoptimization /tmp/jfr/health.jfr

# 비교 검증 (핵심 루프만, 상황별):
# 1. 특정 메서드를 C2 제외: -XX:CompileCommand=exclude,com.app.CriticalLoop::method
# 2. 결과 비교 → 다르면 C2 버그 의심
```

### 3-E2. WAF/IDS 시그니처 (외부 공개 룰 — alert-first 권고)

취약 표면: 표준 알파벳·URL 디코더(MIME은 무관). JDK17 최소 트리거 ~129자(21/25/27은 ~65자).
베이스64가 정상 트래픽에도 흔하므로 **alert 모드로 FP 측정 후 차단 전환**, JDK 패치 후 제거.

```text
1) Basic auth 초장문: Authorization:\s*Basic\s+[A-Za-z0-9+/]{128,}={1,2}
2) 단일문자 연속 + 패딩 PoC 시그니처: ([A-Za-z0-9+/_-])\1{63,}={1,2}  (body: /P, header: /H)
3) JWT(URL-safe) 세그먼트에 '=' 패딩 — 정상 JWT는 무패딩이므로 그 자체가 이례:
   [A-Za-z0-9_-]{85,}={1,2}(\.|[^A-Za-z0-9_=-]|$)
```

(출처: 커뮤니티 공개 룰 정리 — 결정적 차단이 아니라 스캐너/저노력 시도 포착용.
결정적 공격은 정상처럼 보이는 b64로 회피 가능 — 패치가 근본 대응.)

### 3-E. 크래시 (메모리커럽션 보조)

> **해석 주의 (v5)**: 크래시가 없다고 안전한 것이 아니고, 프로세스가 살아 있다고 메모리가 무사한 것도 아니다.
> 우리 랩에서는 작은 입력 150발이 크래시 없이 흡수됐다. 외부 보고(Hadrian, REPORTED)에는 코드 실행 후에도
> 서비스가 정상 응답을 계속한 사례가 있다. 크래시는 **실패했거나 불안정한 시도의 흔적**일 뿐이다.
> 탐지는 보조 수단이고 패치나 완화가 대체 수단이 아니다.

> **11/24 자체 실측(랩 모델, `exploit/E2E-EXPLOIT-SUITE.md` 체인 5·6):** 코드 실행에 이른 17회 모두 **hs_err 0·JVM 생존**으로 끝났다.
> 크래시 없음은 비침해 지표가 아니다. **(정정) young GC가 통과한다고 볼 수 없다** — young GC 준비 단계가 손상 객체의 klass를 읽으므로,
> 통과 여부는 깨진 klass가 읽기 가능한 주소에 놓이는지에 달려 있다(어떤 run은 5회 통과, 다른 run은 첫 GC에 `G1PrepareRegionsClosure` SIGSEGV).
> 공격자는 GC가 없는 사이에 끝낸다 — 크래시는 안 올 수도, 나중에 올 수도 있다.
> 같은 랩에서 본 추가 서명: ① 손상 배열을 건드리는 앱 프레임의 `SIGSEGV SEGV_ACCERR`(klass+8 역참조 — `bastore`·`aastore`·`checkcast`),
> ② `G1 Conc#0`의 `oopDesc::size_given_klass`. ③ 요청 관점: MB급 본문이 `=`/`==`로 끝나는 400 직후, **객체 크기를 넘는 offset의 범위 읽기·부분 수정 요청**.
> ④ 볼륨: 그 구현은 keep-alive 연결 1개에 송신 3.28 GB(26초)라 "세션당 100 MB" 류의 룰에 걸린다(1회 실측). 단일 최대 요청은 6.67 MiB라
> 연결을 나누면 걸리지 않는다 — 볼륨 룰은 노력 낮은 시도용이고 ①~③이 이 체인에 더 특이적이다(체인 5 §트래픽 프로파일).
> ⑤ **(체인 6) 토큰·권한 인터페이스 없이도 됨:** OOB 쓰기 3건 + 요청 1건(`GET /actions/upper?arg=touch%20/tmp/…`)으로 JVM이 자식 프로세스를 만들었다.
> 가장 직접적인 신호는 **java 프로세스의 예기치 않은 자식 프로세스**(실행 감사·auditd·Falco). 앱 로그에는 무해한 핸들러가
> `{"result":"Process[pid=…]}`를 돌려주거나, 실패한 시도의 `IllegalArgumentException: object is not an instance of declaring class`가 남는다.
> ⑥ **(11/25) 실패한 시도의 다른 서명:** 리플렉션 호출의 반환 값을 문자열화하는 프레임(`java.lang.String.valueOf`, C1 코드)에서 `SIGSEGV`.
> 그 설정(CDS를 끈 랩 JVM, 3회)에서는 그 슬롯이 `long`을 돌려주는 메서드(`freeMemory`)라, 원시값이 객체로 취급됐다. §3-F의 예외 지표와 함께 본다.

```bash
find <앱작업디렉토리> -name 'hs_err_pid*.log' -newermt '-1 hour' \
  -exec grep -lE 'SIGSEGV|SIGBUS|loop|opto' {} \;
```

### 3-F. 코드 실행 단계의 지표 (v6 — 2026-11-25, 랩 모델 실측)

`exploit/E2E-EXPLOIT-SUITE.md` 체인 5·6을 원격에서 실행하며 본 것. 피해자는 랩 모델(`J4sRceVictim`)이고 실제 애플리케이션에서 재현한 것은
JVM 크래시까지라, 아래는 **관측 지점의 후보**이지 확정 시그니처가 아니다.

| 지표 | 어디서 보이나 | 뜻 | 한계 |
|---|---|---|---|
| **응답 본문의 `Process[pid=`** | 평소 문자열·JSON을 돌려주는 API의 응답. 정칙 `Process\[pid=\d+` | 문자열을 돌려줘야 할 리플렉션 호출이 `Runtime.exec`로 바뀌고, 그 반환 객체(`Process.toString()`)가 그대로 응답에 실린 것 | Java4Shell 전용이 아니다. sqlmap의 SSTI 판정 로직(`lib/techniques/ssti/inject.py`)에도 "명령은 실행됐지만 stdout을 잡지 못한 blind exec"으로 이미 들어 있다. 공격자가 결과를 돌려주지 않으면 안 보인다. TLS 구간은 복호화하거나 앱·게이트웨이 시점에서만 보인다 |
| **핸들러 예외** | 애플리케이션 로그 | 호출 대상 바꿔치기가 **실패**한 흔적 | 정상 앱의 리플렉션 오용·라이브러리 버그와 겹칠 수 있다 |
| **java의 예기치 않은 자식 프로세스** | 실행 감사(auditd·Falco·EDR) | 가장 직접적인 신호 (§3-A) | 컨테이너·호스트 PID와 요청 시각을 연결해야 쓸 수 있다 |
| **트리거 직후의 요청 패턴** | 접근 로그·pcap | MB급 본문이 `=`로 끝나며 거부(400)된 직후, 저장 크기를 넘는 offset의 범위 읽기·부분 수정 | 그런 API가 있는 서비스에만 해당한다 (§3-E ③) |

핸들러 예외는 랩에서 세 가지를 봤다.

- `IllegalArgumentException: object is not an instance of declaring class` — 수신자가 선언 클래스의 인스턴스가 아닐 때.
- **JDK 18 이상**: `NullPointerException: Cannot invoke "java.lang.invoke.MethodHandle.asFixedArity()" because "dmh" is null`.
  JDK 18부터 기본 리플렉션이 메서드 핸들 기반이라(JEP 416) 접근자를 만들 때 선언 클래스·이름·시그니처로 메서드를 찾는데,
  `Method` 객체의 그 셋이 서로 맞지 않아 찾지 못한 것이다 (Temurin 21.0.13+9 랩, 한 JVM에서 202건).
- 존재하지 않는 메서드를 가리키는 `NoSuchMethodError` — 랩에서는 `'java.lang.String java.lang.Class.upper(java.lang.String)'`.

**시간 관계(1회 실측):** 트리거 요청 약 8초 뒤에 코드 실행 요청 1건이 왔고, 전체 실행은 60초 안에 끝났다. 연관 탐지 창은 분 단위가 아니라
초 단위로 잡는다. 구간별 시각은 `exploit/results/pcap/j4s-chain6-remote/j4s-chain6-remote-README.txt`.

**캡처의 한계:** 공유 pcap는 패킷당 96바이트(`tcpdump -s 96`)만 담고 있어 요청 라인과 헤더 앞부분은 보이지만 **응답 본문은 보이지 않는다**
(랩 캡처 두 개에서 패킷의 63~65%가 잘림). 응답 본문 지표는 이 pcap로는 검증할 수 없고, 전체 길이 캡처나 액세스 로그·APM이 따로 필요하다.

## 4. 완화 — KISA 5-다

> 적용 전 **테스트 환경 회귀 확인**. 운영 반영은 재시작 필요. 패치 후 불필요 옵션 제거.

### ★ 4-E. Base64 intrinsic 비활성화 (CVE-2026-114938 — 진범 직접 완화)

```bash
# 표적 완화 — Base64 AVX-512 intrinsic만 차단 (나머지 JIT 최적화는 그대로)
# 비 AVX-512VL+BW CPU에서는 intrinsic 자체가 비활성이므로 이 옵션은 무해(공석)
# (취약 벡터 경로는 VBMI+BW CPU에서만 생성 — §0-1)
JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"
```

| 항목 | 내용 |
|---|---|
| 효과 | CVE-2026-114938 **완전 차단** — 버그 코드(AVX-512 decode 스텁)가 생성/호출되지 않음 |
| 성능 영향 | **극히 제한** — Base64 코덱만 Java 스칼라 경로 fallback, 나머지 JIT는 원상 유지 |
| 적용 대상 | 모든 아키텍처 공통 (비 AVX-512 CPU에선 no-op) |
| 참고 | v3의 `-XX:TieredStopAtLevel=1`(C2 비활성)도 차단에는 유효(intrinsic은 C2 전용, `opto/library_call.cpp`)하나 20~50% 성능 저하로 **임시 완화 부적합** — v4에서 폐기 |
| 해제 시점 | **17.0.21.1 패치 적용 직후** |

> **활성 메커니즘 (소스 검증)**: 플래그 정적 기본값 false(`runtime/globals.hpp`),
> 단 `vm_version_x86.cpp:951-954`에서 `UseAVX>2 && avx512vl && avx512bw` CPU에
> 에르고노믹스 동적 활성. 단 취약 벡터 경로는 **VBMI+BW CPU**에서만 생성되므로
> "AVX-512 서버는 기본 취약"(v4)은 과잉 — **VBMI 지원 AVX-512 서버가 기본 취약** (v5 정정, CORRECTION-3 C-10).
> 명시 플래그는 에르고노믹스를 무시하므로 위 옵션이 확실.

**적용 확인 (필수)**: 옵션 추가 후 **JVM 재기동**, 그리고 실행 중인 프로세스에서 직접 확인한다
(설정 파일만 보고 판정하지 않는다):
```bash
jcmd <pid> VM.flags -all | grep -E 'UseBASE64Intrinsics|UseAVX'
# 기대: UseBASE64Intrinsics = false  {command line}
```

### 4-E2. 광역 대안: `-XX:UseAVX=2`

```bash
JAVA_TOOL_OPTIONS="-XX:UseAVX=2"
```
`UseAVX>2` 조건이 깨지므로 Base64 intrinsic 에르고노믹스가 활성화되지 않는다 (`vm_version_x86.cpp`).
대신 **AVX-512 기반 최적화 전체를 포기**하므로 성능 영향 범위가 넓다. §4-E를 쓸 수 없는 경우
(옵션 화이트리스트 등)에만 고려하고, 적용 후 같은 방법으로 `UseAVX`·`UseBASE64Intrinsics`를 확인한다.

### 4-E3. 이것들은 완화가 아니다 (v6 — 2026-11-25 실측)

랩 체인 6(메모리 손상만으로 `Method.invoke`를 `Runtime.exec`로 바꾸는 경로)이 동작하지 않는 조건을 확인했다.
**그 구현 하나가 깨졌을 뿐, 취약점은 그대로이고 다른 경로는 막히지 않는다.** 완화는 §4-E, 근본 대응은 §5뿐이다.

| 조건 | 체인 6 | 취약점·다른 경로 | 왜 |
|---|---|---|---|
| JDK **17 라인 + CDS 기본 아카이브** | 됨 — 11/11 (빌드별 측정값 없이도) | — | 체인 6은 이 범위에서만 성립한다 |
| `-Xshare:off` (CDS 아카이브 끔) | 안 됨 — 0/3 | 취약점은 그대로. **체인 5는 6/6 정상** | 메서드 슬롯 번호가 실행 설정마다 달라진다 |
| JDK **18 이상**의 기본 리플렉션 | 안 됨 | Temurin 21.0.13+9에서도 손상 관측(랩 3회) | 기본 리플렉션이 메서드 핸들 기반이라 호출 시점에 슬롯을 읽지 않는다(JEP 416). 구형 접근자 플래그(`jdk.reflect.useDirectMethodHandle=false`)를 켜면 됨(랩 1/1) |

`-Xshare:off`나 리플렉션 설정을 "완화"로 쓰지 않는다. 실제 서비스에서 저 경로가 되는지는 측정하지 않았다(랩 모델).

### 4-A. 역직렬화 (별개 취약점 — 계속 유효)

```
# ⚠ *는 직접 패키지 멤버만 매치 (하위 패키지 안 됨 — 실측)
jdk.serialFilter=!org.apache.commons.collections.functors.*;\
!org.apache.commons.collections4.functors.*;\
!org.codehaus.groovy.runtime.*;\
!com.sun.org.apache.xalan.internal.xsltc.trax.*;\
!com.sun.org.apache.xalan.internal.xsltc.runtime.*;\
!com.sun.org.apache.xalan.internal.xsltc.dom.*;\
!javax.management.BadAttributeValueExpException;\
!java.rmi.server.UnicastRef;\
!sun.rmi.server.*;\
!sun.rmi.transport.*;\
maxdepth=20;maxrefs=2000
```

### 4-B. JNDI/LDAP (별개 취약점)

```
-Dcom.sun.jndi.ldap.object.trustURLCodebase=false
-Dcom.sun.jndi.rmi.object.trustURLCodebase=false
-Dcom.sun.jndi.ldap.object.trustSerialData=false     # 17.0.6~12 기본값 true!
-Djdk.jndi.object.factoriesFilter=java.naming.*;javax.sql.rowset.*;!*
```

### 4-C. XML/XSLT

```java
TransformerFactory tf = TransformerFactory.newInstance();
tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```

### 4-D. HTTP/이미지 (기존 유지)

## 5. 패치 적용 (11/18 공개)

**OpenJDK Advisory 2026/11/17 공개 완료. jdk-17.0.21.1-ga 관측 완료(패치 커밋 확인).**

| CVE | 컴포넌트 | CVSS | 실수정 커밋 (17 라인) |
|---|---|---|---|
| **CVE-2026-114938** | **hotspot/compiler** | **8.1** | **8393212 (`8ea73158af`) — Base64 AVX-512 경계검사 4줄** |
| CVE-2026-114941 | hotspot/compiler | 7.0 | 8390400 Enhance C2 comparisons |
| CVE-2026-114939 | security-libs/jgss | 7.4 | 8387162 등 |
| CVE-2026-114940 | security-libs/javax.net.ssl | 7.4 | 8393456 |
| CVE-2026-114942 | core-libs | 7.0 | 8386535 |
| (기타 6건) | — | ≤6.5 | — |

> **정정 (CORRECTION-2)**: v3가 본 CVE의 커밋을 8389989 "Enhance loop handling"로 표기한
> 것은 오인 — 8389989는 별개 **계산정확성 버그**(C2 루프 조기 종료, OOB/RCE 아님).
> CVE-2026-114938의 실수정은 **8393212** (stubGenerator_x86_64.cpp, decode 테일 경계검사).

**벤더 수정 빌드 (v5 — 확인일 명시)**:

| 배포 | 수정 빌드 | 출처·확인일 |
|---|---|---|
| OpenJDK / Oracle | 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1 | Oracle CSPU 11/17 |
| **Eclipse Temurin** | **17.0.21.1+2, 21.0.13.1+2, 25.0.5.1+2, 27.0.1.1+4** | Adoptium 공지 11/18. Docker Hub `eclipse-temurin:17.0.21.1_2-jdk(-jammy)` 11/20 게시 (11/23 확인). 플랫폼별 상태: adoptium/temurin#326 |
| Corretto, Zulu | released | 11/18 확인 |
| Microsoft, RHEL | 11/18 시점 pending | **재확인 필요** |

주의: **`17.0.21`(+9 등) 기본 빌드는 미수정**이다. 반드시 `.1` 빌드인지 확인한다. 컨테이너 이미지는 태그가 아니라 실제 `java -version`으로 확인한다.

**조치 순서**:
1. **17.0.21.1 (또는 각 라인 .1) 업그레이드 최우선**
2. 패치 적용 전 서비스는 §4-E (`-XX:-UseBASE64Intrinsics`) — 성능 영향 거의 없음,
   신속 전면 적용 가능. 패치 후 해제
3. §4-A~D는 방어 심화로 유지 가능 (패치와 무관하게 무해)

## 6. 침해 의심 시 (IR 플레이북)

1. §3-A/3-B 경보 발생 호스트 **격리** (네트워크 차단, 종료 금지 — 메모리 보존)
2. 수집: `ps`/`/proc` 트리, 네트워크 연결, 최근 생성 파일, 앱 로그
3. 지표: java 자식 프로세스(**셸을 거치지 않는 직접 실행 포함** — §3-A), 응답·로그의 `Process[pid=`와 리플렉션 예외(§3-F),
   미지 아웃바운드, `/tmp` 신규 파일
4. **C2 JIT 침해의 경우**: 성공한 페이로드는 위 지표가 없을 수 있으나,
   JFR 녹화(§3-D)에서 Compilation/Deoptimization 이상, 잘못된 계산 결과,
   실패한 시도의 hs_err 덤프를 확인. **완전히 흔적이 없는 것은 아님**.
5. 범위 산정 후 자격증명 교체·패치·재배포

## 7. KISA 양식 매핑 (11/20 회신)

| 양식 항목 | 소스 |
|---|---|
| Java 사용 여부·버전 | §1 (17.0.6~17.0.21.0.3 = CVE-2026-114938 영향) |
| 취약점 정보 | **CVE-2026-114938 = Base64 AVX-512 assembly OOB, hotspot/compiler, CVSS 8.1(v3.1)** — 상세: `KISA-REPLY-2026-11-20.md` |
| 영향 시스템 | §0-1 조건(VBMI CPU 포함) × §1 인벤토리 × §2 외부 노출 교차 |
| 조치계획 | §4-E `-XX:-UseBASE64Intrinsics`(임시, 성능 영향 극히 제한; 불가 시 §4-E2 `-XX:UseAVX=2`) → **17.0.21.1 업그레이드(근본)**. 적용 후 `jcmd VM.flags`로 실행 프로세스 확인 |

## 8. 한계 (정직)

- **C2 JIT 익스플로잇의 탐지**: 전통적 시그니처(크래시·자식 프로세스·네트워크 비콘)를
  회피할 수 있으나 **완전히 탐지 불가능한 것은 아니다**. JIT 컴파일/디옵트 이벤트,
  비정상 메서드 호출 워밍업, 코드 캐시·힙 이상은 관측 가능하며(§3-D),
  **JFR 상시 수집이 가장 비용 효율적인 탐지 수단**이다. 완화(§4-E)는 탐지와 병행.
- **§4-E 성능 영향**: TieredStopAtLevel=1은 CPU-bound 서비스에 20~50% 저하.
  적용 대상 신중 선별 필요 (외부 입력 처리 서비스 우선, 내부 배치는 후순위)
- **§4-A blocklist 한계**: 미지 가젯은 차단 못함 (allowlist가 이상적이나 운영 부담)
- **와일드카드 주의**: `com.example.*`는 하위 패키지 매치 안 됨 (직접 멤버만)
  TemplatesImpl 차단: `...xsltc.trax.*` (O). `...xalan.*` (X)
- **A3 검증 (11/17)**: TemplatesImpl → defineClass → RCE를 17.0.8에서 실증.
  §4-A 수정 패턴으로 차단 확인. **단, JDK 17 기본 설정에서는 모듈 시스템이
  superclass 접근을 차단하여 원격 공격 불가** — add-opens/add-exports 환경에서만 유효.
- **정정 (v4, CORRECTION-2 반영)**: v3가 "Chain 3 = CVE-2026-114938 재현"으로 표기한 것은
  오인 — 해당 테스트는 **JDK-8389989 별개 계산정확성 버그**(캐너리 FIRED)이고,
  E2E 원격 RCE(11/18)는 **TemplatesImpl 체인**(별개 취약점, add-exports 조건)이다.
- **OOB 직접 관측 완료 (11/18)**: CVE-2026-114938의 OOB 쓰기를 힙 커널리 기법으로
  Java 레벨에서 직접 관측 — canary 헤더 length 필드 뭉개짐(64B store, 논리 초과 62/63B — CORRECTION-3 C-2),
  `-XX:-UseBASE64Intrinsics` 대조 CLEAN(**완화 실효 입증**).
  상세: `OOB-OBSERVATION-2026-11-18.md`. 성공한 OOB 직후 JVM SIGABRT —
  **급사하는 Java 프로세스 + hs_err/코어 덤프가 운영 탐지 신호**.
- **코드 실행 실증의 범위 (v6, 11/25)**: 체인 5·6 모두 피해자는 랩 모델이다. 실제 애플리케이션에서 재현한 것은 JVM 크래시(DoS)까지다.
  체인 6은 **JDK 17 라인 + CDS 기본 아카이브**로 한정된다(§4-E3). "크래시가 없으니 안전"도 "JVM이 살아 있으니 무사"도 성립하지 않는다.
- **응답 본문 지표의 검증 공백 (v6)**: 공유 pcap는 96바이트 단위 캡처라 `Process[pid=` 응답 룰을 그걸로 검증하지 못했다.
  전체 길이 캡처나 애플리케이션 로그로 탐지률·오탐을 재기 전에는 후보로만 둔다.
