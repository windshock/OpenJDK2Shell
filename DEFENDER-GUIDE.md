# 방어자 가이드 — OpenJDK 17.0.6+ Base64 OOB (Java4Shell) 대응 (v4 — 진범 확정 반영)

작성일: 2026-11-17 · 갱신: 2026-11-18 (v4 — CVE-2026-114938 = Base64 AVX-512 assembly OOB 확정)
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
| **Base64 OOB (본 CVE)** | 실패 시 hs_err / 성공 시 힙 커럽션 | 없음 | 없음 | **§3-D/E** (hs_err·커럽션·길이 이상) |
| 역직렬화 가젯 | 없음 | 있을 수 있음 | 있을 수 있음 | §3-A/3-B |
| JNDI/LDAP | 없음 | 있을 수 있음 | 있음 | §3-B |
| C2 계산정확성 (8389989, 별개) | 없음 | 없음 | 없음 | 잘못된 계산 결과 모니터링 |

**완화는 §4-E: `-XX:-UseBASE64Intrinsics` — product 플래그 1개, 성능 영향 극히 제한(권장).**
참고: Base64 intrinsic 구현은 C2 전용(`src/hotspot/share/opto/library_call.cpp`)이므로
`-XX:TieredStopAtLevel=1`(C1-only)로도 차단되나, 성능 저하 20~50%로 임시 완화 부적합 —
v3 §4-E의 우선순위를 뒤집었다(해당 서술은 v4에서 폐기).
(§3-D의 JFR 기반 C2 관측 기법은 CVE-2026-114941 등 C2 계열 대비로 보존.)

---

## 1. 자산 식별 (영향 선별)

- **진범(CVE-2026-114938) 영향**: Java 17.0.6~17.0.21.0.3 (hotspot/compiler, 8·11·17·21·25·27 전 라인)
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

### 3-A. JVM 자식 프로세스 (역직렬화 RCE 페이로드 단계에서 유효)

```bash
# Linux auditd
-a always,exit -F arch=b64 -S execve -F exe=/bin/sh    -k java_child
-a always,exit -F arch=b64 -S execve -F exe=/bin/bash  -k java_child
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/curl -k java_child
```

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

### 3-E. 크래시 (메모리커럽션 보조)

```bash
find <앱작업디렉토리> -name 'hs_err_pid*.log' -newermt '-1 hour' \
  -exec grep -lE 'SIGSEGV|SIGBUS|loop|opto' {} \;
```

## 4. 완화 — KISA 5-다

> 적용 전 **테스트 환경 회귀 확인**. 운영 반영은 재시작 필요. 패치 후 불필요 옵션 제거.

### ★ 4-E. Base64 intrinsic 비활성화 (CVE-2026-114938 — 진범 직접 완화)

```bash
# 표적 완화 — Base64 AVX-512 intrinsic만 차단 (나머지 JIT 최적화는 그대로)
# 비 AVX-512VL+BW CPU에서는 intrinsic 자체가 비활성이므로 이 옵션은 무해(공석)
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
> 에르고노믹스 동적 활성 → **AVX-512 서버는 기본 취약**. 명시 플래그는 에르고노믹스를
> 무시하므로 위 옵션이 확실.

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

**조치 순서**:
1. **17.0.21.1 (또는 각 라인 .1) 업그레이드 최우선**
2. 패치 적용 전 서비스는 §4-E (`-XX:-UseBASE64Intrinsics`) — 성능 영향 거의 없음,
   신속 전면 적용 가능. 패치 후 해제
3. §4-A~D는 방어 심화로 유지 가능 (패치와 무관하게 무해)

## 6. 침해 의심 시 (IR 플레이북)

1. §3-A/3-B 경보 발생 호스트 **격리** (네트워크 차단, 종료 금지 — 메모리 보존)
2. 수집: `ps`/`/proc` 트리, 네트워크 연결, 최근 생성 파일, 앱 로그
3. 지표: java 자식 셸, 미지 아웃바운드, `/tmp` 신규 바이너리
4. **C2 JIT 침해의 경우**: 성공한 페이로드는 위 지표가 없을 수 있으나,
   JFR 녹화(§3-D)에서 Compilation/Deoptimization 이상, 잘못된 계산 결과,
   실패한 시도의 hs_err 덤프를 확인. **완전히 흔적이 없는 것은 아님**.
5. 범위 산정 후 자격증명 교체·패치·재배포

## 7. KISA 양식 매핑 (11/20 회신)

| 양식 항목 | 소스 |
|---|---|
| Java 사용 여부·버전 | §1 (17.0.6~17.0.21.0.3 = CVE-2026-114938 영향) |
| 취약점 정보 | **CVE-2026-114938 = Base64 AVX-512 assembly OOB, hotspot/compiler, CVSS 8.1(v3.1)** — 상세: `KISA-REPLY-2026-11-20.md` |
| 영향 시스템 | §1 인벤토리 × §2 외부 노출 교차 |
| 조치계획 | §4-E `-XX:-UseBASE64Intrinsics`(임시, 성능 영향 극히 제한) → **17.0.21.1 업그레이드(근본)** |

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
  **CVE-2026-114938(Base64 OOB) 자체의 실측은 Java4Shell 트리거로 진행 중**
  (히프 커널리·gdb 관측 승격 예정).
