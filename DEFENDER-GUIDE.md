# 방어자 가이드 — OpenJDK 17.0.6+ 무인증 RCE 대응

작성일: 2026-11-17 · 대상: 인프라·SOC·서비스 담당 · 성격: **방어/탐지/대응 (패치 전·후 공용)**
근거: KISA ISMS인증팀 공문(11/17) "OpenJDK Java 17.0.6 이상, 인증 없는 RCE". 공개공지 11/18 예정.
후보 서열화 근거: `candidate-triage-2026-11-17.md`.

> **이 가이드의 전제**: 취약 컴포넌트가 아직 미확정이다. 그래서 **단일 가설(Base64)에 걸지 않고**,
> base-rate 상위 클래스(역직렬화·JNDI/LDAP·XSLT·HTTP파싱) 전반에 유효한 완화·탐지를 깐다.
> 여기 적힌 모든 조치는 **패치와 무관하게 무해하며 즉시 적용 가능**하다(KISA 5-다 "즉시 적용 준비").

---

## 0. 가장 중요한 한 가지

**상위 RCE 클래스(역직렬화·JNDI·XSLT 가젯)는 JVM을 죽이지 않는다 — 가젯이 깔끔히 실행된다.**
따라서 `hs_err_pid*.log`(크래시) 탐지만으로는 **실제 침해를 100% 놓친다.** 탐지의 중심은:

1. **JVM이 자식 프로세스를 생성**(`sh`, `bash`, `curl`, `powershell` 등)
2. **JVM에서 예상 외 아웃바운드**(LDAP 389/636/1389, RMI 1099 및 동적 포트, 미지 IP)
3. **역직렬화·JNDI·XML 예외 로그**의 급증

이 셋이 없으면 가이드의 90%가 무력하다. §3을 먼저 깔 것.

---

## 1. 자산 식별 (영향 선별)

- 영향 범위: **Java 17.0.6 ~ 현재(미패치)**. 11u/21u/25u도 Oracle CSPU 대상 — 동일 조사.
- **앱이 실제 사용하는 런타임**을 식별(번들 JRE·컨테이너 베이스이미지·임베디드 JDK 포함).
  패키지 인벤토리만으로 누락되는 번들 JRE가 핵심.
- 컨테이너: `eclipse-temurin:17.*`, `openjdk:17.*` 베이스 이미지 전수.
```bash
# 호스트 레벨
find / -name 'release' -path '*/lib/*' 2>/dev/null | while read f; do
  v=$(grep -h '^JAVA_VERSION=' "$f"); echo "$f  $v"; done
# 실행 중 JVM (번들 JRE 포착)
ps -eo pid,comm,args | grep -i '[j]ava' | awk '{print $1}' | while read p; do
  readlink -f /proc/$p/exe 2>/dev/null; done | sort -u
```

## 2. 노출면 축소 (KISA 5-나) — 즉시

**인증 전 외부 입력이 닿는 Java 서비스의 외부 접근을 최소화한다.**

| 포트/서비스 | 조치 |
|---|---|
| RMI 레지스트리 1099, **jstatd**, JMX | 외부 차단. 내부도 필요 범위로 ACL. jstatd는 중지 권장 |
| LDAP 클라이언트 콜백(389/636/1389/1099) | **아웃바운드** egress 제어(앱서버→외부 LDAP/RMI 차단) |
| `jdk.httpserver` 직접 노출 | 리버스 프록시 뒤로. 불필요 노출 제거 |
| 업로드→이미지/문서 파싱 | pre-auth 업로드 경로 식별, 파서 격리/샌드박스 |

## 3. 탐지 (crash-free RCE 중심) — 최우선 보강

### 3-A. JVM 자식 프로세스 생성 (가젯 실행의 보편 신호)

**Linux auditd** — java의 자식으로 셸/네트워크 도구가 뜨면 경보:
```
# /etc/audit/rules.d/java-rce.rules
-a always,exit -F arch=b64 -S execve -F exe=/bin/sh    -k java_child
-a always,exit -F arch=b64 -S execve -F exe=/bin/bash  -k java_child
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/curl -k java_child
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/wget -k java_child
# 조사: ausearch -k java_child 후 ppid의 comm=java 인지 확인
```
**쿠버네티스(Falco)** — 컨테이너 내 java 자식 프로세스:
```yaml
- rule: Java spawned a shell
  condition: spawned_process and proc.pname in (java) and proc.name in (sh,bash,dash,curl,wget,nc,python,powershell)
  output: "JVM이 자식 프로세스 생성 (parent=%proc.pname child=%proc.name cmd=%proc.cmdline pod=%k8s.pod.name)"
  priority: CRITICAL
```
**EDR(SentinelOne 등)**: `parent_process=java* AND child_process IN (sh,bash,cmd,powershell,curl,wget,nc)` 커스텀 룰.

### 3-B. 예상 외 아웃바운드 (JNDI/RMI 콜백)

- 앱서버 네트워크에서 **:389 :636 :1389 :1099 및 미등록 목적지**로의 egress 경보.
- JNDI 공격은 앱서버가 공격자 LDAP/RMI로 **먼저 연결**한다 — 인바운드가 아니라 **아웃바운드**가 신호.
```bash
# 빠른 점검(스냅샷): java 프로세스의 외부 연결
ss -tnp 2>/dev/null | grep -i java | grep -vE '127\.0\.0\.1|::1|<내부대역>'
```

### 3-C. 로그 시그니처 (앱/JVM)

```
# 역직렬화
java.io.InvalidClassException | filter status: REJECTED | ObjectInputFilter
sun.reflect | InvocationTargetException .* (Runtime|ProcessBuilder)
# JNDI/LDAP
javax.naming .* lookup | Unable to load class | trustURLCodebase | ldap://  rmi://
# XML/XSLT
TransformerConfigurationException | ACCESS_EXTERNAL | DOCTYPE .* SYSTEM | TemplatesImpl
```

### 3-D. 크래시(메모리커럽션 클래스 보조)

```bash
# hs_err 감시 (이미지/zip/base64/네이티브 파서 프레임)
find <앱작업디렉토리> -name 'hs_err_pid*.log' -newermt '-1 hour' \
  -exec grep -lE 'Base64|ImageIO|libjpeg|libpng|zip| unzip |SIGSEGV|SIGBUS' {} \;
```

## 4. 완화 (클래스별, 패치 전 선적용) — KISA 5-다

> 적용 전 **테스트 환경에서 회귀 확인**. 운영 반영은 재시작 필요. 패치 후 불필요 옵션 제거.

### 4-A. 역직렬화 (최우선)
`$JAVA_HOME/conf/security/java.security` 또는 `-Djdk.serialFilter=...`:
```
# 위험 가젯 전역 거부(allowlist 기반이 이상적, 최소 blocklist 예)
jdk.serialFilter=!org.apache.commons.collections.functors.*;!org.apache.commons.collections4.functors.*;\
!org.codehaus.groovy.runtime.*;!com.sun.org.apache.xalan.*;!javax.management.BadAttributeValueExpException;\
!java.rmi.server.UnicastRef;!sun.rmi.server.*;maxdepth=20;maxrefs=2000
```
- RMI: `-Djava.rmi.server.useCodebaseOnly=true`(기본 true 유지), `jdk.jndi.rmi.object.factoriesFilter` 적용.
- jstatd 중지.

### 4-B. JNDI/LDAP
```
-Dcom.sun.jndi.ldap.object.trustURLCodebase=false   # (JDK17 기본 false — 명시 고정)
-Dcom.sun.jndi.rmi.object.trustURLCodebase=false
-Djdk.jndi.object.factoriesFilter=java.naming.*;javax.sql.rowset.*;!*   # 미지 팩토리 차단
```

### 4-C. XML/XSLT
애플리케이션 코드:
```java
TransformerFactory tf = TransformerFactory.newInstance();
tf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
tf.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
```
전역 시스템 속성: `-Djavax.xml.accessExternalDTD="" -Djavax.xml.accessExternalStylesheet=""`

### 4-D. HTTP 파싱 / 이미지
- 비정상 요청(과대 헤더·비정상 인코딩) WAF 차단. `jdk.httpserver` 불필요 노출 제거.
- pre-auth 이미지 파싱 경로 격리. (Base64 가설 대비 보조: `-XX:-UseBASE64Intrinsics` — AVX-512 x86에서만 의미, **컴포넌트 확정 전 전사 적용 불가**)

## 5. 패치 도착 시 (11/18 공지 / jdk17u 푸시)

1. `./check_patch.sh` → `git -C jdk17u log jdk-17.0.21.0.3-ga..origin/jdk17.0.21.1 --stat`
2. **11건 커밋 ↔ Oracle/NVD CVE ↔ `candidate-triage` 매트릭스** 1:1 매핑
3. 각 커밋의 **신규 회귀 테스트를 코드보다 먼저** 읽기 — 공격 입력 축을 직접 설명
4. 확정된 컴포넌트에 맞춰 §4 완화 중 **해당 항목만 유지**, 나머지 정리
5. **17.0.21.1(또는 해당 라인) 업그레이드**를 최우선 — 완화는 임시일 뿐

## 6. 침해 의심 시 (IR 플레이북)

1. §3-A/3-B 경보 발생 호스트 **격리**(네트워크 차단, 종료 금지 — 메모리 보존)
2. 수집: `ps`/`/proc/<pid>` 트리, java 프로세스 네트워크 연결, 최근 생성 파일, 웹/앱 로그
3. 지표: java 자식 셸, 미지 아웃바운드, `/tmp`·웹루트 신규 바이너리, cron/서비스 신규 등록
4. 범위 산정 후 자격증명 교체·패치·재배포

## 7. KISA 양식 매핑 (11/20 회신)

| 양식 항목 | 소스 |
|---|---|
| Java 사용 여부·버전 | §1 인벤토리 (17.0.6+ = 영향 대상) |
| 영향 시스템 선별 | 버전 × §2 외부 노출 교차 |
| 조치계획 | §4 완화(적용일) + 패치 적용 예정(§5, 공개 즉시) |

## 8. 한계 (정직)

- 컴포넌트 미확정 상태의 **다중 클래스 광역 방어**다. 확정(§5)되면 해당 클래스로 좁혀 정리.
- 완화는 임시. **근본 대응은 패치 적용**. 공지 11/18, 패치 공개 즉시 적용 권고.
