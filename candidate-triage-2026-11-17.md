# 후보 triage — OpenJDK 17.0.6+ 무인증 RCE (편향 제거 · base-rate 서열화)

작성일: 2026-11-17 · 성격: **패치 전 확률적 후보 triage (방어/영향도용)**
권위 출처: KISA ISMS인증팀 공문(2026-11-17) — "OpenJDK Java 17.0.6 이상, 인증 없는 RCE",
CVE·CVSS 미기재. 공개 보안공지 boho.or.kr **11/18 예정**. Oracle CSPU 2026-11: Java SE 11건,
전건 인증 불요 원격, 최고 CVSS v3.1 **8.1(AC:H)**.

> 이 문서는 `vuln-analysis-2026-11-17.md`의 H2(Base64) 편중을 교정한다. 기존 분석은 한 가설을
> **깊게** 팠을 뿐 후보집합을 **닫지** 못했다. 아래는 직전 CPU(17.0.21) 보안 커밋 42건을
> 템플릿으로 삼아 후보 유니버스를 닫고, 도달성 × 코드형태 × base-rate로 서열화한 결과다.

## 1. 방법론

- **P1("17.0.6 = 도입시점")은 1차 필터가 아니라 2차 가점**으로만 사용. P1 과신이 H2
  터널비전의 원인이었다. P1 출처는 공문의 버전 표기뿐이며 "지원 하한"일 수 있다(미검증).
- 채점 3축:
  - **R 도달성**: 인증 전 외부 입력 도달 (프로토콜 자체 pre-auth=상 / 업로드·설정 의존=중 / 클라측·로컬=하)
  - **F 형태**: RCE 코드형태 — 가젯(역직렬화/JNDI) · 네이티브 메모리커럽션 · 순수로직(=RCE 아님)
  - **B base-rate**: "Java 무인증 RCE"로 실제 터진 역사적 빈도
- **8.1 / AC:H 신호**: 9.8 웜형이 아니라 **가젯이 클래스패스에 있어야/특정 설정이어야** 성립하는
  조건부 RCE에 부합. 역직렬화·JNDI·XSLT 가젯 클래스와 정합.

## 2. 후보 triage 매트릭스 (직전 CPU 42건 → 클래스 서열화)

| 순위 | 클래스 | 관련 커밋(템플릿) | R | F | B | 종합 |
|---|---|---|---|---|---|---|
| **1** | **역직렬화 가젯** (RMI/JMX/jstatd/WebRowSet) | `8383301 WebRowSets`, `8384930 jstatd`, `8385249 diagnostic sessions`, `8384455 DataFlavor` | 중 | 가젯 | **최상** | **최우선** |
| **2** | **JNDI/LDAP 주입** | `8382407 LDAP Lookups`, `8383047 LDAP logins`, `8383076 SASL` | 중상 | 가젯 | 상 | **최우선** |
| **3** | **XML/XSLT 템플릿** | `8384654 Template Handling`, `8383699 XPath`, `8384031 XML Processing` | 중 | 가젯 | 상 | 고 |
| **4** | **HTTP 서버/클라 파싱** | `8386515 HTTP server parsing`, `8386525 Handler`, `8383439/8384872`, `8386535 headers` | 상(httpserver pre-auth) | 메모리/스머글링 | 중 | 고 |
| **5** | **이미지/미디어 파서** (업로드) | `8384445 JPEG`, `8384664 Image`, `8386552 GIF`, `8386187 font`, `8385476 MIDI` | 중(업로드 의존) | 네이티브 커럽션 | 중 | 중 |
| 6 | **Kerberos/GSS 토큰** | `8387152/8387217/8387238 krb5` | 상(pre-auth) | 파싱(로직/메모리) | 중하 | 중 |
| 7 | **Zip 파싱** | `8341625 ZIP END header` | 중(업로드) | 로직/메모리 | 중하 | 중하 |
| 8 | **Base64 intrinsic (H2)** | (이번 템플릿 배치에 없음) | 상 | 네이티브 커럽션 | **최하**(선례 사실상 없음) | **하** |
| 9 | TLS/인증서 검증 | `8382178/8384771/8386923/8383679/8384021` | 상 | 순수로직 → RCE 아님 | — | 제외(우회·MitM) |
| 10 | 크립토(PKCS5/MD5/SHA3) | `8380715/8383281/8333867` | — | 순수로직 | — | 제외 |

## 3. 상위 티어 근거

- **1·2위 (역직렬화 + JNDI/LDAP)**: "Java 무인증 RCE"의 역사적 다수(commons-collections deser
  사태, Log4Shell, RMI/JMX deser). 템플릿에 `WebRowSets`(XML→java 역직렬화), `jstatd`(기본
  무인증 RMI 데몬), `LDAP Lookups/logins`, `SASL`이 동시 등장 — AC:H(가젯 의존)와 정합.
- **3위 (XSLT/Template)**: `Enhance Template Handling`은 TransformerFactory/TemplatesImpl 계열
  냄새. 고전 RCE 가젯.
- **4위 (HTTP 파싱)**: `jdk.httpserver`는 pre-auth 네트워크 노출 1순위. 파싱 버그 =
  메모리커럽션 또는 요청 스머글링. 도달성 최상.
- **8위 (H2 Base64)**: 네이티브·pre-auth는 맞으나 "HotSpot 인트린식 pre-auth 웜형 메모리커럽션
  RCE"는 역사적 선례가 사실상 없음. 231×2 차등 CLEAN도 낮은 사전확률과 정합. **기각 불가
  (침묵 커럽션 관측불가)지만 최우선 → 최하위 재배치.**

## 4. 완화·탐지 준비 (상위 클래스별 — 패치 무관 무해·유효, KISA "즉시 적용 준비"에 부합)

| 상위 클래스 | 준비할 완화 | 준비할 탐지 |
|---|---|---|
| 역직렬화 | `jdk.serialFilter`/`ObjectInputFilter` 전역 블랙리스트, jstatd·RMI 포트 외부차단 | 역직렬화 예외 로그, **JVM 자식프로세스 생성**, **예상외 아웃바운드** |
| JNDI/LDAP | `com.sun.jndi.{ldap,rmi}.object.trustURLCodebase=false`, `trustSerialData=false` | JVM→외부 **LDAP/RMI 아웃바운드**(콜백) |
| XSLT | `FEATURE_SECURE_PROCESSING`, 외부 엔티티/stylesheet 차단 | Transformer 예외, 외부 DTD 조회 |
| HTTP 파싱 | 비정상 요청 WAF, 불필요 httpserver 외부차단 | 파싱 예외·비정상 헤더 |
| 이미지 | pre-auth 업로드 ImageIO 경로 식별·격리 | 파서 `hs_err` 크래시 |

> 현 `ops/mitigate.sh`(Base64)·`ops/scan_hs_err.sh`(크래시)만으로는 **1~4위를 못 막고 못 본다.**
> 특히 1~3위 RCE는 **크래시를 안 내므로** "자식프로세스 생성 + 예상외 아웃바운드"가 핵심
> 탐지축인데 현재 전무 — 이 둘을 우선 보강할 것.

## 5. 한계 (확정 수단)

- **패치 전 확률적 triage.** 템플릿은 직전 CPU(17.0.21)이지 17.0.21.1 실제 diff가 아니다.
- **확정은 둘뿐**: ① boho.or.kr 공지(11/18) + NVD **컴포넌트 열**, ② jdk17u 패치 diff.
  공개 즉시 42건식 커밋 목록을 이 매트릭스에 매핑하면 10분 내 붕괴된다.
- 상위 후보별 "17.0.6 도입" 검증(P1)은 **NVD 컴포넌트/패치 diff로** 수행할 것 —
  blobless clone `-S` 전수탐색은 blob 폭탄(ENOSPC 전례) 금지.

## 6. 다음 수

1. 상위 1~4위 완화·탐지 스니펫 선작성 (무해·유효)
2. 11/18 공지/패치 공개 즉시 본 매트릭스에 매핑 → 확정 → CVE↔커밋↔후보 대조표
