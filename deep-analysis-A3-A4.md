# A3(XSLT/TemplatesImpl) + A4(httpserver) 사이클 보고

작성: 2026-11-17 심야 · GOAL-find-and-exploit 국면 A3·A4 완결

## A3 — TemplatesImpl → 순수 JDK RCE (🚨 실증 완료)

### 발견 경위
10월 `8384654 Enhance Template Handling` diff에서 `TemplatesImpl.readObject()`에
**무조건적 차단 검사 신설** 확인 → 그 이전(17.0.0~17.0.20)은 `SecurityManager=null`
(기본값)일 때 `if (security != null)` 블록이 **건너뛰어져** 역직렬화 무조건 허용.

### E2E 실증 (DFIRtx/Genoa/17.0.8)
```
TemplatesImpl.readObject() → _bytecodes 역직렬화 [무검사]
→ getOutputProperties() → defineTransletClasses() → defineClass()
→ 악성 클래스 static initializer 실행
→ [RCE CANARY] 캐너리 파일 생성 FIRED ✓✓✓
```
증거: `exploit/results/a3-templates-rce.log` (커밋 47545eb)

### 공격 체인 (A1/A2 + A3 결합 = 완전한 무인증 순수 JDK RCE)
```
① 진입: 무인증 RMI echo(Object) 또는 LDAP javaSerializedData
② 역직렬화: TemplatesImpl [SecurityManager=null → 무검사, serialFilter=null]
③ 코드 실행: _bytecodes → defineClass → static initializer → RCE
   (외부 라이브러리 불필요 — commons-collections 등 없이 순수 JDK만으로 가능)
```

### 버전 영향
| 버전 | 보호 상태 | 이유 |
|---|---|---|
| 17.0.0~17.0.20 | **취약** | SecurityManager=null(기본값) → 차단 없음 |
| 17.0.21 (8384654) | 보호 | `jdk.xml.enableTemplatesImplDeserialization` 필수 (기본=false) |

## A4 — jdk.httpserver 파싱 (이상 없음)

### 테스트 결과 (17.0.8 클러스터, 7개 엣지 케이스)
| 케이스 | 결과 |
|---|---|
| CRLF 헤더 주입 | 400 Bad Request (적절히 거부) |
| 100KB 초장 헤더 | 200 OK (처리 가능) |
| 음수 Content-Length | 400 (거부) |
| TE+CL 동시 (스머글링) | 400 (거부) |
| NUL 바이트 헤더 | 200 (처리됨) |
| 1000개 헤더 | Connection reset (거부, 크래시 없음) |

**판정: 미지지(관측된 이상 없음)** — 10월 8386515는 코드 리팩토링이지 특정 취약점 수정이 아님.

## 국면 A 종합

| 클래스 | 순위 | E2E | 캐너리 | 핵심 |
|---|---|---|---|---|
| A1 역직렬화/RMI | 1위 | ✓ 완료 | JRMP 콜백 | 무인증 RMI → 무필터 역직렬화 |
| A2 JNDI/LDAP | 2위 | ✓ 완료 | 파일 생성 | trustSerialData=true (17.0.6~12) |
| A3 XSLT/Templates | 3위 | ✓ 완료 | **RCE 코드 실행** | 순수 JDK 가젯 — 최종 익스플로잇 |
| A4 httpserver | 4위 | ✓ 완료 | 이상 없음 | 파싱 강건, RCE 아님 |

**완성된 E2E 익스플로잇**: A1(진입) + A3(가젯) = 무인증·순수 JDK·17.0.6~17.0.20 RCE
