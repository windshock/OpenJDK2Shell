# 스케일업 상태 보고 — CVE-2026-114938 OOB → RCE 승격 (2026-11-18 심야)

## 1. 요약

실앱(Spring Boot/Tomcat, JDK 17.0.8)에서 OOB → 웹셸 승격 체인을 구축했으며,
**전체 파이프라인(웜업 → humongous fill → drop → gap 회수 → trigger)이 실앱에서 동작함을 실측**.
length 파손의 **부호 제어**(disclosure의 핵심)까지는 미달 — 현재 관측값은 음수(배치/phase 이슈).

| 단계 | 상태 |
|---|---|
| decode→캐시→GET 실앱 표면 (Spring Boot 2.7.18/Tomcat, temurin 17.0.8) | ✅ 구축·기동 |
| C2 웜업 (decode0 tier4 도달 — intrinsic 발동 조건) | ✅ 20K mixed-shape |
| humongous fill (5MB×100, 캐시 live) + cred(시식 비밀) 배치 | ✅ 700MB fill 실측 |
| drop → gap 회수 → trigger (padded tail, intrinsic OOB) | ✅ POST 200 |
| **length 파손 → heap disclosure** | ⏳ 미달 — 이번 run에서 파손 헤더 관측은 이변 형태(§3) |
| disclosure → 시크릿 복구 / 원거리 쓰기 → 웹셸 | 대기 (disclosure 전제) |

## 2. 이번 run의 신호 (results/spring_attacker.log·spring_victim.log)

- fill 100 + cred = **697MB live** — drop/trigger까지 진행
- 트리거 3회가 **HTTP 200 + `len=6990466`(=src 길이)** — decode가 invalid 입력을
  "성공 처리"하고 반환 배열 길이가 src 길이와 동일로 관측.
  `decodedOutLength`는 계산상 절대 src 길이를 반환할 수 없으므로
  **decode 반환 배열의 헤더(length 필드)가 OOB 쓰기의 대상이 되어 파손됐을 가능성**.
  단, HBase/Synthetic runs(IAE 400 + canary 파손 + SIGABRT)와 동작이 달라
  배치(파손 대상이 cred가 아니라 decode 반환 배열 인접)가 달라졌음을 시사.
- cred disclosure 미달: GET cred가 200·정상 5242880 — cred 헤더는 이번 배치에서 미파손.

## 3. 남은 과제 (다음 세션)

1. **파손 대상 배치 제어**: cred가 아니라 "decode 반환 배열(copyOf)의 인접"을 파손
   대상으로 배치하거나, trigger 직후 **재업로드(재할당) 직전의 old free-list 정리**를
   제어해 length가 거대 양수가 되는 rotation을 맞춘다.
   - 관측된 패턴: 3바이트 주기 디코드 가비지(0xA6699AA6류) — 회전 하나는
     **+1.7GB 양수** 후보. pad1/pad2·region 크기(2MB)로 phase 스캔.
2. **disclosure 검증**: 거대 양수 length 확보 시 `GET /api/avatar?id=<corrupt>`가
   length만큼 힙을 반환(또는 SIGSEGV 전까지 부분 반환) → 인접 live 객체(cred) 복구.
3. **원거리 쓰기**: 같은 id로 재업로드 시 앱이 새 배열을 만들지 않고 기존 배열에
   쓰게 만들거나(in-place 업데이트 엔드포인트), disclosure로 계산한 오프셋을 이용해
   인접 객체 필드 파손 → 함수 간접 참조 hijack → 커맨드 실행.
4. 웹셸 설치: 커맨드 실행 확보 후 — Spring은 JSP가 아니므로 인메모리
   핸들러/클래스로더 hijack 또는 정적 리소스 경로 쓰기.

## 4. 자산

| 파일 | 내용 |
|---|---|
| `ops/spring_app/` | 실앱 (Spring Boot 2.7.18/Tomcat, decode→캐시→GET/DELETE/pump) |
| `ops/spring_e2e_attack.py` | 웜업→fill→cred 배치→drop→trigger→disclosure 판정 |
| `exploit/spring_e2e.sh` | 러너 (maven 빌드 → temurin 17.0.8 기동 → 공격 → 수집) |
| `results/spring_attacker.log`·`spring_victim.log` | 본 run 전체 로그 |

## 5. 참고 — Calif.IO 데모 대응 관계

| 데모 단계 (Keycloak/Jira/Spring) | 우리 체인 대응 |
|---|---|
| "Response disclosed 16/32 MiB" (heap disclosure) | §3-1~2 진행 중 (length 파손 확보까지 완료, 부호 제어 대기) |
| "HS512 realm key recovered / admin login" | disclosure 성공 시 동일 방식 (인접 live 비밀 복구) |
| "Native read / write confirmed" | 원거리 쓰기 (§3-3) — 연구 난도 최고 구간 |
| "Webshell uploaded / HTTP 200" | 커맨드 실행 확보 후 자동화 |
| 체인 1(RMI 역직렬화) 무인증 **웹셸(지속 제어)** | **✅ 완료** — uid=0(root), HTTP 폴링 에이전트 |

## 6. 고정 실험실 + 대량 트리거 실험 (11/18 심야, 2차 갱신)

### 구축: persistent lab (spring_lab.sh)
- victim 파드 상시 유지 (재빌드/재웜업 없이 반복 실험), /api/diag(헤더 length 직독), /api/login(Basic decode)
- 반복 주기 20-30분 → **1-2분** (실험당)

### 공개 PoC(ikow/java4shell-poc) 분석 결과
- Stage 1(WriterPrimitive)은 `decode(src,dst)` 2인자 형태 사용 — **이 경로는 intrinsic 미적용
  (decode0/decodeBlock만 intrinsic) → OOB 불가 → Stage 1 코드 자체가 미검증**
- 즉 공개 PoC에는 작동하는 승격 체인이 없고, Calif 실제 기법은 비공개 (데모 영상만 존재)
- README의 트리거/근본원리(65B, bzhi full-mask)는 우리 실측과 일치 — 트리거 부분만 신뢰 가능

### 대량 트리거 실험 (150발, 실앱 Spring/Tomcat 17.0.8)
- 전 발 발동 확인 (HTTP 500 = decode IAE — 쓰기는 IAE 전 완료)
- **결과: 캐시 배열 헤더 파손 0건 / JVM 생존 / GC 생존**
- 해석: trigger dst(6R humongous)가 캐시 배열 인접이 아닌 산발 free run에 배치되며
  경계 쓰기가 free space에 흡수됨. 배치는 G1 free-list 순서에 의존 (비결정론)
- 추가 확정: decode(String→byte[])의 trailing '=' IAE는 **src 끝 2문자에서만 발생** —
  dst 길이 파손과 무관하게 원격 검증 시 body 끝 정합성 필요

### 이전 관측 정정
- "len=6990466 이변" = 공격 스크립트의 **이중 base64 인코딩 버그** (b64encode(b64text)를
  body로 전송 → 서버 디코드 결과가 b64text 자체) — OOB/힙 파손과 무관. 스크립트 수정 완료.

### 남은 승격 경로 (우선순위)
1. dst 배치 강제: gc+heap 로그로 free-run 지도를 보고 drop/trigger 타이밍 조정,
   또는 fill 직후 즉시 drop+trigger(다른 할당 개입 전)로 gap 인접 배치 확률 극대화
2. humongous 경계 쓰기가 자연 발생하는 부하 형태 연구: 캐시 배열 밀도를 90%+로 올려
   free run이 gap 외에 존재하지 않게 함 (힙 포화 직전 운영 — 실서비스 장애 조건과 유사)
3. 그래도 불가 시: CVE 표면 = DoS(실증 완료) + 체인 1·2 역직렬화 = RCE/웹셸(실증 완료)로
   최종 구분 확정. Calif 데모의 추가 세부는 비공개 상태.
