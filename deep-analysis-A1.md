# A1 — 역직렬화 가젯 클래스 (triage 1위) 사이클 완결 보고

작성: 2026-11-17 심야 · GOAL-find-and-exploit 국면 A1 · 증거: `exploit/results/a1-*`

## 결론 먼저

**"인증 없는 단 한 번의 RMI 호출 → 희생 JVM이 공격자 지정 주소로 JRMP 역연결" 프리미티브를
DFIRtx 클러스터(EPYC-Genoa, 17.0.8)에서 무인증·크로스-파드로 실증 완료.**
이 클래스의 E2E는 "가젯이 클래스패스에 있는가"에서만 막히며, 이 지점이 곧 AC:H(8.1)의
실체이자 11월 패치가 채울 빈칸이다.

## 사이클 기록 (7단계 상당)

| 단계 | 결과 |
|---|---|
| 템플릿 근거 | 10월 `8384930 Enhance jstatd` = 무인증 RMI에 ObjectInputFilter **신설** — 이 표면이 현재 진행형 하드닝 대상임을 VG가 자증 |
| 필터 실태(소스+실험) | 전역 serialFilter=**null**(실측). `UnicastServerRef`: *"필터 공급 시에만 적용, 아니면 ObjectInputStream 기본"* — **인자 경로 기본 무필터**. `StreamRemoteCall`(응답 경로)도 설정 의존 — 기본 무필터 |
| 진입(①) | 무인증 RMI 호출 — 레지스트리 bind는 비로컬 거부(`AccessException`)되나 **export 객체는 호스트체크 없음** — `echo(Object)` 인자로 전달 성공 |
| 역직렬화(②) | 인자 그래프(Proxy+RemoteObjectInvocationHandler+LiveRef)가 희생 측에서 **무필터 역직렬화** 성공 (반환값 echo OK) |
| 콜백 레일(③) | 역직렬화된 LiveRef가 ConnectionInputStream에 등록 → `registerRefs()` → DGC dirty — **공격자 지정 host:port로 JRMP 역연결**. 클러스터에서 **6회 접속 관측**(초기+갱신) |
| 응답경로(보조) | 악성 Return(내 JRMP 서버 구현 — 451B dirty 원문 복호까지 성공)도 역직렬화되나, Lease 캐스팅 예외 시 `discardRefs()`로 ref 폐기 → 2차 캐너리 미발사(소스로 규명) |
| 관측축 | EvilDgcServer·CanaryListen(자체 제작) + `ops/detect-rce.sh --live` 축(RMI 아웃바운드)과 정합 |

## 승격 지점 (11월 패치 대조용)

이 체인의 유일한 공백 = **readObject 부수효과로 이어지는 가젯**:
- 순수 JDK 후보 발굴: `UnicastRemoteObject.readObject → reexport()`(역직렬화만으로 리스닝
  시작 — 소스 확인) 등 readObject-부수효과 인벤토리화 예정
- 패치 diff가 이 공간(java.rmi 직렬화/ref 처리)을 건드리면 즉시 이 하니스에 트리거 투입

## 산출물

- `exploit/victims/`: DeserVictim(무필터 RMI+/osi)·PayloadGen·BindAttack(bind/echo)·
  EvilDgcServer(JRMP 와이어 전체)·CanaryListen
- 증거: `results/a1-jrmp-callback-local.txt`(로컬 7B)·`a1-cluster-{attacker,victim}.log`
  (클러스터 6회 접속·echo OK·dirty 원문)·`a1-4-progress.txt`
- 판정: **triage 1위 클래스 실증 완료(진입+직렬화+레일)** / RCE 종점은 가젯·패치 대기
