# 운영 산출물 — 모니터링 / 인벤토리 / 임시 패치 / 탐지

기준 문서: `../vuln-analysis-2026-11-17.md` (H2 가설, 전제 명시됨). 아래는 모두
**패치(17.0.21.1) 공개 전 임시 대응**이며 H2 확정 여부와 무관하게 무해하게 적용 가능하다.

## 1. 패치 공개 감시 — `monitor.sh`

- GitHub API 폴링(브랜치 헤드 4개 + jdk17u 태그). git fetch를 쓰지 않아
  blobless clone 디스크 사고(§8.5) 재발이 없다.
- `NEW:` 줄이 나오면 즉시 `../check_patch.sh` → §8.4 절차.
- 수동: `./monitor.sh` / 자동: 워크스페이스 cron(30분 간격)이 같은 스크립트를 실행한다.

## 2. 노출 인벤토리 — `inventory.sh`

JDK 버전 × AVX-512 CPU × `UseBASE64Intrinsics` 플래그를 점검해 H2 전제 하 노출 판정.
전사 적용 예: `ansible all -m script -a './inventory.sh'`.

## 3. 임시 패치 — `mitigate.sh` (핵심)

근거(저장소 소스 검증): Base64 인트린식 스텁은 `if (UseBASE64Intrinsics)`
(globals.hpp `product` 플래그) 하위에서만 생성 → **`-XX:-UseBASE64Intrinsics`** 로
이 경로만 차단, 디코드는 Java 폴백으로 정확 동작(성능: CPU-bound 디코드 위주 서비스만 영향).

| 모드 | 내용 |
|---|---|
| `print` | `JAVA_TOOL_OPTIONS="-XX:-UseBASE64Intrinsics"` 출력 |
| `verify` | 대상 JVM 플래그 상태 확인(x86에서 `bool ... = false` 확인) |
| `systemd UNIT --apply` | drop-in 작성 + daemon-reload (재시작으로 반영) |
| `waf` | nginx Basic 헤더 사전검증 스니펫 — 앱 도달 전 트리거 차단 |

적용 우선순위: ① AVX-512 × 17.0.6~17.0.21 인증 전 Base64 디코드 서비스부터
② 전사는 패치 공개 직후 17.0.21.1 업그레이드로 대체(그때 옵션 제거).

## 4. 공격 시도 탐지 — `scan_hs_err.sh`

인증 전 디코드를 하는 서비스의 `hs_err_pid*.log`(SIGSEGV/SIGBUS)를 후보로 올리는
tripwire. 확정 시그니처는 패치 diff 확보 후 회귀 테스트 기반으로 갱신할 것.
애플리케이션/프록시 로그에서는 `Authorization: Basic` 값의 비정상 길이·캐릭터셋
(대문자/숫자/+//외 문자, 8KB 초과) 출현 카운트도 병행 권장.

## 5. x86_64 / AVX-512 실행 러너 — `docker/run_x64.sh`

- Temurin 17.0.8 x64 이미지 + 실행 스크립트. CPU 플래그 실측(avx512 여부) 후
  `e2e.py --diff` 자동 실행. colima(x86_64 QEMU·brute-force 경로)와 AVX-512 호스트
  (VBMI 경로) 양쪽에서 동일하게 사용.

### 사내 쿠버네티스(DFIRtx dev, EPYC-Genoa avx512vbmi 확인) 재사용 절차

자격증명: `kube/dfirtx-dev.conf` (클러스터 admin — **git 제외**, 권한 600).
접속: `export KUBECONFIG="$(git rev-parse --show-toplevel 2>/dev/null || echo ..)/kube/dfirtx-dev.conf"`

2026-11-17 실측에 사용한 절차(전 노드 AVX-512 풀세트 확인됨):

1. `kubectl create ns oj2s-test`
2. victim 클래스를 ConfigMap(binaryData)으로 적재. Pod는
   `eclipse-temurin:17.0.8_7-jdk-jammy` 이미지 + `command: ["java","-cp","/v",
   "UnauthBase64Svc","18080","0.0.0.0"]` + `JAVA_TOOL_OPTIONS=-XX:+UseBASE64Intrinsics`
   (OFF 팔은 `-XX:-`), limits 2CPU/2Gi, `restartPolicy: Never`, nodeName으로 워커 고정
3. NodePort 31808 Service → 맥에서 `python3 exploit/trigger_gen.py --fire <nodeIP> 31808`
4. on/off 두 번 실행 → JSONL 비교(DIVERGENT). 크래시 시 Pod 로그·hs_err 보존
5. 종료: `kubectl delete ns oj2s-test` (클러스터 원상복구)
