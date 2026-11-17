# HANDOFF — 신규 세션 인계 문서

작성: 2026-11-18 오전 · 갱신: 2026-11-18 오후 (§6-1·3·4·5 완수 반영)

## 1. 프로젝트 한 줄 요약

OpenJDK CVE-2026-114938 (Java4Shell — Base64 AVX-512 assembly OOB 쓰기) 대응 프로젝트.
사전 분석 → 취약점 실증 → 무기화 → 방어 가이드 → **OOB 직접 관측 → KISA 회신 초안** 완료.
**H2 가설(Base64 intrinsic) 최종 확정 + OOB 쓰기 실측 완료.**

## 2. 저장소 위치·환경

- 로컬: `~/Downloads/OpenJDK2Shell` (구 경로 `~/Downloads/OpenJDK`는 심볼릭 링크)
- GitHub: https://github.com/windshock/OpenJDK2Shell (private, 협업자 HeeRPOU 초대됨)
- jdk17u 클론: `~/Downloads/OpenJDK2Shell/jdk17u` (blobless — **전트리 git grep 금지,
  blob 폭탄 ENOSPC 전례**, 경로 한정 git show만)
- kubeconfig: `kube/dfirtx-dev.conf` (admin, git 제외, 600)
- 클러스터: DFIRtx dev (전 노드 AMD EPYC-Genoa, avx512vbmi/bw/vl — Java4Shell 실증 환경)
- colima: 삭제 완료 (디스크 6G 회수)

## 3. 최종 결론 (2026-11-18 기준)

| 항목 | 결론 |
|---|---|
| **CVE-2026-114938** | **Base64 AVX-512 assembly OOB 쓰기 (Java4Shell)** |
| 트리거 | JDK 17: `A`×128 + `=` (129바이트) — 4바이트 미만 패딩 조각을 assembly가 처리 |
| 패치 | 17.0.21.1 커밋 `8ea73158af` (8393212) — `cmpl(length,4); jcc(L_bruteForce)` 4줄 |
| 취약 버전 | 17.0.6~17.0.21.0.x (intrinsic 도입 = 17.0.6, NCSC 하한과 정합) |
| 완화 | `-XX:-UseBASE64Intrinsics` (product 플래그, §9.1 소스 검증) 또는 17.0.21.1 업그레이드 |
| H2 가설 | **재확정 — 처음부터 옳았음** (트리거 몰라서 231케이스 미발동했을 뿐) |
| 8389989 C2 JIT | **별개 버그** — 계산 정확성 버그(루프 조기 종료), OOB/RCE 아님 (CORRECTION-2.md) |
| TemplatesImpl | 별개 실증 (add-opens 환경 원격 RCE 성공) — JDK 17 모듈 시스템이 기본 설정 차단 |
| LDAP trustSerialData | 별개 — 17.0.13에서 이미 패치 (기본값 true→false) |

## 4. 핵심 문서 지도

| 문서 | 내용 |
|---|---|
| `vuln-analysis-2026-11-17.md` | 전체 분석 (§1~§11) — 사실/전제/가설/실증 기록 |
| `candidate-triage-2026-11-17.md` | 후보 triage (+§7 검증 결과) — JIT 미순위 교훈 포함 |
| `PHASE-B-VERDICT.md` | ⚠ **부분 폐기** — CVE↔8389989 매핑은 오인 (CORRECTION-2 참조) |
| `CORRECTION.md` / `CORRECTION-2.md` | 정오표 2건 — 과장 주장 정정 이력 |
| `DEFENDER-GUIDE.md` | **v4** (Base64 확정·OOB 실측 반영; v3의 C2 중심 서술 폐기) |
| `KISA-REPLY-2026-11-20.md` | **KISA 회신 초안** — 컴포넌트·하한·완화 전부 소스 검증 완료 |
| `OOB-OBSERVATION-2026-11-18.md` | **OOB 직접 관측 보고서** — 메커니즘·레시피·매트릭스·포렌식 |
| `deep-analysis-*.md` (C1~C7, A1~A4) | 후보별 심층 분석 |
| `GOAL-find-and-exploit.md` | 실행 골 (국면 A 완료, B 완료) |
| `exploit/E2E-EXPLOIT-SUITE.md` | 익스플로잇 아키텍처 |

## 5. 익스플로잇 자산

| 파일 | 상태 |
|---|---|
| `exploit/src/Java4Shell*.java` | CVE-2026-114938 트리거 (Java 레벨 차등 — 커럽션 미관측 한계) |
| `exploit/src/OobCanary.java` | **★ OOB 직접 관측 도구** (5리전 갭 그루밍 + 힙 커널리) — `oob_run.sh`로 매트릭스 실행 |
| `exploit/results/oob_*.log` | 관측 매트릭스 로그 (셀 1·2 OOB 관측, 셀 3 완화 CLEAN) |
| `exploit/src/Chain2LdapExploit.java` | TemplatesImpl RCE (완전 실증, add-opens) |
| `exploit/src/WeaponizedExploit.java` | RMI → TemplatesImpl (원격, --add-exports 조건) |
| `exploit/src/C2OobExploit.java` | C2 JIT 계산 버그 (별개 버그, OOB 아님) |
| `exploit/victims/` | DeserVictim·EvilDgcServer·StringDecodeSvc 등 |
| `exploit/results/` | 원격 실증 로그 전부 |

## 6. 남은 과제 (2026-11-18 오후 기준)

1. ~~Java4Shell OOB 실측 승격~~ — **완료** (`OOB-OBSERVATION-2026-11-18.md`,
   힙 커널리로 62/63B 쓰기 관측, 완화 대조 입증)
2. **애플리케이션 표적 재현** (미착수, 선택): Keycloak/JWT 파싱이 유력 표적
   (Base64.getUrlDecoder 같은 intrinsic 스텁 공유, 패딩 허용 여부 확인 필요)
3. ~~완화 실효 검증~~ — **셀 1·3 완료** (취약 ON=OOB 관측 / OFF=CLEAN).
   **셀 5·6 (자체 빌드 17.0.21.0.3 vs 17.0.21.1) 파드 빌드 진행 중**
   (`java4shell-build/jdk-build`, `ops/build_jdk17u.sh`, ~2-3h).
   완료 시 OOB-OBSERVATION §4 갱신 + 커밋 + `kubectl delete ns java4shell-build`
4. ~~DEFENDER-GUIDE 최종 갱신~~ — **완료** (v4)
5. ~~KISA 양식~~ — **초안 완료** (`KISA-REPLY-2026-11-20.md`): 컴포넌트 =
   **hotspot/compiler** (8ea73158af = stubGenerator_x86_64.cpp), 하한 17.0.6 =
   decode intrinsic 도입 (07050b000c/JDK-8268276) 코드 아키폴로지, 완화 =
   `-XX:-UseBASE64Intrinsics` (에르고노믹스: vm_version_x86.cpp:951 — AVX-512VL+BW
   CPU 기본 활성). 회신 전 검토 필요.

## 7. 신규 세션 시작 명령

```
~/Downloads/OpenJDK2Shell/HANDOFF.md 를 읽고 이어서 진행하라.
```

한 줄이면 충분 — 이 문서가 자기완결.

## 8. 운영 메모

- 감시 cron: 임무 완수 (jdk-17.0.21.1-ga 관측) — 남아 있으면 삭제 가능
  (`CronList`에서 `OpenJDK 17.0.21.1 패치 감시` 확인)
- 클러스터: 항상 ns 생성→테스트→`kubectl delete ns` 원상복구 사이클
- blobless clone 규율: `git grep` 전트리 금지 / auto-gc 비활성 (`gc.auto 0` 설정됨)
- 협업자 초대: HeeRPOU 완료, kerberosjoo27@gmail.com은 GitHub 사용자명 미확인 (보류)
