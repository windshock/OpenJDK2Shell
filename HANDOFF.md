# HANDOFF — 신규 세션 인계 문서

작성: 2026-11-18 오전 · 이 문서 하나면 새 세션에서 전부 이어갈 수 있음.

## 1. 프로젝트 한 줄 요약

OpenJDK CVE-2026-114938 (Java4Shell — Base64 AVX-512 assembly OOB 쓰기) 대응 프로젝트.
사전 분석 → 취약점 실증 → 무기화 → 방어 가이드까지 완료. **H2 가설(Base64 intrinsic)이
최종적으로 진범으로 확정됨.**

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
| `DEFENDER-GUIDE.md` | 방어자 가이드 v3 (JFR 탐지, C2/TemplatesImpl 완화, §8 한계) |
| `deep-analysis-*.md` (C1~C7, A1~A4) | 후보별 심층 분석 |
| `GOAL-find-and-exploit.md` | 실행 골 (국면 A 완료, B 완료) |
| `exploit/E2E-EXPLOIT-SUITE.md` | 익스플로잇 아키텍처 |

## 5. 익스플로잇 자산

| 파일 | 상태 |
|---|---|
| `exploit/src/Java4Shell*.java` | **CVE-2026-114938 트리거** (길이별 차등 테스트) — Java 레벨 관측 한계 있음 |
| `exploit/src/Chain2LdapExploit.java` | TemplatesImpl RCE (완전 실증, add-opens) |
| `exploit/src/WeaponizedExploit.java` | RMI → TemplatesImpl (원격, --add-exports 조건) |
| `exploit/src/C2OobExploit.java` | C2 JIT 계산 버그 (별개 버그, OOB 아님) |
| `exploit/victims/` | DeserVictim·EvilDgcServer·StringDecodeSvc 등 |
| `exploit/results/` | 원격 실증 로그 전부 |

## 6. 남은 과제 (신규 세션 후보 작업)

1. **Java4Shell OOB 실측 승격**: Java 레벨 예외만으로는 커럽션 미관측 —
   네이티브 디버거(gdb/lldb)·ASAN 빌드·JFR ObjectAllocationSample로
   "62바이트 OOB 쓰기"를 직접 관측 (공개 주장 검증)
2. **애플리케이션 표적 재현**: Keycloak/Jira/Confluence 등 공개 RCE 목록을
   DFIRtx에서 재현 (공개 정보에 실증 상세 없음)
3. **완화 실효 검증**: `-XX:-UseBASE64Intrinsics` vs 취약 빌드 vs 17.0.21.1
   3중 대조로 트리거 입력 차등 확인 (§11 패턴)
4. **DEFENDER-GUIDE 최종 갱신**: 진범 확정(CVE-2026-114938=Base64) 반영 —
   현재 v3는 C2 JIT 중심 서술이 남아 있음
5. **KISA 양식 (11/20 회신)**: CVE-2026-114938 컴포넌트 = security-libs? →
   Risk matrix 기준 `security-libs/javax.net.ssl` 아님, **hotspot/compiler가 아니라
   Base64 intrinsic = hotspot/compiler** 재확인 필요

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
