# research/ — Java4Shell 인과·예측·기전 검증 (재사용 인덱스)

이 세션(2026-11-23)에서 만든 실험·분석·진단 자산과 **재실행 방법**. 전제: `kube/dfirtx-dev.conf`(gitignore,
600)로 DFIRtx dev 클러스터 접근. 노드 dev01~06 = AMD EPYC-Genoa(AVX-512 VBMI+BW). 실험 네임스페이스는
`j4s-research*`/`j4s-mech`이며 종료 시 전부 삭제한다(`teardown`).

## 문서 지도
| 파일 | 내용 |
|---|---|
| `RESEARCH-PLAN-2026-11-23.md` (리포 루트) | 통합 계획 v2.0 (트랙 C 정정·D 방어·Phase 0~3) |
| `PREREG-2026-11-23.md` | 사전등록 (arm·프로토콜·지표·결정규칙) + deviation D-1·D-2 (잠금 5fbe402) |
| `RESULTS-2026-11-23.md` | 실험 A·B 결과 (A causal supported / B INCONCLUSIVE), 독립 감사 반영 |
| `mechanism/MECH-PLAN.md`·`MECH-RESULTS.md` | 중간 기전 확인 (A Unsafe 헤더 diff · B fastdebug 검증기) + 유출 "불가능 아님" 검토 |
| 리포트 근거 | `CORRECTION-3.md`(정정 C-1~C-11), `DEFENDER-GUIDE.md` v5, `KISA-REPLY-2026-11-20.md` |

## 실험 랩 (실험 A·B) — `lab/`
새 JVM = 1 episode. supervisor가 JVM 사망 시에도 컨테이너 유지, episode마다 새 JVM.
```bash
export KUBECONFIG=kube/dfirtx-dev.conf
# 단일 노드
NS=j4s-research NODE=dfirtx-worker-dev02 research/lab/lab.sh deploy
research/lab/lab.sh run  research/schedules/main-2026-11-23.json
research/lab/lab.sh status            # N=20 로 더 보기
research/lab/lab.sh pull  main-2026-11-23/dev02   # /share → research/data/<dir>/
research/lab/lab.sh stop              # 드라이버·JVM 정지
research/lab/lab.sh teardown
# 다중 노드 병렬 (노드당 블록)
python3 research/schedules/make_main.py dev01 dev02 dev03 dev04 dev05 dev06   # lane별 스케줄 생성
PENDING=3,4,5,8,9,10 python3 -u research/lab/coordinator.py   # 노드 Ready 감지→배포→블록 배정 (로그: lab/coordinator.log)
```
- 스키마: `lab/episode_driver.py` 각 attempt JSONL (process_crash / live_object_corruption / intrinsic_reached(대리) / GC feature). 결함은 D-2 참조.
- 이미지 digest 고정: `image-digests-2026-11-23.txt` (17.0.8 / 17.0.21 / 17.0.21.1_2).

## 분석 — `analysis/`
```bash
python3 research/analysis/analyze.py research/data/main-2026-11-23/attempts_merged.jsonl --out report.md
research/.venv/bin/python research/analysis/crosscheck.py research/data/main-2026-11-23/attempts_merged.jsonl   # scipy/sklearn 대조
```
venv 복원: `python3 -m venv research/.venv && research/.venv/bin/pip install -r research/analysis/requirements.txt` (gitignore).

## 기전 진단 — `mechanism/`
```bash
export KUBECONFIG=kube/dfirtx-dev.conf
research/mechanism/run_mech.sh methodA   # 실제 취약 빌드, Unsafe 헤더 diff (수 분)
research/mechanism/run_mech.sh buildB     # fastdebug 빌드 후 VerifyBeforeGC/AfterGC (~2h)
research/mechanism/run_mech.sh vary       # 입력 문자 A/B/Q로 length 필드 입력 의존성 (수 분)
research/mechanism/run_mech.sh varystatus
research/mechanism/run_mech.sh pull; research/mechanism/run_mech.sh teardown
```
도구 `mechanism/MechProbe.java` = OobCanary grooming + 인접 헤더 원시 읽기(Unsafe). 컴파일에
`--add-exports java.base/jdk.internal.misc=ALL-UNNAMED`, 실행에 `--add-opens …` 필요.
**범위:** 손상·GC 접촉의 관측. 값/부호 제어·OOB 읽기·코드 실행은 하지 않음.

## 데이터 — `data/`
`main-2026-11-23/`(40 episode, lane별 ep/ + attempts_merged.jsonl + analysis.md), `mechanism/out/`,
`main-2026-11-23-prepar/`·`legacy-spring-lab-2026-11-20/`(격리·보존, 분석 제외).

## 정리 체크
```bash
kubectl get ns | grep -E 'j4s-research|j4s-mech'   # 비어 있어야 함
# 'j4s'(11/18 세션 잔존)는 이 세션 자산 아님 — 손대지 않음
```
