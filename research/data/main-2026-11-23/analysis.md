# 분석 결과 (사전등록 §5–6)

입력: research/data/main-2026-11-23/attempts_merged.jsonl · episode_class = main · 행 462 

## 실험 A — episode 단위

| arm | episode(유효) | INVALID | 크래시 | 크래시율 | 헤더 손상 OBSERVED | 생존+손상 |
|---|---|---|---|---|---|---|
| A1 | 10 | 0 | 6 | 0.60 | 0 | 0 |
| A2 | 10 | 0 | 0 | 0.00 | 0 | 0 |
| A3 | 10 | 0 | 0 | 0.00 | 0 | 0 |
| A4 | 10 | 0 | 0 | 0.00 | 0 | 0 |

| 비교 | Fisher 단측 p | Holm 보정 p |
|---|---|---|
| A1 > A2 | 0.005418 | 0.01625 |
| A1 > A3 | 0.005418 | 0.01625 |
| A1 > A4 | 0.005418 | 0.01625 |

**판정 (사전등록 §5): causal supported** (A1 크래시율 0.60)

## 실험 B — attempt 단위 예측 (A1 VALID attempt)

attempt 62, 양성(크래시) 6, episode 10

| 모델 | Brier (LOEO) |
|---|---|
| 상수(양성 비율, 참고) | 0.0874 |
| H0 점유율 단일 | 0.0930 |
| H1 GC 상태 전체 | 0.0912 |

**판정 (사전등록 §6): INCONCLUSIVE (양성 6 < 8)**

탐색적 (라벨 = 헤더 손상 OBSERVED; UNKNOWN 제외 6/62): H0 0.0000 / H1 0.0000, 양성 0

