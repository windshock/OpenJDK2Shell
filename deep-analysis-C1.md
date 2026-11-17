# C1 — Base64 AVX-512 decode intrinsic

작성: 2026-11-17 (GOAL-deep-analysis 템플릿 적용) · 증거: vuln-analysis §6~§9.5, exploit/results/

## 1. 도입 시점 (실측)
`8268276`(decode, 2022-11-09)·`8269404`(encode) — **jdk-17.0.6-ga 탑재 확인**.
aarch64 대응물은 GA(17.0.0)부터 존재(`8256245`) → x86만 P1(a)와 정합.

## 2. 코드 형태
**네이티브**(stubGenerator_x86_64.cpp 생성 x86 asm, ~400줄). 계약상 dst 무검사 쓰기
("no length check is possible on dst"). 메모리 커럽션 가능 형태 ✓.

## 3. pre-auth 도달 경로
Basic 인증 헤더·SASL·토큰 등 인증 전 base64 디코드 — 보편적 ✓ (P2).
발동 조건: AVX-512(vl/bw)+`UseBASE64Intrinsics`(512급 CPU 기본 on, 실측)+C2 컴파일.

## 4. 공격 입력 축
경계 길이(4/64/256/…/65536±)·패딩 위치·MIME 불법 문자·슬라이스 offset·오류 경로
(round-up)·"arbitrarily long" — 5패밀리+directed 38케이스, 총 231.

## 5. 관측 축 설계
출력 차등(on/off × Python 오라클) + hs_err 감시. **사각**: 조용한 힙 커럽션·
OOB read만으로는 출력 불변 — ASAN 빌드 미실시(선택 단계 미수행 명시).

## 6. 클러스터 실측 (DFIRtx, EPYC-Genoa avx512vbmi)
17.0.8 Pod × on/off 양팔 × 231케이스 → **MISMATCH 0/0, DIVERGENT 0, 크래시 0**
(증거: results/oj2s_genoa_{on,off}.jsonl). 선행: arm64(도구), x86 에뮬(brute-force 경로).

## 7. 판정
**미지지(이 입력 공간·출력 관측축)** — 반증에 가까우나 관측축 사각(조용한 커럽션)으로
기각 불가. 형태론적으로는 RCE 9.2와 가장 정합한 후보임은 유지.
**최종: 패치 diff가 stubGenerator_x86_64.cpp·Base64.java를 건드리는지로 결정.**
