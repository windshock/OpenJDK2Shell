# C2 — HotSpot/문자열 UTF-8 처리 (CVE-2024-21131 클래스)

작성: 2026-11-17 (GOAL-deep-analysis 7단계 전부 실시) · 증거: results/c2_*.jsonl

## 1. 도입 시점 (실측 — 17.0.6 델타에서 문자열/UTF-8 경로 전수)
- **`8280124` "Reduce branches decoding latin-1 chars from UTF-8 encoded bytes"**
  (2022-09-13, 17.0.6 탑재): `new String(bytes, UTF_8)`의 **latin-1 fast path 분기 재작성**
  (`(b1==0xc2||b1==0xc3)` → `(b1&0xfe)==0xc2`, String.java 2곳). 비트마스크 치환 자체는
  부호확장 검산상 **동치 확인** — 결함은 이 hunk가 아니라 이 hunk가 건드린 **주변 상태기계**에
  잠복했을 가능성이 축.
- **`8297530` "Negative length on strings concatenation"** (2022-12-01, 17.0.6 탑재):
  StringConcatHelper 길이 산술 수정 + 회귀테스트 136줄 — concat 길이 오버플로 클래스의
  존재를 입증하는 마커.

## 2. 코드 형태
**순수 Java**(String.java fast path, StringConcatHelper). 배열 접근이 경계검사됨 →
이 경로의 메모리 커럽션은 형태상 비자연. 잠재 결함 등급 = 디코드 혼동(overlong/surrogate
수용 편차)·예외/DoS·논리 왜곡. RCE 9.2 직결은 비자연 — 단 신뢰경계 우회의 부품 가능성 유지.

## 3. pre-auth 도달 경로
**보편 최상**: HTTP 헤더·경로·바디의 모든 `bytes→String(UTF_8)` 변환. 사실상 전 서비스.

## 4. 공격 입력 축 (utf8 패밀리 33케이스)
꼬리 절단(2/3/4바이트 중단)·과장 인코딩(C0 80/E0 80 80/F8 5바이트)·서로게이트
(ED A0 80/ED BF BF)·U+10FFFF 초과(F4 90 80 80)·C2/C3 밀도·버퍼 끝 경계(변경 분기의
`offset+1 < sl` 조건)·경계 길이·400KB 대형.

## 5. 관측 축
① strict(CharsetDecoder REPORT) vs Python strict 오라클 ② 동일 JVM 내 strict vs lenient
(new String) 내부 정합성 ③ **힙 스트레스 팔**(-Xmx512m+SerialGC+GC 로그 — 관측축 확장).

## 6. 클러스터 실측 (DFIRtx worker-dev01, Temurin 17.0.8)
- 기본 팔: 33케이스 — **MISMATCH 0** (초기 1건은 오라클 계수 단위 교정 대상:
  Python 코드포인트 vs Java UTF-16 단위, U+10000 케이스)
- 힙 스트레스 팔 ×3회: **MISMATCH 0, Pod 생존, hs_err 없음, GC 이상 없음**

## 7. 판정
**미지지(이 입력 공간·문자/길이/예외/힙 스트레스 관측축)**. 형태론 근거(순수 Java·경계검사)로
메모리 커럽션 계열 가능성도 낮음. **최종: 패치 diff가 String.java·StringConcatHelper·
hotspot 문자열 경로를 건드리는지로 결정.**
