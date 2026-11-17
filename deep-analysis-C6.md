# C6 — 데스크톱 파서 (BMP/ICC·폰트·사운드)

작성: 2026-11-17 (diff 실측 기반)

## 1. 도입 시점 (실측 — 17.0.6 탑재)
| 커밋 | diff 실측 |
|---|---|
| 8293734 Improve BMP image handling | BMPImageReader **2줄** 변경 |
| 8295687 Better BMP bounds | BMPImageReader **16+/74-** — 경계 처리 코드 대량 '감소'(단순화) |
| 8288516 Enhance font creation | **Windows 전용 네이티브**(awt_Font.cpp·fontpath.c·lcdglyph.c) |

## 2. 코드 형태
- BMP: **순수 Java** (javax.imageio) — 경계검사 됨, 커럽션 형태 아님.
- 폰트: 네이티브이나 **Windows 한정** — Linux 서버 RCE 시나리오에서 도달 불가.
- 8295687의 74줄 감소는 경계 검사 제거가 아니라 중복 제거로 판독(컨텍스트상 리팩터)되나,
  C7 스윕에서 BMPImageReader 경계 이력은 재검토 대상으로 남김.

## 3. pre-auth 도달 경로
이미지/폰트 업로드를 받는 서비스로부터 도달 가능하나 **애플리케이션 의존**(파일 업로드
전제) — 보편 pre-auth 아님.

## 7. 판정
**미지지(형태·플랫폼·도달 전제)**. Linux 서버 무관(폰트=Windows 전용). 패치 diff가
java.desktop/를 건드리면 확장 분석 개시.
