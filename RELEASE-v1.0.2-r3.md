# 실용음악위원회 v1.0.2 · macOS modern hotfix r3

정식 조직명: **인천학원연합회 음악분과 실용음악위원회**  
앱 표시명: **실용음악위원회**

## macOS modern hotfix
- macOS 26 / Apple Silicon에서 한글 내부 bundle/helper 이름의 NFC/NFD 정규화 차이로 앱이 즉시 종료되던 문제를 수정했습니다.
- macOS 내부 bundle/executable/helper 기준 이름은 `IncheonAcademyOS`로 고정합니다.
- 사용자에게 보이는 `CFBundleDisplayName`과 앱 창 제목은 계속 **실용음악위원회**입니다.
- Electron 44.5.0, macOS 13+ Universal(x86_64 + arm64) 채널입니다.
- Windows 및 macOS Mojave 공개 파일은 기존 v1.0.2 릴리스를 그대로 유지합니다.

## 검증
- Product main: `4e60654968ca83402434486ebc0d52753e55798a`
- macOS 26 ARM64 targeted build/startup 검증 통과
- Apple M5 실기기 실행 확인
- 이 릴리스는 macOS modern hotfix 파일만 별도 태그로 게시하며 기존 v1.0.2 자산을 덮어쓰지 않습니다.

> Apple Developer ID/notarization 전 빌드이므로 Gatekeeper 경고가 표시될 수 있습니다.
