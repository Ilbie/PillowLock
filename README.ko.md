<p align="center">
  <img src="assets/branding/logo.png" alt="PillowLock logo" width="88" />
</p>

<h1 align="center">PillowLock</h1>

<p align="center">
  데스크톱용 계층형 파일 보호 앱.
</p>

<p align="center">
  일반 파일을 <code>.plock</code> 보호 파일로 만들고, 나중에 올바른 비밀번호로 다시 복원할 수 있습니다.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-2021-000000?logo=rust&logoColor=white" alt="Rust 2021" />
  <img src="https://img.shields.io/badge/UI-Slint-0f172a" alt="Slint UI" />
  <img src="https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows&logoColor=white" alt="Windows" />
  <img src="https://img.shields.io/badge/Crypto-AES--256--GCM-0057FF" alt="AES-256-GCM" />
  <img src="https://img.shields.io/badge/KDF-Argon2id-4F46E5" alt="Argon2id" />
</p>

<p align="center">
  <a href="README.md">English</a> |
  <a href="README.ko.md">한국어</a> |
  <a href="CONTRIBUTING.md">Contributing</a> |
  <a href="SECURITY.md">Security</a>
</p>

---

## 소개

PillowLock는 Rust와 Slint로 만든 데스크톱 파일 보호 앱입니다.

일반 파일을 `.plock` 보호 파일로 만들고, 나중에 올바른 비밀번호로 다시 복원할 수 있습니다. 선택적으로 키 파일을 추가해서 더 강하게 보호할 수도 있습니다.

> 이 프로젝트는 제가 Rust로 처음 만든 프로젝트입니다. 제가 필요해서 만들었고, 그래서 코드가 다소 난잡하거나 이상하게 보일 수 있습니다. 그 점은 너그럽게 이해해 주시면 감사하겠습니다.
>
> 버그나 문제점이 있거나, 원하는 기능이 있다면 이슈나 풀 리퀘스트 부탁드립니다.

## 주요 기능

- 일반 파일을 `.plock` 보호 파일로 변환
- `.plock` 보호 파일을 다시 일반 파일로 복원
- AES-256-GCM 기반 인증 암호화
- Argon2id 기반 비밀번호 키 파생
- 선택형 키 파일 지원
- 균형 / 강화 보호 프로필
- 여러 파일용 배치 큐
- 영어 기본 UI와 한국어 지원
- 릴리스 빌드용 앱 내 업데이트 지원

## 기술 스택

- Rust 2021
- Slint
- AES-GCM
- Argon2id
- HKDF / SHA-512
- Zeroize

## 빌드

```bash
cargo build --release
```

개발 모드 실행:

```bash
cargo run
```

테스트:

```bash
cargo test
```

Windows 릴리스 실행 파일:

```text
target\release\pillowlock.exe
```

## 면책

- PillowLock는 어떠한 보증도 없는 상태 그대로 제공됩니다.
- 버그, 데이터 손실, 보안 문제 등이 전혀 없다고 보장하지 않습니다.
- 중요한 파일에 사용하기 전에는 직접 결과를 확인하고, 반드시 별도 백업을 유지해 주세요.
- 사용에 따른 책임은 사용자 본인에게 있습니다.

## 참고

- PillowLock는 실용적인 개인 프로젝트이며, 인증된 보안 제품은 아닙니다.
- 원본 파일은 자동 삭제되지 않습니다.
- 기본적으로 덮어쓰기를 막습니다.
- 키 파일을 사용한다면 별도 안전한 위치에 백업해 두는 것을 권장합니다.
- 비밀번호나 필요한 키 파일을 잃어버리면 복구가 어려울 수 있습니다.
