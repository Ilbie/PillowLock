<p align="center">
  <img src="assets/branding/logo.png" alt="PillowLock logo" width="88" />
</p>

<h1 align="center">PillowLock</h1>

<p align="center">
  Layered file protection for desktop.
</p>

<p align="center">
  Protect files into <code>.plock</code> files and restore them later with the right password.
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

## About

PillowLock is a desktop app for protecting and restoring files with a clean Windows UI built in Rust.

It supports password-based protection, an optional extra key file, multiple security profiles, batch queue workflows, and Windows release packaging.

> This is my first project written in Rust. I built it because I needed it myself, so some parts of the code may still look rough, messy, or unusual. Please keep that in mind when reading the codebase.
>
> If you find a bug, notice a problem, or want a feature, please open an issue or send a pull request.

## Highlights

- Protect a regular file into a `.plock` file
- Restore a `.plock` file back into a normal file
- AES-256-GCM authenticated encryption
- Argon2id-based password key derivation
- Optional key file support
- Balanced and Hardened protection profiles
- Batch queue for multiple files
- English-first UI with Korean support
- In-app update support for release builds

## Tech Stack

- Rust 2021
- Slint
- AES-GCM
- Argon2id
- HKDF / SHA-512
- Zeroize

## Build

```bash
cargo build --release
```

Run in development:

```bash
cargo run
```

Run tests:

```bash
cargo test
```

Windows release binary:

```text
target\release\pillowlock.exe
```

## Disclaimer

- PillowLock is provided as-is, without any warranty.
- I make no guarantee that it is free from bugs, data loss, or security issues.
- You are responsible for verifying results and keeping your own backups before using it on important files.
- Use it at your own risk.

## Notes

- PillowLock is a practical personal project, not a certified security product.
- Original files are not deleted automatically.
- Overwrite is blocked by default.
- If you use a key file, keep a backup in a separate safe place.
- Losing the password or required key file can make recovery impossible.
