
# Pass Craft Docker Image User Manual

## Image Introduction

A lightweight Docker image application that password hash generationin Rust.

### Available Tags
- `scratch` (1.27MB) - Built on `alpine` and deployed on `scratch` as runtime image
- ~~`alpine` (12.8MB) - Built on `alpine` and deployed on `alpine` as runtime image~~
- `latest` (1.27MB) - Uses `scratch` version as latest image

## Quick Start

### 1. Pull Image
```bash
# from docker.io
docker pull yemiancheng/pass-craft:latest

# from ghcr.io
docker pull ghcr.io/ymc-github/pass-craft:latest
```

### 2. Run Container
```bash
# docker run --rm yemiancheng/pass-craft:latest --help
# docker run --rm yemiancheng/pass-craft:latest --version
# docker run --rm yemiancheng/pass-craft:latest --show-platform
# uc-1 
docker run --rm -v $(pwd):/app --name pass-craft  yemiancheng/pass-craft:latest --file passwords.example.md --save passwords.example.md

# uc-2
docker run --rm -v $(pwd):/app --name pass-craft  --sslf "name:john,email:john@gmail.com,site:john.com;method:sha512,cut:8,end:+,upper-start:5" 

# uc-3
docker run --rm -v $(pwd):/app --name pass-craft  --text "name:john,email:john@gmail.com,site:john.com" --hash "method:sha512,cut:8,end:+,upper-start:5" 

```

#### Runtime Log Example
```bash
# ./pass-craft --sslf "name:john,email:john@gmail.com,site:john.com,;method:sha512,cut:8,end:+,upper-start:5" 
==============Current Configuration==============
✅ Platform: linux-x86_64
✅ Algorithm: sha512
✅ User: john
✅ Site: john.com
✅ Format: 8 chars, end with '+', first 5 uppercase
-------------Generating Password Hash-------------
ℹ️ 2025-10-20 13:44:05 - Base text: john,john@gmail.com,john.com
ℹ️ 2025-10-20 13:44:05 - Raw sha512 hash: b5cb3043cd6b756e5260804c3c6a492a5a7e3c53a97f202307b5d0d76275aaf3dbeb5d58a284ca96b301e4a5d014f120ad75c9ee9ee2adb810606df97c12c5d1
ℹ️ 2025-10-20 13:44:05 - Truncated to 8 chars: b5cb3043
ℹ️ 2025-10-20 13:44:05 - Added end character '+'
ℹ️ 2025-10-20 13:44:05 - First 5 characters uppercased
✅ 2025-10-20 13:44:05 - Final result: john,B5CB304+,john.com
===========Password Generation Complete===========
✅ 2025-10-20 13:44:05 - Generated Password: john,B5CB304+,john.com
```

## Technical Support
If you encounter issues, please submit an Issue to the project repository:
[https://github.com/ymc-github/pass-craft](https://github.com/ymc-github/pass-craft)

## License
MIT OR Apache-2.0
