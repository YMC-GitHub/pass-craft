# Pass Craft Docker 镜像用户手册

## 镜像介绍

一个轻量级的 Docker 镜像应用，用于生成密码哈希，使用 Rust 实现。

### 可用标签
- `scratch` (1.27MB) - 基于 `alpine` 构建，在 `scratch` 上部署为运行时镜像
- ~~`alpine` (12.8MB) - 基于 `alpine` 构建，在 `alpine` 上部署为运行时镜像~~
- `latest` (1.27MB) - 使用 `scratch` 版本作为最新镜像

## 快速开始

### 1. 拉取镜像
```bash
# 从 docker.io 拉取
docker pull yemiancheng/pass-craft:latest

# 从 ghcr.io 拉取
docker pull ghcr.io/ymc-github/pass-craft:latest
```

### 2. 准备配置文件
创建 `passwords.example.md` 配置文件：
```
name:john,email:john@gmail.com,site:john.com;method:sha512,cut:8,end:+,upper-start:5
```

### 3. 运行容器
```bash
# 查看帮助信息
docker run --rm yemiancheng/pass-craft:latest --help

# 查看版本信息
docker run --rm yemiancheng/pass-craft:latest --version

# 查看平台信息
docker run --rm yemiancheng/pass-craft:latest --show-platform

# 用例1：使用文件配置
docker run --rm -v $(pwd):/app --name pass-craft yemiancheng/pass-craft:latest --file passwords.example.md --save passwords.example.md

# 用例2：使用SSLF格式配置
docker run --rm -v $(pwd):/app --name pass-craft yemiancheng/pass-craft:latest --sslf "name:john,email:john@gmail.com,site:john.com,;method:sha512,cut:8,end:+,upper-start:5"

# 用例3：使用分离参数配置
docker run --rm -v $(pwd):/app --name pass-craft yemiancheng/pass-craft:latest --text "name:john,email:john@gmail.com,site:john.com" --hash "method:sha512,cut:8,end:+,upper-start:5"
```

#### 运行时日志示例
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

## 技术支持

如果遇到问题，请向项目仓库提交 Issue：
[https://github.com/ymc-github/pass-craft](https://github.com/ymc-github/pass-craft)

## 许可证

MIT OR Apache-2.0