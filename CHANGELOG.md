# Changelog

## [Unreleased] - 2026-11-07

### 安全
- `CryptoCore` 的 `dk` 在加密/解密成功与异常路径均通过 `finally` 清零，避免异常分支残留密钥材料。
- 多密钥链式推导 `deriveKeyMulti` 在异常时清零已推导的中间密钥，并清除 `K(i-1)‖salt` 拼接缓冲。

### 测试
- 新增 JUnit 测试 `CryptoCoreTest`，覆盖 v2 单把/十把往返、错误密钥与顺序、密钥数量/长度边界、密文截断、最小帧和帧头 `n` 损坏。
- 自测脚本新增 v2 截断/边界/错误密钥用例，断言数从 82 增至 92。

### 构建与 CI
- `tools/run-selftest.sh` shebang 改为 `#!/usr/bin/env bash`，可在非 Termux 环境直接运行。
- 新增 GitHub Actions：运行自测脚本（结果写入 job summary 并上传日志）和 JUnit 单元测试。

### 文档
- README 补充密钥材料清零说明、JUnit 测试命令与项目结构。
- 新增本 CHANGELOG。

## [1.1.0] - 2026-09-27

### 新增
- 高级模式 Luanyu v2：最多 10 把密钥链式推导，顺序敏感、缺一不可。
- 多密钥组合空间估算与展示。
- 自动识别 v1/v2 密文，兼容旧版单密钥密文。

## [1.0.0] - 2026-09-26

### 新增
- Luanyu v1 单密钥认证加密：PBKDF2-HMAC-SHA256 + AES-256-GCM。
- 乱序 64 符号字母表编码，支持聊天软件中的换行/空白容错。
- 零权限、无网络、密钥不落盘的 Android 原生实现。
