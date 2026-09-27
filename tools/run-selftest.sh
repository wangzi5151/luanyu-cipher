#!/data/data/com.termux/files/usr/bin/bash
# 乱语加密核心自测: 编译 crypto 源码 + 自测, 运行全部断言
set -e
cd "$(dirname "$0")/.."
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
javac -encoding UTF-8 -d "$OUT" \
  app/src/main/java/com/wangzi5151/luanyucipher/crypto/CryptoCore.java \
  tools/CipherSelfTest.java
java -cp "$OUT" CipherSelfTest
