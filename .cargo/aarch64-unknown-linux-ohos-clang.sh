#!/bin/sh

exec ${OHOS_NDK_HOME}/native/llvm/bin/clang \
  -target aarch64-linux-ohos \
  --sysroot=${OHOS_NDK_HOME}/native/sysroot \
  -D__MUSL__ \
  "$@"
