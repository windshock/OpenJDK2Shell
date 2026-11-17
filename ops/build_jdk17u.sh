#!/bin/bash
# In-pod build + canary: vulnerable (17.0.21.0.3) vs patched (17.0.21.1) from public jdk17u
set -ex
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git build-essential autoconf zip unzip file cpio \
  libx11-dev libxext-dev libxrender-dev libxrandr-dev libxi-dev libxt-dev libxtst-dev \
  libcups2-dev libfontconfig1-dev libasound2-dev >/dev/null

run_canary() {
  local JDK="$1" TAG="$2"
  echo "══════════ CANARY ($TAG) ══════════"
  "$JDK/bin/java" -XX:+PrintFlagsFinal -version 2>&1 | grep -i base64 || true
  "$JDK/bin/java" -XX:+UnlockExperimentalVMOptions -Xms1g -Xmx3g -XX:G1HeapRegionSize=1m \
    -XX:G1MaxNewSizePercent=5 -Xlog:gc:file=/tmp/gc_$TAG.log -XX:+PrintCompilation \
    -cp /v/oob.jar OobCanary gap pad2 140 /tmp/gc_$TAG.log || true
  echo "══════════ CANARY END ($TAG) ══════════"
}

for TAG in jdk-17.0.21.0.3-ga jdk-17.0.21.1-ga; do
  rm -rf /build/src
  git clone --depth 1 --branch "$TAG" https://github.com/openjdk/jdk17u.git /build/src
  cd /build/src
  bash configure --with-boot-jdk=/opt/java/openjdk --with-debug-level=release \
    --with-native-debug-symbols=none --disable-warnings-as-errors \
    --with-conf-name="$TAG" 2>&1 | tail -20
  make images CONF_NAME="$TAG" JOBS=6 2>&1 | tail -8
  run_canary "/build/src/build/$TAG/images/jdk" "$TAG"
done
echo "BUILD-AND-CANARY DONE"
