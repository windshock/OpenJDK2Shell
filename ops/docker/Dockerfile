# H2 검증용 x86_64 환경 — Temurin 17.0.8 (취약 범위 17.0.6~17.0.21 내)
# colima(x86_64 VM)/실제 x86 호스트 양쪽에서 사용. AVX-512 호스트에서는
# VBMI fast path까지 활성화됨(에뮬레이션 환경은 brute-force 경로만).
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 ca-certificates curl && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /tmp/jdk.tgz \
      https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.8%2B7/OpenJDK17U-jdk_x64_linux_hotspot_17.0.8_7.tar.gz \
 && mkdir -p /opt/jdk && tar xzf /tmp/jdk.tgz -C /opt/jdk --strip-components=1 \
 && rm /tmp/jdk.tgz
ENV JAVA_HOME=/opt/jdk
