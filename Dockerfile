# ============================================================
# 第一阶段：编译 relay（静态链接，减小依赖）
# ============================================================
FROM alpine:3.20 AS builder

RUN apk add --no-cache gcc musl-dev openssl-dev

WORKDIR /build
COPY relay.c .

# 静态编译（无需运行时 OpenSSL 动态库）
RUN gcc -O2 -Wall -static -o relay relay.c -lssl -lcrypto

# ============================================================
# 第二阶段：运行时镜像
# ============================================================
FROM alpine:3.20

# 安装 ca-certificates（用于 cloudflared HTTPS 连接）
RUN apk add --no-cache ca-certificates

# 安装 cloudflared（根据架构自动选择）
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        CLOUDARCH="arm64"; \
    else \
        CLOUDARCH="amd64"; \
    fi && \
    wget -qO /usr/local/bin/cloudflared \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CLOUDARCH}" && \
    chmod +x /usr/local/bin/cloudflared

# 复制编译好的 relay
COPY --from=builder /build/relay /usr/local/bin/relay

# 创建非 root 用户（提高安全性）
RUN adduser -D -u 1000 relayuser
USER relayuser

WORKDIR /app

# 环境变量默认值（可通过 docker run -e 覆盖）
ENV UUID=00000000-0000-4000-8000-000000000000 \
    CFIP=cdns.doon.eu.org \
    CFPORT=443
    ARGO_PORT=8001
    RELAY_PORT=7860
    ARGO_AUTH=
    ARGO_DOMAIN=

# 暴露端口：
#   ARGO_PORT   - 代理端口（cloudflared 转发目标）
#   RELAY_PORT  - HTTP 订阅端口
EXPOSE 7860 3000

CMD ["relay"]
