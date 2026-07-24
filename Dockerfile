# ============================================================
# 第一阶段：编译 relay（静态链接）
# ============================================================
FROM alpine:3.20 AS builder

RUN apk add --no-cache gcc musl-dev openssl-dev openssl-libs-static

WORKDIR /build
COPY relay.c .

# 静态编译，并指定库路径（若需要）
RUN gcc -O2 -Wall -static -o relay relay.c -lssl -lcrypto

# ============================================================
# 第二阶段：运行时镜像
# ============================================================
FROM alpine:3.20

RUN apk add --no-cache ca-certificates

ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ]; then \
        CLOUDARCH="arm64"; \
    else \
        CLOUDARCH="amd64"; \
    fi && \
    wget -qO /usr/local/bin/cloudflared \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CLOUDARCH}" && \
    chmod +x /usr/local/bin/cloudflared

COPY --from=builder /build/relay /usr/local/bin/relay

RUN adduser -D -u 1000 relayuser
USER relayuser

WORKDIR /app

EXPOSE 7860 8001

CMD ["relay"]
