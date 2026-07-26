FROM alpine:3.20 AS builder
RUN apk add --no-cache gcc musl-dev openssl-dev
WORKDIR /build
COPY relay.c .
RUN gcc -O2 -static -o relay relay.c -lssl -lcrypto

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
# 下载 cloudflared
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "arm64" ]; then CLOUDARCH="arm64"; else CLOUDARCH="amd64"; fi && \
    wget -qO /usr/local/bin/cloudflared \
    "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CLOUDARCH}" && \
    chmod +x /usr/local/bin/cloudflared
COPY --from=builder /build/relay /usr/local/bin/relay
RUN adduser -D -u 1000 relayuser
USER relayuser
WORKDIR /app
EXPOSE 7860
CMD ["/usr/local/bin/relay"]
