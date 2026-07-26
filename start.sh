#!/bin/sh
set -e

# ============================================================
# 环境变量默认值
# ============================================================
ARGO_PORT=${ARGO_PORT:-8001}
ARGO_DOMAIN=${ARGO_DOMAIN:-"gocfvps.rboya.indevs.in"}
ARGO_AUTH=${ARGO_AUTH:-"eyJhIjoiNWRmNTFlZjhhMTNiMWQ1ZDFhODhhZTAxNWFmYTU5OGIiLCJ0IjoiOTBlYWNkYmYtODE1ZS00N2JjLWJhNTAtOGQ0NjIzMWY1N2UwIiwicyI6Ik1qazRNREF5TUdVdE5ETXhaaTAwWlRJNUxUaGxObVV0WldZeFlXWmxOemMyTmpnMyJ9"}
UUID=${UUID:-"4a0636f4-4514-47f4-87f7-2f1967289758"}
NAME=${NAME:-"C"}

# ============================================================
# 检查必填项
# ============================================================
if [ -z "$ARGO_DOMAIN" ] || [ -z "$UUID" ]; then
    echo "ERROR: ARGO_DOMAIN and UUID must be set."
    echo "  ARGO_DOMAIN: your-argo-domain.trycloudflare.com"
    echo "  UUID: your-uuid-here"
    exit 1
fi

# ============================================================
# 下载 cloudflared（如果尚未安装）
# ============================================================
if ! command -v cloudflared >/dev/null 2>&1; then
    echo "Downloading cloudflared..."
    ARCH=$(uname -m)
    case "$ARCH" in
        aarch64|arm64) CLOUDARCH="arm64" ;;
        x86_64)        CLOUDARCH="amd64" ;;
        *)             CLOUDARCH="amd64" ;;
    esac
    wget -qO /usr/local/bin/cloudflared \
        "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CLOUDARCH}"
    chmod +x /usr/local/bin/cloudflared
    echo "cloudflared downloaded to /usr/local/bin/cloudflared"
fi

# ============================================================
# 启动 relay（后台运行）
# ============================================================
echo "Starting relay on port $ARGO_PORT..."
/usr/local/bin/relay &
RELAY_PID=$!
echo "Relay PID: $RELAY_PID"

# ============================================================
# 启动 cloudflared（根据认证模式）
# ============================================================
if [ -n "$ARGO_AUTH" ]; then
    if [ ${#ARGO_AUTH} -gt 100 ]; then
        # 模式 1：Token（长字符串）
        echo "Starting cloudflared with token..."
        CLOUDARGS="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token $ARGO_AUTH"
    elif echo "$ARGO_AUTH" | grep -q "TunnelSecret"; then
        # 模式 2：JSON 配置（包含 TunnelSecret）
        echo "Starting cloudflared with JSON configuration..."
        # 提取 Tunnel ID（第一个非空字符串）
        TUNNEL_ID=$(echo "$ARGO_AUTH" | grep -o '"TunnelSecret":"[^"]*"' | cut -d'"' -f4)
        if [ -z "$TUNNEL_ID" ]; then
            echo "ERROR: Could not extract tunnel ID from ARGO_AUTH"
            exit 1
        fi
        echo "$ARGO_AUTH" > /app/tunnel.json
        cat > /app/tunnel.yml <<EOF
tunnel: $TUNNEL_ID
credentials-file: /app/tunnel.json
protocol: http2
ingress:
  - hostname: $ARGO_DOMAIN
    service: http://localhost:$ARGO_PORT
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
        CLOUDARGS="tunnel --edge-ip-version auto --config /app/tunnel.yml run"
    else
        # 模式 3：普通域名 + 无认证（仅用于测试）
        echo "Starting cloudflared with default (no auth)..."
        CLOUDARGS="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --url http://localhost:$ARGO_PORT"
    fi
else
    # 无认证（自动分配域名，不保证生效）
    echo "Starting cloudflared with auto-url (no auth)..."
    CLOUDARGS="tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --url http://localhost:$ARGO_PORT"
fi

/usr/local/bin/cloudflared $CLOUDARGS &
CLOUDFLARED_PID=$!
echo "Cloudflared PID: $CLOUDFLARED_PID"

# ============================================================
# 等待任一进程退出（保持容器存活）
# ============================================================
echo "Both services started. Waiting for termination..."
wait $RELAY_PID $CLOUDFLARED_PID
