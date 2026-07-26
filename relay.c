#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <signal.h>
#include <sys/wait.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

// ============================================================
// 配置常量
// ============================================================
#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192      // 增大缓冲区，适配大帧
#define UUID_LEN 36
#define CLOUDFLARED_PATH_DEFAULT "/usr/local/bin/cloudflared"

static char g_uuid[UUID_LEN + 1] = "4a0636f4-4514-47f4-87f7-2f1967289758";
static unsigned char g_uuid_bin[16];
static char g_trojan_password[57];
static char g_argo_domain[256] = "gocfvps.rboya.indevs.in";
static int g_port = 7860;
static char g_name[64] = "C";
static char g_argo_auth[2048] = "eyJhIjoiNWRmNTFlZjhhMTNiMWQ1ZDFhODhhZTAxNWFmYTU5OGIiLCJ0IjoiOTBlYWNkYmYtODE1ZS00N2JjLWJhNTAtOGQ0NjIzMWY1N2UwIiwicyI6Ik1qazRNREF5TUdVdE5ETXhaaTAwWlRJNUxUaGxObVV0WldZeFlXWmxOemMyTmpnMyJ9";   // 扩大缓冲区，容纳长 Token
static char g_cloudflared_path[256] = CLOUDFLARED_PATH_DEFAULT;

// ============================================================
// 工具函数
// ============================================================
static void uuid_to_bin(const char *uuid, unsigned char *bin) {
    int k = 0;
    for (int i = 0; i < 16; i++) {
        char hex[3] = {uuid[k], uuid[k + 1], 0};
        bin[i] = strtol(hex, NULL, 16);
        k += 2;
        if (uuid[k] == '-') k++;
    }
}

static void compute_trojan_password(const unsigned char *bin) {
    unsigned char hash[SHA224_DIGEST_LENGTH];
    SHA224(bin, 16, hash);
    for (int i = 0; i < SHA224_DIGEST_LENGTH; i++)
        sprintf(g_trojan_password + i * 2, "%02x", hash[i]);
    g_trojan_password[56] = '\0';
}

static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int create_tcp_server(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    if (listen(fd, 128) < 0) { close(fd); return -1; }
    set_nonblock(fd);
    return fd;
}

static int connect_target(const char *host, uint16_t port) {
    struct addrinfo hints, *res, *p;
    int sock;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;
    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) break;
        close(sock);
    }
    freeaddrinfo(res);
    return (p == NULL) ? -1 : sock;
}

// ============================================================
// VLESS/Trojan 首包解析（与之前一致）
// ============================================================
static int parse_vless(const unsigned char *data, size_t len,
                       char *host, size_t host_size, uint16_t *port,
                       const unsigned char **payload, size_t *payload_len) {
    if (len < 18) return -1;
    if (memcmp(data + 1, g_uuid_bin, 16) != 0) return -1;
    unsigned char opt_len = data[17];
    size_t cmd_idx = 18 + opt_len;
    if (len < cmd_idx + 1) return -1;
    unsigned char cmd = data[cmd_idx];
    if (cmd != 1) return -1;  // TCP only
    size_t port_idx = cmd_idx + 1;
    if (len < port_idx + 3) return -1;
    *port = (data[port_idx] << 8) | data[port_idx + 1];
    unsigned char addr_type = data[port_idx + 2];
    size_t addr_start = port_idx + 3;
    if (addr_type == 1) { // IPv4
        if (len < addr_start + 4) return -1;
        snprintf(host, host_size, "%d.%d.%d.%d",
                 data[addr_start], data[addr_start + 1], data[addr_start + 2], data[addr_start + 3]);
        addr_start += 4;
    } else if (addr_type == 2) { // Domain
        if (len < addr_start + 1) return -1;
        unsigned char domain_len = data[addr_start];
        if (len < addr_start + 1 + domain_len) return -1;
        if (domain_len >= host_size) return -1;
        memcpy(host, data + addr_start + 1, domain_len);
        host[domain_len] = '\0';
        addr_start += 1 + domain_len;
    } else if (addr_type == 3) { // IPv6
        if (len < addr_start + 16) return -1;
        const unsigned char *ip6 = data + addr_start;
        snprintf(host, host_size,
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7],
                 ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15]);
        addr_start += 16;
    } else return -1;
    *payload = data + addr_start;
    *payload_len = len - addr_start;
    return 0;
}

static int parse_trojan(const unsigned char *data, size_t len,
                        char *host, size_t host_size, uint16_t *port,
                        const unsigned char **payload, size_t *payload_len) {
    if (len < 58) return -1;
    if (memcmp(data, g_trojan_password, 56) != 0) return -1;
    if (data[56] != 0x0d || data[57] != 0x0a) return -1;
    size_t offset = 58;
    if (len < offset + 2) return -1;
    unsigned char cmd = data[offset];
    if (cmd != 1) return -1;
    unsigned char atype = data[offset + 1];
    size_t cursor = offset + 2;
    char addr_str[256];
    if (atype == 1) { // IPv4
        if (len < cursor + 4) return -1;
        snprintf(addr_str, sizeof(addr_str), "%d.%d.%d.%d",
                 data[cursor], data[cursor + 1], data[cursor + 2], data[cursor + 3]);
        cursor += 4;
    } else if (atype == 3) { // Domain
        if (len < cursor + 1) return -1;
        unsigned char domain_len = data[cursor];
        if (len < cursor + 1 + domain_len) return -1;
        if (domain_len >= host_size) return -1;
        memcpy(addr_str, data + cursor + 1, domain_len);
        addr_str[domain_len] = '\0';
        cursor += 1 + domain_len;
    } else if (atype == 4) { // IPv6
        if (len < cursor + 16) return -1;
        const unsigned char *ip6 = data + cursor;
        snprintf(addr_str, sizeof(addr_str),
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7],
                 ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15]);
        cursor += 16;
    } else return -1;
    if (len < cursor + 4) return -1;
    *port = (data[cursor] << 8) | data[cursor + 1];
    if (data[cursor + 2] != 0x0d || data[cursor + 3] != 0x0a) return -1;
    strncpy(host, addr_str, host_size - 1);
    host[host_size - 1] = '\0';
    *payload = data + cursor + 4;
    *payload_len = len - (cursor + 4);
    return 0;
}

// ============================================================
// HTTP / WebSocket 协议处理
// ============================================================
typedef struct {
    char method[16];
    char path[256];
    int is_websocket;
    char ws_key[256];
    char host[256];
} HttpRequest;

static int parse_http_request(const char *buf, size_t len, HttpRequest *req) {
    memset(req, 0, sizeof(*req));
    char *line = strstr(buf, "\r\n");
    if (!line) return -1;
    *line = '\0';
    if (sscanf(buf, "%15s %255s", req->method, req->path) != 2) {
        *line = '\r'; // 恢复
        return -1;
    }
    *line = '\r'; *line = '\r'; *line++ = '\n'; *line++ = '\0';
    const char *upgrade = strstr(buf, "Upgrade:");
    const char *key = strstr(buf, "Sec-WebSocket-Key:");
    if (upgrade && strstr(upgrade, "websocket") && key) {
        req->is_websocket = 1;
        const char *p = key + 19;
        while (*p == ' ' || *p == '\t') p++;
        const char *end = strstr(p, "\r\n");
        if (end) {
            size_t klen = end - p;
            if (klen < sizeof(req->ws_key) - 1) {
                memcpy(req->ws_key, p, klen);
                req->ws_key[klen] = '\0';
            }
        }
    }
    return 0;
}

static void build_ws_handshake(const char *key, char *resp, size_t *len) {
    unsigned char sha1_out[20];
    char input[512];
    snprintf(input, sizeof(input), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    SHA1((unsigned char *)input, strlen(input), sha1_out);
    const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char accept[32];
    for (int i = 0; i < 20; i += 3) {
        uint32_t n = (sha1_out[i] << 16) | (sha1_out[i + 1] << 8) | sha1_out[i + 2];
        accept[i * 4 / 3] = b64[(n >> 18) & 0x3F];
        accept[i * 4 / 3 + 1] = b64[(n >> 12) & 0x3F];
        accept[i * 4 / 3 + 2] = (i + 1 < 20) ? b64[(n >> 6) & 0x3F] : '=';
        accept[i * 4 / 3 + 3] = (i + 2 < 20) ? b64[n & 0x3F] : '=';
    }
    accept[28] = '\0';
    *len = snprintf(resp, 4096,
                   "HTTP/1.1 101 Switching Protocols\r\n"
                   "Upgrade: websocket\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: %s\r\n\r\n",
                   accept);
}

typedef struct {
    int fin;
    int opcode;
    unsigned char mask[4];
    int mask_len;
    unsigned char *payload;
    size_t payload_len;
} WsFrame;

static int parse_ws_frame(const unsigned char *buf, size_t len, WsFrame *frame) {
    if (len < 2) return -1;
    frame->fin = (buf[0] >> 7) & 1;
    frame->opcode = buf[0] & 0x0F;
    int masked = (buf[1] >> 7) & 1;
    unsigned char payload_len = buf[1] & 0x7F;
    size_t offset = 2;
    if (payload_len == 126) {
        if (len < 4) return -1;
        payload_len = (buf[2] << 8) | buf[3];
        offset = 4;
    } else if (payload_len == 127) {
        // 超大帧（>65535），简化处理，直接拒绝
        return -1;
    }
    if (masked) {
        if (len < offset + 4) return -1;
        memcpy(frame->mask, buf + offset, 4);
        offset += 4;
        frame->mask_len = 4;
    } else {
        frame->mask_len = 0;
    }
    if (len < offset + payload_len) return -1;
    frame->payload = (unsigned char *)buf + offset;
    frame->payload_len = payload_len;
    return 0;
}

static void build_ws_frame(const unsigned char *payload, size_t len, unsigned char *out, size_t *out_len) {
    size_t head_len = 2;
    if (len > 125) head_len = 4;
    out[0] = 0x82; // FIN + binary opcode
    if (len <= 125) {
        out[1] = len & 0x7F;
    } else {
        out[1] = 126;
        out[2] = (len >> 8) & 0xFF;
        out[3] = len & 0xFF;
    }
    memcpy(out + head_len, payload, len);
    *out_len = head_len + len;
}

// ============================================================
// 订阅生成（Base64 编码）
// ============================================================
static void base64_encode(const unsigned char *in, size_t in_len, char *out, size_t out_len) {
    const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, j = 0;
    while (i < in_len && j < out_len - 4) {
        uint32_t n = in[i++] << 16;
        if (i < in_len) n |= in[i++] << 8;
        if (i < in_len) n |= in[i++];
        out[j++] = b64[(n >> 18) & 0x3F];
        out[j++] = b64[(n >> 12) & 0x3F];
        out[j++] = (i > in_len - 1) ? '=' : b64[(n >> 6) & 0x3F];
        out[j++] = (i > in_len - 2) ? '=' : b64[n & 0x3F];
    }
    out[j] = '\0';
}

static void generate_subscription(char *out, size_t out_size) {
    if (!g_argo_domain[0]) {
        snprintf(out, out_size, "ERROR: ARGO_DOMAIN not set");
        return;
    }
    char vless[512], trojan[512], vmess[512], vmess_json[512];
    snprintf(vless, sizeof(vless),
             "vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=/vless-argo#%s_VLESS",
             g_uuid, g_argo_domain, g_argo_domain, g_argo_domain, g_name);
    snprintf(trojan, sizeof(trojan),
             "trojan://%s@%s:443?security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=/trojan-argo#%s_Trojan",
             g_uuid, g_argo_domain, g_argo_domain, g_argo_domain, g_name);
    snprintf(vmess_json, sizeof(vmess_json),
             "{\"v\":\"2\",\"ps\":\"%s_VMess\",\"add\":\"%s\",\"port\":443,\"id\":\"%s\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"%s\",\"path\":\"/vless-argo?ed=2560\",\"tls\":\"tls\",\"sni\":\"%s\",\"fp\":\"firefox\"}",
             g_name, g_argo_domain, g_uuid, g_argo_domain, g_argo_domain);
    char vmess_base64[512];
    base64_encode((unsigned char *)vmess_json, strlen(vmess_json), vmess_base64, sizeof(vmess_base64));
    snprintf(vmess, sizeof(vmess), "vmess://%s", vmess_base64);

    char plain[2048];
    snprintf(plain, sizeof(plain), "%s\n%s\n%s\n", vless, trojan, vmess);
    char b64_sub[4096];
    base64_encode((unsigned char *)plain, strlen(plain), b64_sub, sizeof(b64_sub));
    snprintf(out, out_size, "%s", b64_sub);
}

// ============================================================
// 连接状态管理
// ============================================================
typedef enum { STATE_HTTP, STATE_WS_ESTABLISHED } ConnState;

typedef struct {
    int fd;
    ConnState state;
    unsigned char recv_buf[BUFFER_SIZE];
    size_t recv_len;
    int target_fd;
} Connection;

static Connection *conns[MAX_EVENTS];
static int conn_count = 0;

static void add_conn(Connection *conn) {
    if (conn_count < MAX_EVENTS) conns[conn_count++] = conn;
}

static void remove_conn(Connection *conn) {
    for (int i = 0; i < conn_count; i++) {
        if (conns[i] == conn) {
            conns[i] = conns[--conn_count];
            break;
        }
    }
}

static void close_conn(Connection *conn) {
    if (!conn) return;
    if (conn->fd > 0) close(conn->fd);
    if (conn->target_fd > 0) close(conn->target_fd);
    free(conn);
}

// ============================================================
// 数据事件处理（循环读取，处理 EAGAIN）
// ============================================================
static void handle_client_data(Connection *conn, int epoll_fd) {
    while (1) {
        ssize_t n = recv(conn->fd, conn->recv_buf + conn->recv_len,
                         BUFFER_SIZE - conn->recv_len, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break; // 无更多数据
            }
            // 错误
            close_conn(conn);
            return;
        }
        if (n == 0) {
            // 对方关闭
            close_conn(conn);
            return;
        }
        conn->recv_len += n;

        if (conn->state == STATE_HTTP) {
            // 尝试解析 HTTP 请求
            if (conn->recv_len >= 4 && memcmp(conn->recv_buf, "GET", 3) == 0) {
                HttpRequest req;
                if (parse_http_request((char *)conn->recv_buf, conn->recv_len, &req) == 0) {
                    if (req.is_websocket) {
                        char resp[512];
                        size_t resp_len;
                        build_ws_handshake(req.ws_key, resp, &resp_len);
                        send(conn->fd, resp, resp_len, 0);
                        conn->state = STATE_WS_ESTABLISHED;
                        conn->recv_len = 0;
                    } else {
                        // 普通 HTTP
                        if (strcmp(req.path, "/sub") == 0) {
                            char sub[4096];
                            generate_subscription(sub, sizeof(sub));
                            char resp[8192];
                            int len = snprintf(resp, sizeof(resp),
                                               "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s", sub);
                            send(conn->fd, resp, len, 0);
                            close_conn(conn);
                            return;
                        } else {
                            const char *msg = "HTTP/1.1 404 Not Found\r\n\r\n";
                            send(conn->fd, msg, strlen(msg), 0);
                            close_conn(conn);
                            return;
                        }
                    }
                } else {
                    // 解析失败，关闭
                    close_conn(conn);
                    return;
                }
            } else {
                // 非 GET 请求，关闭
                close_conn(conn);
                return;
            }
        } else if (conn->state == STATE_WS_ESTABLISHED) {
            // 处理 WebSocket 帧
            while (conn->recv_len > 0) {
                WsFrame frame;
                int ret = parse_ws_frame(conn->recv_buf, conn->recv_len, &frame);
                if (ret < 0) break; // 帧不完整，等待更多数据
                if (frame.opcode == 0x8) { // 关闭帧
                    close_conn(conn);
                    return;
                }
                if (frame.opcode == 0x1 || frame.opcode == 0x2) {
                    if (frame.mask_len) {
                        for (size_t i = 0; i < frame.payload_len; i++)
                            frame.payload[i] ^= frame.mask[i % 4];
                    }
                    if (!conn->target_fd) {
                        // 首包，解析 VLESS/Trojan
                        char host[256];
                        uint16_t port;
                        const unsigned char *payload;
                        size_t payload_len;
                        int parsed = 0;
                        if (parse_vless(frame.payload, frame.payload_len,
                                        host, sizeof(host), &port, &payload, &payload_len) == 0)
                            parsed = 1;
                        else if (parse_trojan(frame.payload, frame.payload_len,
                                              host, sizeof(host), &port, &payload, &payload_len) == 0)
                            parsed = 1;
                        if (!parsed) {
                            // 数据不足，继续累积（但可能永远不够，这里简单丢弃）
                            break;
                        }
                        int target = connect_target(host, port);
                        if (target < 0) {
                            close_conn(conn);
                            return;
                        }
                        conn->target_fd = target;
                        set_nonblock(target);
                        if (payload_len > 0)
                            send(conn->target_fd, payload, payload_len, 0);
                        // 将 target fd 加入 epoll
                        struct epoll_event ev;
                        ev.events = EPOLLIN | EPOLLET;
                        ev.data.ptr = conn;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn->target_fd, &ev);
                    } else {
                        // 透传数据到目标
                        send(conn->target_fd, frame.payload, frame.payload_len, 0);
                    }
                }
                size_t consumed = (const unsigned char *)frame.payload - conn->recv_buf + frame.payload_len;
                if (consumed < conn->recv_len) {
                    memmove(conn->recv_buf, conn->recv_buf + consumed, conn->recv_len - consumed);
                    conn->recv_len -= consumed;
                } else {
                    conn->recv_len = 0;
                    break;
                }
            }
        }
    }
}

static void handle_target_data(Connection *conn) {
    while (1) {
        unsigned char buf[BUFFER_SIZE];
        ssize_t n = recv(conn->target_fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            close_conn(conn);
            return;
        }
        if (n == 0) {
            close_conn(conn);
            return;
        }
        unsigned char frame[BUFFER_SIZE + 16];
        size_t frame_len;
        build_ws_frame(buf, n, frame, &frame_len);
        ssize_t sent = send(conn->fd, frame, frame_len, 0);
        if (sent < 0) {
            // 发送失败，关闭
            close_conn(conn);
            return;
        }
        // 如果发送后仍有剩余，可继续，但一次循环够用
    }
}

// ============================================================
// cloudflared 子进程管理
// ============================================================
static pid_t cloudflared_pid = 0;

static void start_cloudflared(void) {
    if (cloudflared_pid > 0) {
        kill(cloudflared_pid, SIGTERM);
        waitpid(cloudflared_pid, NULL, 0);
        cloudflared_pid = 0;
    }

    // 构建参数
    char *args[32];
    int arg_idx = 0;
    args[arg_idx++] = g_cloudflared_path;
    args[arg_idx++] = "tunnel";
    args[arg_idx++] = "--edge-ip-version";
    args[arg_idx++] = "auto";
    args[arg_idx++] = "--no-autoupdate";
    args[arg_idx++] = "--protocol";
    args[arg_idx++] = "http2";

    if (g_argo_auth[0]) {
        size_t len = strlen(g_argo_auth);
        if (len > 100) {
            // Token 模式
            args[arg_idx++] = "run";
            args[arg_idx++] = "--token";
            args[arg_idx++] = g_argo_auth;
        } else if (strstr(g_argo_auth, "TunnelSecret") != NULL) {
            // JSON 配置模式
            // 提取 tunnel ID
            char tunnel_id[64] = {0};
            char *tunnel_id_ptr = strstr(g_argo_auth, "\"TunnelSecret\":\"");
            if (tunnel_id_ptr) {
                tunnel_id_ptr += 16;
                char *end = strchr(tunnel_id_ptr, '\"');
                if (end) {
                    size_t id_len = end - tunnel_id_ptr;
                    if (id_len < sizeof(tunnel_id) - 1) {
                        strncpy(tunnel_id, tunnel_id_ptr, id_len);
                        tunnel_id[id_len] = '\0';
                    }
                }
            }
            if (!tunnel_id[0]) {
                fprintf(stderr, "Failed to extract tunnel ID from ARGO_AUTH JSON\n");
                return;
            }
            // 写入 JSON 和 YAML
            FILE *f = fopen("/app/tunnel.json", "w");
            if (f) {
                fputs(g_argo_auth, f);
                fclose(f);
            } else {
                fprintf(stderr, "Failed to write /app/tunnel.json\n");
                return;
            }
            FILE *yaml = fopen("/app/tunnel.yml", "w");
            if (yaml) {
                fprintf(yaml,
                        "tunnel: %s\n"
                        "credentials-file: /app/tunnel.json\n"
                        "protocol: http2\n"
                        "ingress:\n"
                        "  - hostname: %s\n"
                        "    service: http://localhost:%d\n"
                        "    originRequest:\n"
                        "      noTLSVerify: true\n"
                        "  - service: http_status:404\n",
                        tunnel_id, g_argo_domain, g_port);
                fclose(yaml);
            } else {
                fprintf(stderr, "Failed to write /app/tunnel.yml\n");
                return;
            }
            args[arg_idx++] = "run";
            args[arg_idx++] = "--config";
            args[arg_idx++] = "/app/tunnel.yml";
        } else {
            // 其他（视为无认证，直接指定 url）
            args[arg_idx++] = "--url";
            char url[128];
            snprintf(url, sizeof(url), "http://localhost:%d", g_port);
            args[arg_idx++] = url;
        }
    } else {
        // 无认证
        args[arg_idx++] = "--url";
        char url[128];
        snprintf(url, sizeof(url), "http://localhost:%d", g_port);
        args[arg_idx++] = url;
    }

    args[arg_idx] = NULL;

    pid_t pid = fork();
    if (pid == 0) {
        // 子进程：重定向输出
        int devnull = open("/dev/null", O_RDWR);
        if (devnull != -1) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        // 注意：在容器环境中，父进程退出时整个容器会停止，子进程也会被终止。
        // 因此不需要额外设置 PR_SET_PDEATHSIG。
        execvp(args[0], args);
        perror("execvp cloudflared");
        exit(1);
    } else if (pid > 0) {
        cloudflared_pid = pid;
        fprintf(stderr, "Started cloudflared (PID %d)\n", pid);
    } else {
        perror("fork");
    }
}

static void sigchld_handler(int sig) {
    int status;
    pid_t pid = waitpid(-1, &status, WNOHANG);
    if (pid == cloudflared_pid) {
        fprintf(stderr, "cloudflared process %d exited, restarting...\n", pid);
        cloudflared_pid = 0;
    }
}

// ============================================================
// main
// ============================================================
int main(int argc, char **argv) {
    // 读取环境变量
    const char *env_port = getenv("ARGO_PORT");
    if (env_port) g_port = atoi(env_port);
    const char *env_uuid = getenv("UUID");
    if (env_uuid) strncpy(g_uuid, env_uuid, UUID_LEN);
    const char *env_domain = getenv("ARGO_DOMAIN");
    if (env_domain) strncpy(g_argo_domain, env_domain, sizeof(g_argo_domain) - 1);
    const char *env_auth = getenv("ARGO_AUTH");
    if (env_auth) strncpy(g_argo_auth, env_auth, sizeof(g_argo_auth) - 1);
    const char *env_name = getenv("NAME");
    if (env_name) strncpy(g_name, env_name, sizeof(g_name) - 1);
    const char *env_cfpath = getenv("CLOUDFLARED_PATH");
    if (env_cfpath) strncpy(g_cloudflared_path, env_cfpath, sizeof(g_cloudflared_path) - 1);

    // 校验必要配置
    if (!g_argo_domain[0] || strlen(g_uuid) != 36) {
        fprintf(stderr, "ERROR: ARGO_DOMAIN and UUID must be set.\n");
        return 1;
    }

    uuid_to_bin(g_uuid, g_uuid_bin);
    compute_trojan_password(g_uuid_bin);

    // 信号处理
    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    // 创建监听 socket
    int listen_fd = create_tcp_server(g_port);
    if (listen_fd < 0) {
        fprintf(stderr, "Failed to bind port %d\n", g_port);
        return 1;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll"); return 1; }
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);

    // 启动 cloudflared
    start_cloudflared();

    fprintf(stderr, "VLESS+WS server on port %d, UUID=%s, Argo domain=%s\n", g_port, g_uuid, g_argo_domain);

    struct epoll_event events[MAX_EVENTS];
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        if (nfds < 0) continue;

        // 检查 cloudflared 是否运行，若退出则重启
        if (cloudflared_pid == 0) {
            start_cloudflared();
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == listen_fd) {
                struct sockaddr_in cli_addr;
                socklen_t cli_len = sizeof(cli_addr);
                int client = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
                if (client < 0) continue;
                set_nonblock(client);
                Connection *conn = calloc(1, sizeof(Connection));
                conn->fd = client;
                conn->state = STATE_HTTP;
                conn->target_fd = -1;
                ev.events = EPOLLIN | EPOLLET;
                ev.data.ptr = conn;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client, &ev);
                add_conn(conn);
            } else {
                Connection *conn = (Connection *)events[i].data.ptr;
                if (!conn) continue;
                if (events[i].events & EPOLLIN) {
                    if (conn->fd == events[i].data.fd) {
                        handle_client_data(conn, epoll_fd);
                    } else if (conn->target_fd == events[i].data.fd) {
                        handle_target_data(conn);
                    }
                }
            }
        }
    }
    return 0;
}
