#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <libwebsockets.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

// ============================================================
// 配置
// ============================================================
typedef struct {
    int port;
    char uuid[37];
    char argo_domain[256];
    char argo_auth[512];
    char name[64];
} Config;
static Config g_config;

static void init_config_from_env(void) {
    memset(&g_config, 0, sizeof(g_config));
    const char *v;

    v = getenv("ARGO_PORT");
    g_config.port = v ? atoi(v) : 8001;

    v = getenv("UUID");
    if (v) strncpy(g_config.uuid, v, sizeof(g_config.uuid)-1);

    v = getenv("ARGO_DOMAIN");
    if (v) strncpy(g_config.argo_domain, v, sizeof(g_config.argo_domain)-1);

    v = getenv("ARGO_AUTH");
    if (v) strncpy(g_config.argo_auth, v, sizeof(g_config.argo_auth)-1);

    v = getenv("NAME");
    if (v) strncpy(g_config.name, v, sizeof(g_config.name)-1);
}

static int validate_config(void) {
    if (g_config.port <= 0) {
        fprintf(stderr, "ERROR: ARGO_PORT must be set and >0\n");
        return 0;
    }
    if (strlen(g_config.uuid) != 36) {
        fprintf(stderr, "ERROR: UUID must be 36 chars\n");
        return 0;
    }
    if (g_config.argo_domain[0] == '\0') {
        fprintf(stderr, "ERROR: ARGO_DOMAIN must be set\n");
        return 0;
    }
    return 1;
}

// ============================================================
// 加密准备
// ============================================================
static unsigned char g_uuid_bin[16];
static char g_trojan_password[57];

static void prepare_crypto(void) {
    int k = 0;
    for (int i = 0; i < 16; i++) {
        char hex[3] = {g_config.uuid[k], g_config.uuid[k+1], 0};
        g_uuid_bin[i] = strtol(hex, NULL, 16);
        k += 2;
        if (g_config.uuid[k] == '-') k++;
    }
    unsigned char hash[SHA224_DIGEST_LENGTH];
    SHA224(g_uuid_bin, 16, hash);
    for (int i = 0; i < SHA224_DIGEST_LENGTH; i++)
        sprintf(g_trojan_password + i*2, "%02x", hash[i]);
    g_trojan_password[56] = '\0';
}

// ============================================================
// VLESS 首包解析
// ============================================================
static int parse_vless(const unsigned char *data, size_t len,
                       char *host, size_t host_size, uint16_t *port,
                       const unsigned char **payload, size_t *payload_len) {
    if (len < 18) return -1;
    if (memcmp(data+1, g_uuid_bin, 16) != 0) return -1;
    unsigned char opt_len = data[17];
    size_t cmd_idx = 18 + opt_len;
    if (len < cmd_idx + 1) return -1;
    unsigned char cmd = data[cmd_idx];
    if (cmd != 1) return -1; // TCP only
    size_t port_idx = cmd_idx + 1;
    if (len < port_idx + 3) return -1;
    *port = (data[port_idx] << 8) | data[port_idx+1];
    unsigned char addr_type = data[port_idx+2];
    size_t addr_start = port_idx + 3;
    if (addr_type == 1) { // IPv4
        if (len < addr_start + 4) return -1;
        snprintf(host, host_size, "%d.%d.%d.%d",
                 data[addr_start], data[addr_start+1], data[addr_start+2], data[addr_start+3]);
        addr_start += 4;
    } else if (addr_type == 2) { // Domain
        if (len < addr_start + 1) return -1;
        unsigned char domain_len = data[addr_start];
        if (len < addr_start + 1 + domain_len) return -1;
        if (domain_len >= host_size) return -1;
        memcpy(host, data+addr_start+1, domain_len);
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

// ============================================================
// Trojan 首包解析
// ============================================================
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
    unsigned char atype = data[offset+1];
    size_t cursor = offset + 2;
    char addr_str[256];
    if (atype == 1) { // IPv4
        if (len < cursor + 4) return -1;
        snprintf(addr_str, sizeof(addr_str), "%d.%d.%d.%d",
                 data[cursor], data[cursor+1], data[cursor+2], data[cursor+3]);
        cursor += 4;
    } else if (atype == 3) { // Domain
        if (len < cursor + 1) return -1;
        unsigned char domain_len = data[cursor];
        if (len < cursor + 1 + domain_len) return -1;
        if (domain_len >= host_size) return -1;
        memcpy(addr_str, data+cursor+1, domain_len);
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
    *port = (data[cursor] << 8) | data[cursor+1];
    if (data[cursor+2] != 0x0d || data[cursor+3] != 0x0a) return -1;
    strncpy(host, addr_str, host_size-1);
    host[host_size-1] = '\0';
    *payload = data + cursor + 4;
    *payload_len = len - (cursor + 4);
    return 0;
}

// ============================================================
// 工具函数
// ============================================================
static void set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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
// 会话管理
// ============================================================
struct per_session_data {
    int target_fd;
    int is_first;
    unsigned char *buffer;
    size_t buf_len;
    struct lws *wsi;
};

#define MAX_SESSIONS 1024
static struct per_session_data *all_sessions[MAX_SESSIONS];
static int session_count = 0;

static void add_session(struct per_session_data *pss) {
    if (session_count < MAX_SESSIONS)
        all_sessions[session_count++] = pss;
}

static void remove_session(struct per_session_data *pss) {
    for (int i = 0; i < session_count; i++) {
        if (all_sessions[i] == pss) {
            all_sessions[i] = all_sessions[--session_count];
            break;
        }
    }
}

// ============================================================
// 数据转发
// ============================================================
static void send_to_target(struct per_session_data *pss, const unsigned char *data, size_t len) {
    if (pss->target_fd < 0) return;
    ssize_t sent = send(pss->target_fd, data, len, MSG_NOSIGNAL);
    if (sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        lws_close_reason(pss->wsi, LWS_CLOSE_STATUS_ABNORMAL, NULL, 0);
    }
}

static void read_from_target(struct per_session_data *pss) {
    unsigned char buf[4096];
    ssize_t n;
    while ((n = recv(pss->target_fd, buf, sizeof(buf), MSG_DONTWAIT)) > 0) {
        unsigned char *p = buf;
        size_t remaining = n;
        while (remaining) {
            int sent = lws_write(pss->wsi, p, remaining, LWS_WRITE_BINARY);
            if (sent < 0) {
                lws_close_reason(pss->wsi, LWS_CLOSE_STATUS_ABNORMAL, NULL, 0);
                return;
            }
            p += sent;
            remaining -= sent;
        }
    }
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
        lws_close_reason(pss->wsi, LWS_CLOSE_STATUS_NORMAL, NULL, 0);
    }
}

// ============================================================
// 订阅生成
// ============================================================
static void generate_subscription(char *out, size_t out_size) {
    if (g_config.argo_domain[0] == '\0') {
        snprintf(out, out_size, "ERROR: ARGO_DOMAIN not set");
        return;
    }
    char vless[512], trojan[512], vmess[512], vmess_json[512];
    char node_prefix[64];
    snprintf(node_prefix, sizeof(node_prefix), "%s", g_config.name[0] ? g_config.name : "C");

    snprintf(vless, sizeof(vless),
             "vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=/vless-argo#%s_VLESS",
             g_config.uuid, g_config.argo_domain, g_config.argo_domain, g_config.argo_domain, node_prefix);
    snprintf(trojan, sizeof(trojan),
             "trojan://%s@%s:443?security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=/trojan-argo#%s_Trojan",
             g_config.uuid, g_config.argo_domain, g_config.argo_domain, g_config.argo_domain, node_prefix);
    snprintf(vmess_json, sizeof(vmess_json),
             "{\"v\":\"2\",\"ps\":\"%s_VMess\",\"add\":\"%s\",\"port\":443,\"id\":\"%s\",\"aid\":\"0\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"%s\",\"path\":\"/vless-argo?ed=2560\",\"tls\":\"tls\",\"sni\":\"%s\",\"fp\":\"firefox\"}",
             node_prefix, g_config.argo_domain, g_config.uuid, g_config.argo_domain, g_config.argo_domain);

    // Base64 编码 vmess_json
    BIO *b64, *bio;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    BIO_push(b64, bio);
    BIO_write(b64, vmess_json, strlen(vmess_json));
    BIO_flush(b64);
    BIO_get_mem_ptr(bio, &bptr);
    char *encoded = malloc(bptr->length + 1);
    memcpy(encoded, bptr->data, bptr->length);
    encoded[bptr->length] = '\0';
    BIO_free_all(b64);
    snprintf(vmess, sizeof(vmess), "vmess://%s", encoded);
    free(encoded);

    char plain[2048];
    snprintf(plain, sizeof(plain), "%s\n%s\n%s\n", vless, trojan, vmess);

    // Base64 整个订阅
    BIO *b64_all, *bio_all;
    BUF_MEM *bptr_all;
    b64_all = BIO_new(BIO_f_base64());
    bio_all = BIO_new(BIO_s_mem());
    BIO_set_flags(b64_all, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64_all, bio_all);
    BIO_write(b64_all, plain, strlen(plain));
    BIO_flush(b64_all);
    BIO_get_mem_ptr(bio_all, &bptr_all);
    size_t b64_len = bptr_all->length;
    if (b64_len < out_size) {
        memcpy(out, bptr_all->data, b64_len);
        out[b64_len] = '\0';
    } else {
        out[0] = '\0';
    }
    BIO_free_all(b64_all);
}

// ============================================================
// HTTP 回调
// ============================================================
static int callback_http(struct lws *wsi, enum lws_callback_reasons reason,
                         void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_HTTP: {
            const char *uri = lws_get_url_path_start(wsi);
            if (strcmp(uri, "/sub") == 0) {
                char sub_buf[4096];
                generate_subscription(sub_buf, sizeof(sub_buf));
                lws_write(wsi, (unsigned char*)sub_buf, strlen(sub_buf), LWS_WRITE_HTTP);
            } else {
                const char *msg = "<html><body>VLESS+WS Server running.<br>Subscribe: /sub</body></html>";
                lws_write(wsi, (unsigned char*)msg, strlen(msg), LWS_WRITE_HTTP);
            }
            return 0;
        }
        default:
            break;
    }
    return 0;
}

// ============================================================
// WebSocket 回调（含路径校验）
// ============================================================
static int callback_vless_ws(struct lws *wsi, enum lws_callback_reasons reason,
                             void *user, void *in, size_t len) {
    struct per_session_data *pss = (struct per_session_data *)user;
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: {
            // 只接受特定路径
            const char *uri = lws_get_url_path_start(wsi);
            if (strcmp(uri, "/vless-argo") != 0 && strcmp(uri, "/trojan-argo") != 0) {
                lws_close_reason(wsi, LWS_CLOSE_STATUS_POLICY_VIOLATION, NULL, 0);
                return -1;
            }
            pss->target_fd = -1;
            pss->is_first = 1;
            pss->buffer = malloc(8192);
            pss->buf_len = 0;
            pss->wsi = wsi;
            add_session(pss);
            break;
        }
        case LWS_CALLBACK_RECEIVE: {
            unsigned char *data = (unsigned char *)in;
            size_t data_len = len;
            if (pss->is_first) {
                if (pss->buf_len + data_len > 8192) {
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_ABNORMAL, NULL, 0);
                    break;
                }
                memcpy(pss->buffer + pss->buf_len, data, data_len);
                pss->buf_len += data_len;

                char host[256];
                uint16_t port;
                const unsigned char *payload;
                size_t payload_len;
                int parsed = 0;
                if (parse_vless(pss->buffer, pss->buf_len, host, sizeof(host), &port, &payload, &payload_len) == 0)
                    parsed = 1;
                else if (parse_trojan(pss->buffer, pss->buf_len, host, sizeof(host), &port, &payload, &payload_len) == 0)
                    parsed = 1;
                if (!parsed) break;

                int target = connect_target(host, port);
                if (target < 0) {
                    lws_close_reason(wsi, LWS_CLOSE_STATUS_ABNORMAL, NULL, 0);
                    break;
                }
                pss->target_fd = target;
                set_nonblock(target);
                if (payload_len > 0)
                    send_to_target(pss, payload, payload_len);
                pss->is_first = 0;
                free(pss->buffer);
                pss->buffer = NULL;
                lws_callback_on_writable(wsi);
            } else {
                send_to_target(pss, data, data_len);
            }
            break;
        }
        case LWS_CALLBACK_WRITEABLE:
            if (pss->target_fd >= 0 && !pss->is_first)
                read_from_target(pss);
            break;
        case LWS_CALLBACK_CLOSED:
        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE:
            if (pss->target_fd >= 0) close(pss->target_fd);
            if (pss->buffer) free(pss->buffer);
            remove_session(pss);
            break;
        default:
            break;
    }
    return 0;
}

// ============================================================
// 协议数组
// ============================================================
static struct lws_protocols protocols[] = {
    { "http", callback_http, 0, 0 },
    { "vless-ws", callback_vless_ws, sizeof(struct per_session_data), 8192 },
    { NULL, NULL, 0, 0 }
};

// ============================================================
// 主循环（含 poll 检查目标 fd）
// ============================================================
static void service_loop(struct lws_context *context) {
    while (1) {
        lws_service(context, 50);

        // 轮询所有会话的目标 fd，若有数据则触发写回调
        if (session_count > 0) {
            struct pollfd fds[MAX_SESSIONS];
            struct per_session_data *sessions[MAX_SESSIONS];
            int n = 0;
            for (int i = 0; i < session_count; i++) {
                struct per_session_data *pss = all_sessions[i];
                if (pss && pss->target_fd >= 0 && !pss->is_first) {
                    fds[n].fd = pss->target_fd;
                    fds[n].events = POLLIN;
                    sessions[n] = pss;
                    n++;
                }
            }
            if (n > 0) {
                int ret = poll(fds, n, 0);
                if (ret > 0) {
                    for (int i = 0; i < n; i++) {
                        if (fds[i].revents & POLLIN)
                            lws_callback_on_writable(sessions[i]->wsi);
                    }
                }
            }
        }
    }
}

// ============================================================
// main
// ============================================================
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    init_config_from_env();
    if (!validate_config()) {
        fprintf(stderr, "Configuration validation failed.\n");
        return 1;
    }
    prepare_crypto();

    struct lws_context_creation_info info = {0};
    info.port = g_config.port;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;

    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "Failed to create lws context\n");
        return 1;
    }

    printf("VLESS+WS Server started:\n");
    printf("  Port: %d\n", g_config.port);
    printf("  UUID: %s\n", g_config.uuid);
    printf("  Argo Domain: %s\n", g_config.argo_domain);

    service_loop(context);

    lws_context_destroy(context);
    return 0;
}
