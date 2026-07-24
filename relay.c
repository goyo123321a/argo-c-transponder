#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// ============================================================================
// 宏定义
// ============================================================================
#define MAX_EVENTS 1024
#define BUFFER_SIZE 8192

// ============================================================================
// 配置结构体与环境变量
// ============================================================================
typedef struct {
    char uuid[37];
    char cfip[64];
    char cfport[8];
    int  proxy_port;      // VLESS/Trojan 代理端口（来自 ARGO_PORT）
    int  sub_port;        // HTTP 订阅端口（来自 RELAY_PORT）
    char argo_auth[2048];
    char argo_domain[256];
    char node_name[64];
} RelayConfig;

static RelayConfig config;

static const char* get_env(const char *key, const char *default_val) {
    const char *val = getenv(key);
    return (val && val[0]) ? val : default_val;
}

static void init_config() {
    strncpy(config.uuid, get_env("UUID", "4a0636f4-4514-47f4-87f7-2f1967289758"), sizeof(config.uuid)-1);
    config.uuid[sizeof(config.uuid)-1] = '\0';
    strncpy(config.cfip, get_env("CFIP", "23.227.38.65"), sizeof(config.cfip)-1);
    config.cfip[sizeof(config.cfip)-1] = '\0';
    strncpy(config.cfport, get_env("CFPORT", "443"), sizeof(config.cfport)-1);
    config.cfport[sizeof(config.cfport)-1] = '\0';
    strncpy(config.argo_auth, get_env("ARGO_AUTH", "eyJhIjoiNWRmNTFlZjhhMTNiMWQ1ZDFhODhhZTAxNWFmYTU5OGIiLCJ0IjoiOTBlYWNkYmYtODE1ZS00N2JjLWJhNTAtOGQ0NjIzMWY1N2UwIiwicyI6Ik1qazRNREF5TUdVdE5ETXhaaTAwWlRJNUxUaGxObVV0WldZeFlXWmxOemMyTmpnMyJ9"), sizeof(config.argo_auth)-1);
    config.argo_auth[sizeof(config.argo_auth)-1] = '\0';
    strncpy(config.argo_domain, get_env("ARGO_DOMAIN", "gocfvps.rboya.indevs.in"), sizeof(config.argo_domain)-1);
    config.argo_domain[sizeof(config.argo_domain)-1] = '\0';
    strncpy(config.node_name, get_env("NAME", "Argo"), sizeof(config.node_name)-1);
    config.node_name[sizeof(config.node_name)-1] = '\0';

    const char *proxy = get_env("ARGO_PORT", "8001");
    config.proxy_port = atoi(proxy);
    if (config.proxy_port <= 0) config.proxy_port = 8001;

    const char *sub = get_env("RELAY_PORT", "7860");
    config.sub_port = atoi(sub);
    if (config.sub_port <= 0) config.sub_port = 7860;
}

// ============================================================================
// UUID 与 Trojan 密码
// ============================================================================
static unsigned char UUID_BIN[16];
static char TROJAN_PASSWORD[57];

static int parse_uuid(const char *str) {
    int i = 0, j = 0;
    while (str[i] && j < 16) {
        if (str[i] == '-') { i++; continue; }
        unsigned int byte;
        if (sscanf(str + i, "%2x", &byte) != 1) return -1;
        UUID_BIN[j++] = (unsigned char)byte;
        i += 2;
    }
    return (j == 16) ? 0 : -1;
}

static void compute_trojan_password() {
    unsigned char hash[SHA224_DIGEST_LENGTH];
    SHA224(UUID_BIN, 16, hash);
    for (int i = 0; i < SHA224_DIGEST_LENGTH; i++)
        sprintf(TROJAN_PASSWORD + 2*i, "%02x", hash[i]);
    TROJAN_PASSWORD[56] = '\0';
}

// ============================================================================
// 非阻塞工具
// ============================================================================
static int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// ============================================================================
// VLESS / Trojan 首包解析
// ============================================================================
static int parse_vless(const unsigned char *data, size_t len,
                       char *host, size_t host_size, uint16_t *port,
                       const unsigned char **payload, size_t *payload_len) {
    if (len < 18) return -1;
    if (memcmp(data+1, UUID_BIN, 16) != 0) return -1;
    unsigned char opt_len = data[17];
    size_t cmd_idx = 18 + opt_len;
    if (len < cmd_idx + 1) return -1;
    unsigned char cmd = data[cmd_idx];
    if (cmd != 1) return -1;   // only TCP
    size_t port_idx = cmd_idx + 1;
    if (len < port_idx + 3) return -1;
    *port = (data[port_idx] << 8) | data[port_idx+1];
    unsigned char addr_type = data[port_idx+2];
    size_t addr_start = port_idx + 3;
    size_t addr_len = 0;
    char addr_str[64];
    if (addr_type == 1) { // IPv4
        if (len < addr_start + 4) return -1;
        snprintf(addr_str, sizeof(addr_str), "%d.%d.%d.%d",
                 data[addr_start], data[addr_start+1], data[addr_start+2], data[addr_start+3]);
        addr_len = 4;
    } else if (addr_type == 2) { // Domain
        if (len < addr_start + 1) return -1;
        unsigned char domain_len = data[addr_start];
        if (len < addr_start + 1 + domain_len) return -1;
        if (domain_len >= sizeof(addr_str)) return -1;
        memcpy(addr_str, data+addr_start+1, domain_len);
        addr_str[domain_len] = '\0';
        addr_len = 1 + domain_len;
    } else if (addr_type == 3) { // IPv6
        if (len < addr_start + 16) return -1;
        const unsigned char *ip6 = data + addr_start;
        snprintf(addr_str, sizeof(addr_str),
                 "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                 ip6[0], ip6[1], ip6[2], ip6[3], ip6[4], ip6[5], ip6[6], ip6[7],
                 ip6[8], ip6[9], ip6[10], ip6[11], ip6[12], ip6[13], ip6[14], ip6[15]);
        addr_len = 16;
    } else {
        return -1;
    }
    snprintf(host, host_size, "%s", addr_str);
    *payload = data + addr_start + addr_len;
    *payload_len = len - (addr_start + addr_len);
    return 0;
}

static int parse_trojan(const unsigned char *data, size_t len,
                        char *host, size_t host_size, uint16_t *port,
                        const unsigned char **payload, size_t *payload_len) {
    if (len < 58) return -1;
    if (memcmp(data, TROJAN_PASSWORD, 56) != 0) return -1;
    if (data[56] != 0x0d || data[57] != 0x0a) return -1;
    size_t offset = 58;
    if (len < offset + 2) return -1;
    unsigned char cmd = data[offset];
    if (cmd != 1) return -1;
    unsigned char atype = data[offset+1];
    size_t cursor = offset + 2;
    char addr_str[64];
    if (atype == 1) { // IPv4
        if (len < cursor + 4) return -1;
        snprintf(addr_str, sizeof(addr_str), "%d.%d.%d.%d",
                 data[cursor], data[cursor+1], data[cursor+2], data[cursor+3]);
        cursor += 4;
    } else if (atype == 3) { // Domain
        if (len < cursor + 1) return -1;
        unsigned char domain_len = data[cursor];
        if (len < cursor + 1 + domain_len) return -1;
        if (domain_len >= sizeof(addr_str)) return -1;
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
    } else {
        return -1;
    }
    if (len < cursor + 4) return -1;
    *port = (data[cursor] << 8) | data[cursor+1];
    if (data[cursor+2] != 0x0d || data[cursor+3] != 0x0a) return -1;
    snprintf(host, host_size, "%s", addr_str);
    *payload = data + cursor + 4;
    *payload_len = len - (cursor + 4);
    return 0;
}

// ============================================================================
// 非阻塞连接目标（使用 epoll 等待可写）
// ============================================================================
static int connect_target_nonblock(const char *host, uint16_t port) {
    struct addrinfo hints, *res, *p;
    int sock, rv;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((rv = getaddrinfo(host, port_str, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }
    for (p = res; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (set_nonblock(sock) == -1) { close(sock); continue; }
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        } else if (errno == EINPROGRESS) {
            int epfd = epoll_create1(0);
            if (epfd == -1) { close(sock); continue; }
            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLET;
            ev.data.fd = sock;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ev) == -1) {
                close(epfd); close(sock); continue;
            }
            struct epoll_event events[1];
            int ret = epoll_wait(epfd, events, 1, 5000); // 5s timeout
            close(epfd);
            if (ret == 1 && (events[0].events & EPOLLOUT)) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                    break;
                }
            }
            close(sock);
            continue;
        }
        close(sock);
    }
    freeaddrinfo(res);
    if (p == NULL) return -1;
    return sock;
}

// ============================================================================
// 零拷贝转发（splice 循环写入）
// ============================================================================
static int splice_forward(int fd_in, int fd_out, int pipe_fd[2], int *closed) {
    ssize_t n = splice(fd_in, NULL, pipe_fd[1], NULL, 65536, SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            *closed = 1;
            return -1;
        }
        return 0;
    }
    ssize_t total = n;
    ssize_t written = 0;
    while (written < total) {
        ssize_t w = splice(pipe_fd[0], NULL, fd_out, NULL, total - written,
                           SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
        if (w <= 0) {
            if (w == -1 && errno == EAGAIN) {
                *closed = 1;
                return -1;
            }
            *closed = 1;
            return -1;
        }
        written += w;
    }
    return 0;
}

// ============================================================================
// 连接上下文及事件处理
// ============================================================================
typedef struct conn_ctx {
    int client_fd;
    int target_fd;
    int pipe_fd[2];
    int state;               // 0=首包解析, 1=转发
    char *buffer;
    size_t buf_len;
    size_t buf_cap;
} conn_ctx;

static void close_conn(conn_ctx *ctx) {
    if (!ctx) return;
    if (ctx->client_fd != -1) close(ctx->client_fd);
    if (ctx->target_fd != -1) close(ctx->target_fd);
    if (ctx->pipe_fd[0] != -1) close(ctx->pipe_fd[0]);
    if (ctx->pipe_fd[1] != -1) close(ctx->pipe_fd[1]);
    free(ctx->buffer);
    free(ctx);
}

static void handle_client_read(conn_ctx *ctx, int epoll_fd) {
    ssize_t n = recv(ctx->client_fd, ctx->buffer + ctx->buf_len,
                     ctx->buf_cap - ctx->buf_len, 0);
    if (n <= 0) { close_conn(ctx); return; }
    ctx->buf_len += n;

    char host[256];
    uint16_t port;
    const unsigned char *payload;
    size_t payload_len;
    int parsed = 0;
    if (parse_vless((unsigned char*)ctx->buffer, ctx->buf_len,
                    host, sizeof(host), &port, &payload, &payload_len) == 0) {
        parsed = 1;
    } else if (parse_trojan((unsigned char*)ctx->buffer, ctx->buf_len,
                            host, sizeof(host), &port, &payload, &payload_len) == 0) {
        parsed = 1;
    }
    if (!parsed) {
        if (ctx->buf_len >= ctx->buf_cap) close_conn(ctx);
        return;
    }

    int target_fd = connect_target_nonblock(host, port);
    if (target_fd < 0) { close_conn(ctx); return; }
    ctx->target_fd = target_fd;

    // 循环发送 payload
    const unsigned char *p = payload;
    size_t rem = payload_len;
    while (rem > 0) {
        ssize_t sent = send(target_fd, p, rem, 0);
        if (sent <= 0) {
            if (sent == -1 && errno == EAGAIN) {
                close_conn(ctx);
                return;
            }
            close_conn(ctx);
            return;
        }
        p += sent;
        rem -= sent;
    }

    ctx->state = 1;
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = ctx;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, ctx->client_fd, &ev);
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ctx->target_fd, &ev);
    free(ctx->buffer);
    ctx->buffer = NULL;
}

static void handle_forward(conn_ctx *ctx, int fd) {
    int other = (fd == ctx->client_fd) ? ctx->target_fd : ctx->client_fd;
    int closed = 0;
    if (splice_forward(fd, other, ctx->pipe_fd, &closed) < 0) closed = 1;
    if (closed) close_conn(ctx);
}

static void handle_accept(int listen_fd, int epoll_fd) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) return;
    if (set_nonblock(client_fd) == -1) { close(client_fd); return; }

    conn_ctx *ctx = calloc(1, sizeof(conn_ctx));
    if (!ctx) { close(client_fd); return; }
    ctx->client_fd = client_fd;
    ctx->target_fd = -1;
    ctx->buffer = malloc(8192);
    if (!ctx->buffer) { free(ctx); close(client_fd); return; }
    ctx->buf_cap = 8192;
    if (pipe(ctx->pipe_fd) < 0) {
        free(ctx->buffer); free(ctx); close(client_fd);
        return;
    }
    fcntl(ctx->pipe_fd[0], F_SETFL, O_NONBLOCK);
    fcntl(ctx->pipe_fd[1], F_SETFL, O_NONBLOCK);

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = ctx;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
        close_conn(ctx);
    }
}

// ============================================================================
// Base64 编码（使用 OpenSSL）
// ============================================================================
static void base64_encode(const unsigned char *input, int length, char *output) {
    EVP_EncodeBlock((unsigned char*)output, input, length);
}

// ============================================================================
// HTTPS 反向代理（获取伪装首页）
// ============================================================================
static int fetch_https(const char *host, const char *path, char **body, long *status) {
    int sock = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    struct addrinfo hints, *res;
    int ret = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) != 0) {
        fprintf(stderr, "getaddrinfo failed for %s\n", host);
        goto cleanup;
    }
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { perror("socket"); goto cleanup; }
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) { perror("connect"); goto cleanup; }
    freeaddrinfo(res); res = NULL;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { fprintf(stderr, "SSL_CTX_new failed\n"); goto cleanup; }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    ssl = SSL_new(ctx);
    if (!ssl) { fprintf(stderr, "SSL_new failed\n"); goto cleanup; }
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "SSL_connect failed\n");
        goto cleanup;
    }

    char req[512];
    snprintf(req, sizeof(req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "User-Agent: Relay/1.0\r\n"
             "\r\n",
             path, host);
    if (SSL_write(ssl, req, strlen(req)) <= 0) {
        fprintf(stderr, "SSL_write failed\n");
        goto cleanup;
    }

    char header[4096] = {0};
    int header_len = 0;
    char ch;
    while (SSL_read(ssl, &ch, 1) > 0) {
        header[header_len++] = ch;
        if (header_len >= 4 && strstr(header, "\r\n\r\n")) break;
        if (header_len >= sizeof(header)-1) break;
    }
    long code = 0;
    if (sscanf(header, "HTTP/%*f %ld", &code) != 1) code = 500;
    *status = code;

    long content_length = -1;
    char *cl = strstr(header, "Content-Length:");
    if (cl) sscanf(cl, "Content-Length: %ld", &content_length);

    if (content_length <= 0) {
        char *buf = NULL;
        long total = 0, cap = 4096;
        buf = malloc(cap + 1);
        if (!buf) goto cleanup;
        while (1) {
            if (total >= cap) {
                cap *= 2;
                char *newbuf = realloc(buf, cap + 1);
                if (!newbuf) { free(buf); goto cleanup; }
                buf = newbuf;
            }
            int n = SSL_read(ssl, buf + total, cap - total);
            if (n <= 0) break;
            total += n;
        }
        buf[total] = '\0';
        *body = buf;
        ret = 0;
    } else {
        char *buf = malloc(content_length + 1);
        if (!buf) goto cleanup;
        long total = 0;
        while (total < content_length) {
            int n = SSL_read(ssl, buf + total, content_length - total);
            if (n <= 0) break;
            total += n;
        }
        buf[total] = '\0';
        *body = buf;
        ret = 0;
    }

cleanup:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (ctx) SSL_CTX_free(ctx);
    if (sock >= 0) close(sock);
    if (res) freeaddrinfo(res);
    return ret;
}

// ============================================================================
// HTTP 订阅服务与反向代理
// ============================================================================
static void send_http_response(int client_fd, const char *content_type,
                               const char *body, size_t body_len) {
    char header[256];
    int header_len = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        content_type, body_len);
    send(client_fd, header, header_len, 0);
    send(client_fd, body, body_len, 0);
    close(client_fd);
}

static void handle_sub_request(int client_fd) {
    char buf[512];
    ssize_t n = recv(client_fd, buf, sizeof(buf)-1, 0);
    if (n <= 0) { close(client_fd); return; }
    buf[n] = '\0';

    char method[16] = {0}, path[256] = {0};
    sscanf(buf, "%s %s", method, path);

    if (strcmp(method, "GET") != 0) {
        const char *err = "Method Not Allowed";
        send_http_response(client_fd, "text/plain", err, strlen(err));
        return;
    }

    // ----- 订阅服务（/sub）-----
    if (strcmp(path, "/sub") == 0) {
        FILE *f = fopen("sub.txt", "rb");
        if (!f) {
            const char *err = "sub.txt not found";
            send_http_response(client_fd, "text/plain", err, strlen(err));
            return;
        }
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        rewind(f);
        char *body = malloc(len + 1);
        if (!body) { fclose(f); close(client_fd); return; }
        fread(body, 1, len, f);
        fclose(f);
        body[len] = '\0';

        int b64_len = ((len + 2) / 3) * 4 + 1;
        char *b64 = malloc(b64_len);
        if (!b64) { free(body); close(client_fd); return; }
        int encoded_len = EVP_EncodeBlock((unsigned char*)b64, (unsigned char*)body, len);
        b64[encoded_len] = '\0';

        char header[256];
        int header_len = snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n",
            encoded_len);
        send(client_fd, header, header_len, 0);
        ssize_t total = 0;
        while (total < encoded_len) {
            ssize_t sent = send(client_fd, b64 + total, encoded_len - total, 0);
            if (sent <= 0) break;
            total += sent;
        }
        close(client_fd);
        free(body);
        free(b64);
        return;
    }

    // ----- 根路径：反向代理到伪装首页 -----
    if (strcmp(path, "/") == 0) {
        char *body = NULL;
        long status = 0;
        if (fetch_https("doh.goyo123.work.gd", "/", &body, &status) == 0 && status == 200) {
            send_http_response(client_fd, "text/html", body, strlen(body));
            free(body);
        } else {
            const char *err = "Backend error";
            send_http_response(client_fd, "text/plain", err, strlen(err));
        }
        return;
    }

    // 其他路径 404
    const char *not_found = "404 Not Found";
    send_http_response(client_fd, "text/plain", not_found, strlen(not_found));
}

static void handle_sub_accept(int listen_fd) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) return;
    handle_sub_request(client_fd);
}

// ============================================================================
// Argo 隧道管理（含自动下载）
// ============================================================================
static pid_t argo_pid = -1;
static char argo_domain[256] = {0};

static const char* get_arch() {
    static char arch[16] = {0};
    if (arch[0]) return arch;
    FILE *fp = popen("uname -m", "r");
    if (!fp) return "amd64";
    if (fgets(arch, sizeof(arch), fp)) {
        size_t len = strlen(arch);
        if (len > 0 && arch[len-1] == '\n') arch[len-1] = '\0';
        if (strcmp(arch, "aarch64") == 0 || strcmp(arch, "arm64") == 0) {
            strcpy(arch, "arm64");
        } else {
            strcpy(arch, "amd64");
        }
    }
    pclose(fp);
    return arch;
}

static int is_executable_exists(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "./%s", name);
    if (access(path, X_OK) == 0) return 1;
    char *path_env = getenv("PATH");
    if (!path_env) return 0;
    char *dup = strdup(path_env);
    char *token = strtok(dup, ":");
    while (token) {
        snprintf(path, sizeof(path), "%s/%s", token, name);
        if (access(path, X_OK) == 0) {
            free(dup);
            return 1;
        }
        token = strtok(NULL, ":");
    }
    free(dup);
    return 0;
}

static int download_cloudflared() {
    const char *arch = get_arch();
    char url[256];
    snprintf(url, sizeof(url), "https://%s.ssss.nyc.mn/bot", arch);
    printf("Downloading cloudflared from %s ...\n", url);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "wget -qO ./cloudflared %s", url);
    int ret = system(cmd);
    if (ret != 0) {
        snprintf(cmd, sizeof(cmd), "curl -sL -o ./cloudflared %s", url);
        ret = system(cmd);
        if (ret != 0) {
            fprintf(stderr, "Failed to download cloudflared. Please install manually.\n");
            return -1;
        }
    }
    system("chmod +x ./cloudflared");
    return 0;
}

static int ensure_cloudflared() {
    if (is_executable_exists("cloudflared")) {
        return 0;
    }
    printf("cloudflared not found. Downloading...\n");
    return download_cloudflared();
}

static int generate_tunnel_config(const char *auth, const char *domain) {
    if (strstr(auth, "TunnelSecret") == NULL) return 0;

    FILE *f = fopen("tunnel.json", "w");
    if (!f) return -1;
    fputs(auth, f);
    fclose(f);

    char tunnel_id[64] = {0};
    const char *p = strstr(auth, "\"TunnelID\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            while (*p == ' ' || *p == '\"') p++;
            char *end = strchr(p, '\"');
            if (end) {
                int len = end - p;
                if (len > 63) len = 63;
                strncpy(tunnel_id, p, len);
                tunnel_id[len] = '\0';
            }
        }
    }

    f = fopen("tunnel.yml", "w");
    if (!f) return -1;
    fprintf(f, "tunnel: %s\n", tunnel_id);
    fprintf(f, "credentials-file: tunnel.json\n");
    fprintf(f, "protocol: http2\n\n");
    fprintf(f, "ingress:\n");
    fprintf(f, "  - hostname: %s\n", domain);
    fprintf(f, "    service: http://localhost:%d\n", config.proxy_port);
    fprintf(f, "    originRequest:\n");
    fprintf(f, "      noTLSVerify: true\n");
    fprintf(f, "  - service: http_status:404\n");
    fclose(f);
    return 0;
}

static int start_cloudflared(const char *auth, const char *domain) {
    if (ensure_cloudflared() != 0) {
        fprintf(stderr, "cloudflared not available.\n");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        char *args[20];
        int idx = 0;
        char *cloudflared_path = (access("./cloudflared", X_OK) == 0) ? "./cloudflared" : "cloudflared";
        args[idx++] = cloudflared_path;
        args[idx++] = "tunnel";
        args[idx++] = "--edge-ip-version";
        args[idx++] = "auto";
        args[idx++] = "--no-autoupdate";
        args[idx++] = "--protocol";
        args[idx++] = "http2";

        if (auth && auth[0]) {
            if (strlen(auth) >= 120 && strlen(auth) <= 250) {
                args[idx++] = "run";
                args[idx++] = "--token";
                args[idx++] = (char*)auth;
            } else if (strstr(auth, "TunnelSecret")) {
                args[idx++] = "--config";
                args[idx++] = "tunnel.yml";
                args[idx++] = "run";
            } else {
                args[idx++] = "--logfile";
                args[idx++] = "argo.log";
                args[idx++] = "--loglevel";
                args[idx++] = "info";
                args[idx++] = "--url";
                char url[64];
                snprintf(url, sizeof(url), "http://localhost:%d", config.proxy_port);
                args[idx++] = url;
            }
        } else {
            args[idx++] = "--logfile";
            args[idx++] = "argo.log";
            args[idx++] = "--loglevel";
            args[idx++] = "info";
            args[idx++] = "--url";
            char url[64];
            snprintf(url, sizeof(url), "http://localhost:%d", config.proxy_port);
            args[idx++] = url;
        }
        args[idx] = NULL;
        execvp(args[0], args);
        perror("execvp cloudflared");
        exit(1);
    }
    argo_pid = pid;
    printf("cloudflared started, PID: %d\n", pid);
    return 0;
}

static int extract_domain_from_log(const char *logfile) {
    FILE *f = fopen(logfile, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "trycloudflare.com")) {
            char *start = strstr(line, "https://");
            if (!start) start = strstr(line, "http://");
            if (start) {
                char *end = strchr(start, ' ');
                if (!end) end = start + strlen(start);
                int len = end - start;
                if (len > 255) len = 255;
                strncpy(argo_domain, start, len);
                argo_domain[len] = '\0';
                char *p = strstr(argo_domain, "://");
                if (p) memmove(argo_domain, p+3, strlen(p+3)+1);
                int l = strlen(argo_domain);
                if (l > 0 && argo_domain[l-1] == '/') argo_domain[l-1] = '\0';
                fclose(f);
                return 0;
            }
        }
    }
    fclose(f);
    return -1;
}

static void generate_subscription(const char *domain) {
    char node_name[128];
    if (config.node_name[0]) {
        snprintf(node_name, sizeof(node_name), "%s", config.node_name);
    } else {
        snprintf(node_name, sizeof(node_name), "Argo");
    }

    FILE *f = fopen("sub.txt", "w");
    if (!f) {
        fprintf(stderr, "Failed to open sub.txt for writing\n");
        return;
    }

    fprintf(f, "vless://%s@%s:%s?encryption=none&security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=%%2Fvless-argo%%3Fed%%3D2560#%s\n",
            config.uuid, config.cfip, config.cfport, domain, domain, node_name);

    fprintf(f, "trojan://%s@%s:%s?security=tls&sni=%s&fp=firefox&type=ws&host=%s&path=%%2Ftrojan-argo%%3Fed%%3D2560#%s\n",
            config.uuid, config.cfip, config.cfport, domain, domain, node_name);

    fclose(f);
    printf("Subscription written to sub.txt, domain: %s, node: %s\n", domain, node_name);
    fflush(stdout);
}

static int argo_run() {
    if (config.argo_auth[0] && config.argo_domain[0]) {
        fprintf(stderr, "Using fixed tunnel: %s\n", config.argo_domain);
        if (generate_tunnel_config(config.argo_auth, config.argo_domain) != 0) {
            fprintf(stderr, "Failed to generate tunnel config\n");
            return -1;
        }
        if (start_cloudflared(config.argo_auth, config.argo_domain) != 0) {
            fprintf(stderr, "Failed to start cloudflared\n");
            return -1;
        }
        strncpy(argo_domain, config.argo_domain, sizeof(argo_domain)-1);
        argo_domain[sizeof(argo_domain)-1] = '\0';
        generate_subscription(argo_domain);
        return 0;
    }

    // 快速隧道
    if (start_cloudflared(NULL, NULL) != 0) {
        fprintf(stderr, "Failed to start quick cloudflared\n");
        return -1;
    }
    for (int i = 0; i < 20; i++) {
        sleep(1);
        if (extract_domain_from_log("argo.log") == 0) {
            generate_subscription(argo_domain);
            return 0;
        }
    }
    fprintf(stderr, "Could not extract temporary domain\n");
    return -1;
}

static void argo_stop() {
    if (argo_pid > 0) {
        kill(argo_pid, SIGTERM);
        waitpid(argo_pid, NULL, 0);
        argo_pid = -1;
    }
}

// ============================================================================
// 主程序与信号处理
// ============================================================================
static int running = 1;
static int epoll_fd = -1;
static int proxy_listen_fd = -1;
static int sub_listen_fd = -1;

static void handle_signal(int sig) {
    if (sig == SIGINT || sig == SIGTERM) running = 0;
}

static void sigchld_handler(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char **argv) {
    init_config();
    if (parse_uuid(config.uuid) != 0) {
        fprintf(stderr, "Invalid UUID, using default.\n");
        strcpy(config.uuid, "00000000-0000-4000-8000-000000000000");
        parse_uuid(config.uuid);
    }
    compute_trojan_password();

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGCHLD, sigchld_handler);

    // ---------- 代理监听 socket (ARGO_PORT) ----------
    proxy_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_listen_fd < 0) { perror("proxy socket"); return 1; }
    int opt = 1;
    setsockopt(proxy_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config.proxy_port);
    if (bind(proxy_listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("proxy bind"); return 1;
    }
    if (listen(proxy_listen_fd, SOMAXCONN) < 0) {
        perror("proxy listen"); return 1;
    }
    set_nonblock(proxy_listen_fd);

    // ---------- 订阅监听 socket (RELAY_PORT) ----------
    sub_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sub_listen_fd < 0) { perror("sub socket"); return 1; }
    setsockopt(sub_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in sub_addr;
    memset(&sub_addr, 0, sizeof(sub_addr));
    sub_addr.sin_family = AF_INET;
    sub_addr.sin_addr.s_addr = INADDR_ANY;
    sub_addr.sin_port = htons(config.sub_port);
    if (bind(sub_listen_fd, (struct sockaddr*)&sub_addr, sizeof(sub_addr)) < 0) {
        perror("sub bind"); return 1;
    }
    if (listen(sub_listen_fd, SOMAXCONN) < 0) {
        perror("sub listen"); return 1;
    }
    set_nonblock(sub_listen_fd);

    // ---------- epoll ----------
    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll"); return 1; }
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = proxy_listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, proxy_listen_fd, &ev);
    ev.data.fd = sub_listen_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sub_listen_fd, &ev);

    // ---------- 启动 Argo ----------
    if (argo_run() != 0) {
        fprintf(stderr, "Argo startup failed, but relay continues.\n");
    }

    printf("Proxy (VLESS/Trojan) listening on port %d\n", config.proxy_port);
    printf("Subscription HTTP server on port %d (path /sub)\n", config.sub_port);
    printf("Root path / proxies to https://doh.goyo123.work.gd\n");

    struct epoll_event events[MAX_EVENTS];
    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, 1000);
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == proxy_listen_fd) {
                handle_accept(proxy_listen_fd, epoll_fd);
            } else if (events[i].data.fd == sub_listen_fd) {
                handle_sub_accept(sub_listen_fd);
            } else {
                conn_ctx *ctx = (conn_ctx*)events[i].data.ptr;
                if (!ctx) continue;
                if (ctx->state == 0) {
                    handle_client_read(ctx, epoll_fd);
                } else {
                    int fd = (events[i].data.fd == ctx->client_fd) ? ctx->client_fd : ctx->target_fd;
                    handle_forward(ctx, fd);
                }
            }
        }
    }

    argo_stop();
    close(epoll_fd);
    close(proxy_listen_fd);
    close(sub_listen_fd);
    printf("Exiting.\n");
    return 0;
}
