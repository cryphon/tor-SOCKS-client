#include "socks5_client.h"
#include "socks5_proto.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>


struct socks5_ctx {
    char proxy_host[MAX_DOMAIN_LEN + 1];
    uint16_t proxy_port;
    int use_auth;
    char uname[MAX_AUTH_LEN + 1];
    char passwd[MAX_AUTH_LEN + 1];
    int timeout;
    int proxy_sock;
    int last_error;
    int verbose;
    char error_msg[256];
};

socks5_ctx* socks5_create_ctx(const char* host, uint16_t port) {
    socks5_ctx* ctx = malloc(sizeof(socks5_ctx));
    if(!ctx) {
        return NULL;
    }

    memset(ctx, 0, sizeof(socks5_ctx));
    strncpy(ctx->proxy_host, host, MAX_DOMAIN_LEN);
    ctx->proxy_host[MAX_DOMAIN_LEN] = '\0';
    ctx->proxy_port = port;
    ctx->use_auth = 0;
    ctx->timeout = DEFAULT_TIMEOUT;
    ctx->verbose = 0;
    ctx->proxy_sock = -1;
    ctx->last_error = 0;

    return ctx;
}

void socks5_set_auth(socks5_ctx* ctx, const char* uname, const char* passwd) {
    if(!ctx || !uname || !passwd) {
        return;
    }
    ctx->use_auth = 1;
    strncpy(ctx->uname, uname, MAX_AUTH_LEN);
    ctx->uname[MAX_AUTH_LEN] = '\0';
    strncpy(ctx->passwd, passwd, MAX_AUTH_LEN);
    ctx->passwd[MAX_AUTH_LEN] = '\0';
}

void socks5_set_timeout(socks5_ctx* ctx, int timeout) {
    if(!ctx || timeout <= 0) {
        return;
    }
    ctx->timeout = timeout;
}

static void socks5_log(socks5_ctx* ctx, const char* format, ...) {
    if(!ctx || !ctx->verbose) {
        return;
    }

    va_list args;
    va_start(args, format);
    fprintf(stderr, "[SOCKS5] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void socks5_set_verbose(socks5_ctx* ctx, int verbose) {
    if(!ctx) {
        return;
    }
    ctx->verbose = verbose;
}

static void socks5_set_error(socks5_ctx* ctx, int err_code, const char* format, ...) {
    if(!ctx) {
        return;
    }

    ctx->last_error = err_code;
    va_list args;
    va_start(args, format);
    vsnprintf(ctx->error_msg, sizeof(ctx->error_msg) - 1, format, args);
    va_end(args);

    if(ctx->verbose) {
        fprintf(stderr, "[SOCKS ERROR] %s (code: %d)\n", ctx->error_msg, err_code);
    }
}

const char* socks5_get_error(socks5_ctx* ctx) {
    if(!ctx) {
        return "Invalid context";
    }
    return ctx->error_msg;
}

int socks5_get_error_code(socks5_ctx* ctx) {
    if(!ctx) {
        return -1;
    }
    return ctx->last_error;
}

static int socks5_connect_to_proxy(socks5_ctx* ctx) {
    struct addrinfo hints, *res, *rp;
    int sock = -1;
    char port_str[8];

    if(!ctx) {
        return -1;
    }

    // already connected
    if(ctx->proxy_sock >= 0) {
        return ctx->proxy_sock;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", ctx->proxy_port);

    socks5_log(ctx, "Resolving proxy addr: %s:%s", ctx->proxy_host, port_str);

    int ret = getaddrinfo(ctx->proxy_host, port_str, &hints, &res);
    if(!ret) {
        socks5_set_error(ctx, ret, "Failed to resolve proxy address: %s", gai_strerror(ret));
        return -1;
    }
    
    // try each addr until successfull connect
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if(sock == -1) {
            continue;
        }

        // socket timeout
        struct timeval tv;
        tv.tv_sec = ctx->timeout;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

        socks5_log(ctx, "Connecting to proxy server...");
        if(connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) {
            // connect successfull
            break;
        }

        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);

    if(sock == -1) {
        return -1;
    }

    socks5_log(ctx, "Connected to proxy server");
    ctx->proxy_sock = sock;
    return sock;
}

static int socks5_do_handshake(socks5_ctx* ctx) {
    if(!ctx || ctx->proxy_sock < 0) {
        return -1;
    }
    unsigned char buff[MAX_BUFFER_SIZE];
    int n, i;

    socks5_log(ctx, "Sending auth method negotiation");

    i = 0;
    buff[i++] = SOCKS5_VERSION;
    
    if(ctx->use_auth) {
        buff[i++] = 2;  // auth methods cnt
        buff[i++] = SOCKS5_AUTH_NONE;
        buff[i++] = SOCKS5_AUTH_PASSWORD;
    }
    else {
        buff[i++] = 1; // auth methods cnt
        buff[i++] = SOCKS5_AUTH_NONE;
    }

    if(write(ctx->proxy_sock, buff, i) != i) {
        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
    }

    socks5_log(ctx, "Reading auth metod selection");

    n = read(ctx->proxy_sock, buff, 2);
    if(n != 2) {
        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        return -1;
    }

    if(buff[0] != SOCKS5_VERSION) {
        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        return -1;
    }

    if(buff[1] == SOCKS5_AUTH_NO_ACCEPT) {
        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        return -1;
    }

    // if uname, passwd auth, send creds
    if(buff[1] == SOCKS5_AUTH_PASSWORD) {
        if(!ctx->use_auth) {
            close(ctx->proxy_sock);
            ctx->proxy_sock = -1;
            return -1;
        }

        socks5_log(ctx, "Performing username/password authentication");

        i = 0;
        buff[i++] = 0x01;   // auth version

        //uname
        buff[i++] = strlen(ctx->uname);
        memcpy(&buff[i], ctx->uname, strlen(ctx->uname));
        i += strlen(ctx->uname);


        buff[i++] = strlen(ctx->passwd);
        memcpy(&buff[i], ctx->passwd, strlen(ctx->passwd));
        i += strlen(ctx->passwd);

        if(write(ctx->proxy_sock, buff, i) != i) {
            close(ctx->proxy_sock);
            ctx->proxy_sock = -1;
            return -1;
        }
        
        // read auth res
        n = read(ctx->proxy_sock, buff, 2);
        if(n != 2) {
            close(ctx->proxy_sock);
            ctx->proxy_sock = -1;
            return -1;
        }

        if(buff[1] != 0) {
            close(ctx->proxy_sock);
            ctx->proxy_sock = -1;
            return -1;
        }

        socks5_log(ctx, "Authentication successfull");
    }
    else if(buff[1] != SOCKS5_AUTH_NONE) {
        socks5_log(ctx, "Unsupported auth method: %d", buff[1]);
        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        return -1;
    }

    return 0;
}

int socks5_connect(socks5_ctx* ctx, const char* host, uint16_t port) { 
    if(!ctx || !host) {
        return -1;
    }

    // connect to proxy if not connected
    if(ctx->proxy_sock < 0) {
        if(socks5_connect_to_proxy(ctx) < 0) {
            socks5_log(ctx, "Failed to connect to proxy");
            return -1;
        }

        // do handshake
        if(socks5_do_handshake(ctx) < 0) {
            socks5_log(ctx, "Failed to do handshake");
            return -1;
        }
    }

    unsigned char buff[MAX_BUFFER_SIZE];
    struct in_addr addr;
    int i = 0, n;
    int is_ipv4 = (inet_pton(AF_INET, host, &addr) == 1);

    socks5_log(ctx, "Connecting to destination: %s:%d", host, port);

    // build connection request
    buff[i++] = SOCKS5_VERSION;
    buff[i++] = SOCKS5_CMD_CONNECT;
    buff[i++] = 0x00; // reserved

    if(is_ipv4) {
        buff[i++] = SOCKS5_ADDR_IPV4;
        memcpy(&buff[i], &addr.s_addr, 4);
        i += 4;
    }
    else {
        // domain name
        size_t host_len = strlen(host);
        if(host_len > MAX_DOMAIN_LEN) {
            return -1;
        }

        buff[i++] = SOCKS5_ADDR_DOMAIN;
        buff[i++] = host_len;
        memcpy(&buff[i], host, host_len);
        i += host_len;
    }
    

    // port (network byte order)
    buff[i++] = (port >> 8) & 0xFF;
    buff[i++] = port & 0xFF;

    // send connection req
    if(write(ctx->proxy_sock, buff, i) != i) {
        socks5_log(ctx, "Failed to send connection request");
        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        return -1;
    }

    // read res
    n = read(ctx->proxy_sock, buff, 4);
    if(n != 4) {
        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        return -1;
    }

    if(buff[0] != SOCKS5_VERSION) {
        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        return -1;
    }

    // check res status
    if(buff[1] != SOCKS5_REP_SUCCESS) {
        const char* error_msg = "Unknown error";

        switch(buff[1]) {
            case SOCKS5_REP_GEN_FAILURE:
                error_msg = "General SOCKS server failure";
                break;
            case SOCKS5_REP_CONN_DENIED:
                error_msg = "Connection not allowed by ruleset";
                break;
            case SOCKS5_REP_NET_UNREACH:
                error_msg = "Network unreachable";
                break;
            case SOCKS5_REP_HOST_UNREACH:
                error_msg = "Host unreachable";
                break;
            case SOCKS5_REP_CONN_REFUSED:
                error_msg = "Connection refused";
                break;
            case SOCKS5_REP_TTL_EXPIRED:
                error_msg = "TTL expired";
                break;
            case SOCKS5_REP_CMD_NOTSUP:
                error_msg = "Command not supported";
                break;
            case SOCKS5_REP_ADDR_NOTSUP:
                error_msg = "Address type not supported";
                break;
        }

        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        return -1;
    }

    // skip rest of res (bound addr and port)
    int atyp = buff[3];
    int addr_len = 0;

    if(atyp == SOCKS5_ADDR_IPV4) {
        addr_len = 4;
    } else if(atyp == SOCKS5_ADDR_IPV6) {
        addr_len = 16;
    } else if(atyp == SOCKS5_ADDR_DOMAIN) {
        // first read domain len byte
        n = read(ctx->proxy_sock, buff, 1);
        if(n != 1) {
            close(ctx->proxy_sock);
            ctx->proxy_sock = -1;
            return -1;
        }
        addr_len = buff[0];
    }
    else { 
        socks5_log(ctx, "Unknown addr type in res: %d", atyp);
        close(ctx->proxy_sock);
        ctx->proxy_sock = -1;
        return -1;
    }

    // skip addr and port
    unsigned char skip_buff[MAX_BUFFER_SIZE];
    int remaining = addr_len + 2;

    while(remaining > 0) {
        n = read(ctx->proxy_sock, skip_buff, remaining > MAX_BUFFER_SIZE ? MAX_BUFFER_SIZE : remaining);
        if(n <= 0) {
            close(ctx->proxy_sock);
            ctx->proxy_sock = -1;
            return -1;
        }
        remaining -= n;
    }

    socks5_log(ctx, "Successfully connected to %s:%d via SOCKS5 proxy", host, port);
    return ctx->proxy_sock;

};


void socks5_close(socks5_ctx* ctx) {
    if(!ctx) {
        return;
    }

    if(ctx->proxy_sock >= 0) {
        close(ctx-> proxy_sock);
        ctx->proxy_sock = -1;
    }
}

void socks5_free(socks5_ctx* ctx) {
    if(!ctx) {
        return;
    }

    socks5_close(ctx);
    free(ctx);
}
