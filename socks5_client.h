#ifndef SOCKS5_CLIENT_H
#define SOCKS5_CLIENT_H

#include <stdint.h>
#include <stdarg.h>

typedef struct socks5_ctx socks5_ctx;

socks5_ctx *socks5_create_ctx(const char* host, uint16_t port);
void socks5_set_auth(socks5_ctx* ctx, const char* uname, const char* passwd);
void socks5_set_timeout(socks5_ctx* ctx, int timeout_secs);
int socks5_connect(socks5_ctx* ctx, const char* host, uint16_t port);
void socks5_close(socks5_ctx* ctx);
void socks5_free(socks5_ctx* ctx);
void socks5_set_verbose(socks5_ctx* ctx, int verbose);
const char* socks5_get_error(socks5_ctx* ctx);
int socks5_get_error_code(socks5_ctx* ctx);

#endif // SOCKS5_CLIENT_H
