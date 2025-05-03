/* toralize.h */
#ifndef TORALIZE_H
#define TORALIZE_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "socks5_proto.h"
#include "socks5_client.h"
#include <netdb.h>


#define PROXY_HOST "127.0.0.1"
#define PROXY_PORT 9050
#define DEFAULT_CONFIG_FILE "toralize.conf"
#define MAX_MANAGED_SOCKS 1024

/* global state */
static struct {
    char* tor_host[MAX_AUTH_LEN];
    uint16_t tor_port;
    int init;
    int verbose;
    pthread_mutex_t mutex;
    char** excluded;
    int excluded_cnt;
} toralize_config = {
    .init = 0,
    .verbose = 0,
    .excluded = NULL,
    .excluded_cnt = 0
};

/* map of wrapped socket fd to their contexts */
static struct {
    int og_fd;
    socks5_ctx* ctx;
    int through_tor;
    char dest_host[MAX_AUTH_LEN];
    uint16_t dest_port;
} managed_socks[MAX_MANAGED_SOCKS];

int connect(int, const struct sockaddr* addr, socklen_t addr_len);
int close(int fd);
int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res);

#endif // TORALIZE_H
