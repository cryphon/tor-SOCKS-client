#include "toralize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <ctype.h>


/* func ptrs for og sock funcs */
static int (*original_connect)(int sockfd, const struct sockaddr* addr, socklen_t);
static int(*original_close)(int fd);
static ssize_t (*original_send)(int sockfd, const void* buf, size_t len, int flags);
static ssize_t (*original_recv)(int sockfd, void* buf, size_t len, int flags);
static ssize_t (*original_write)(int fd, const void* buf, size_t count);
static ssize_t (*original_read)(int fd, void* buf, size_t count);

/* logging */
static void toralize_log(const char* format, ...) {

    va_list args;
    va_start(args, format);

    fprintf(stderr, "[TORALIZE] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");

    va_end(args);
}

static int is_host_excluded(const char* host) {
    for(int i = 0; i < toralize_config.excluded_cnt; i++) {
        if(strcmp(toralize_config.excluded[i], host) == 0) {
            return 1;
        }
    }
    return 0;
}


/* init the library */
static void init_toralize() {
    pthread_mutex_lock(&toralize_config.mutex);

    if(toralize_config.init) {
        pthread_mutex_unlock(&toralize_config.mutex);
        return;
    }

    /* set default config */
    strncpy(toralize_config.tor_host, PROXY_HOST, MAX_AUTH_LEN -1);
    toralize_config.tor_port = PROXY_PORT;

    /* read config file if exists */
    char* config_path = getenv("TORALIZE_CONFIG");
    if(!config_path) {
        config_path = DEFAULT_CONFIG_FILE;
    }
FILE *config_file = fopen(config_path, "r");
    if(config_file) {
        char line[512];
        while(fgets(line, sizeof(line), config_file)) {
            /* remove newline */
            size_t len = strlen(line);
            if(len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
            }

            /* skip comments and empty lines */
            if(line[0] == '#' || line[0] == '\0') {
                continue;
            }

            char key[256], value[256];
            if(sscanf(line, "%255[^=]=%255s", key, value) == 2) {
                if(strcmp(key, "tor_host") == 0) {
                    strncpy(toralize_config.tor_host, value, MAX_AUTH_LEN - 1);
                } else if(strcmp(key, "tor_port") == 0) {
                    toralize_config.tor_port = (uint16_t)atoi(value);
                } else if(strcmp(key, "verbose") == 0) {
                    toralize_config.verbose = atoi(value);
                } else if (strcmp(key, "exclude") == 0) {
                    /* add to excluded hosts */
                    toralize_config.excluded_cnt++;
                    toralize_config.excluded = realloc(
                            toralize_config.excluded,
                            toralize_config.excluded_cnt * sizeof(char*)
                            );
                    toralize_config.excluded[toralize_config.excluded_cnt - 1] = strdup(value);
                }
            }
        }
        fclose(config_file);
    }

    /* always exclude localhost */
    if(!is_host_excluded("127.0.0.1")) {
            toralize_config.excluded_cnt++;
            toralize_config.excluded = realloc(
                    toralize_config.excluded,
                    toralize_config.excluded_cnt * sizeof(char*)
                    );
            toralize_config.excluded[toralize_config.excluded_cnt - 1] = strdup("127.0.0.1");
    }

    if(!is_host_excluded("localhost")) {
        toralize_config.excluded_cnt++;
        toralize_config.excluded = realloc(
                toralize_config.excluded,
                toralize_config.excluded_cnt * sizeof(char*)
                );
        toralize_config.excluded[toralize_config.excluded_cnt - 1] = strdup("localhost");
    }

    /* load original functions */
    
    dlerror();
    original_connect = dlsym(RTLD_NEXT, "connect");
    char* err_connect = dlerror();
    if(err_connect) {
        fprintf(stderr, "dlsym error: %s\n", err_connect);
        exit(1);
    }


    dlerror();
    original_close = dlsym(RTLD_NEXT, "close");
    char* err_close = dlerror();
    if(err_close) {
        fprintf(stderr, "dlsym error: %s\n", err_close);
        exit(1);
    }

    dlerror();
    original_send = dlsym(RTLD_NEXT, "send");
    char* err_send = dlerror();
    if(err_send) {
        fprintf(stderr, "dlsym error: %s\n", err_send);
        exit(1);
    }
    
    dlerror();
    original_recv = dlsym(RTLD_NEXT, "recv");
    char* err_recv = dlerror();
    if(err_recv) {
        fprintf(stderr, "dlsym error: %s\n", err_recv);
        exit(1);
    }
    
    dlerror();
    original_write = dlsym(RTLD_NEXT, "write");
    char* err_write = dlerror();
    if(err_write) {
        fprintf(stderr, "dlsym error: %s\n", err_write);
        exit(1);
    }


    dlerror();
    original_read = dlsym(RTLD_NEXT, "read");
    char* err_read = dlerror();
    if(err_read) {
        fprintf(stderr, "dlsym error: %s\n", err_read);
        exit(1);
    }

    /* init socket tracking table */
    memset(managed_socks, 0, sizeof(managed_socks));
    for(int i = 0; i < MAX_MANAGED_SOCKS; i++) {
        managed_socks[i].og_fd = -1;
    }

    toralize_config.init = 1;
    toralize_log("Initialized with Tor proxy at %s:%d", toralize_config.tor_host, toralize_config.tor_port);

    pthread_mutex_unlock(&toralize_config.mutex);
}

static int register_socket(int fd, socks5_ctx* ctx, int through_tor, const char* host, uint16_t port) {
    for(int i = 0; i < MAX_MANAGED_SOCKS; i++) {
        if(managed_socks[i].og_fd == -1) {
                managed_socks[i].og_fd = fd;
                managed_socks[i].ctx = ctx;
                managed_socks[i].through_tor = through_tor;
                strncpy(managed_socks[i].dest_host, host, sizeof(managed_socks[i].dest_host) - 1);
                managed_socks[i].dest_port = port;
                return 0;
        }
    }
    return -1;
}

/* find managed sock by fd */
static int find_sock_index(int fd) {
    for(int i = 0; i < MAX_MANAGED_SOCKS; i++) {
        if(managed_socks[i].og_fd == fd) {
            return i;
        }
    }
    return -1;
}

static int extract_addr_info(const struct sockaddr* addr, socklen_t addrlen, char* host, size_t host_len, uint16_t* port) {
    if(addr->sa_family == AF_INET) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
        inet_ntop(AF_INET, &(addr_in->sin_addr), host, host_len);
        *port = ntohs(addr_in->sin_port);
        return 0;
    }
    else if(addr->sa_family == AF_INET6) {
        struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)addr;
        inet_ntop(AF_INET6, &(addr_in6->sin6_addr), host, host_len);
        *port = ntohs(addr_in6->sin6_port);
        return 0;
    }
    else {
        return -1;
    }
}


int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if(!toralize_config.init) {
        init_toralize();
    }

    /* extract host and port from sockaddr */
    char host[256];
    uint16_t port;

    if(extract_addr_info(addr, addrlen, host, sizeof(host), &port) != 0) {
        toralize_log("Unknown address family, using direct connection");
        return original_connect(sockfd, addr, addrlen);
    }
    
    /* check if host is excluded */
    if(is_host_excluded(host)) {
        toralize_log("Host %s is excluded, using direct connection", host);
        register_socket(sockfd, NULL, 0, host,  port);
        return original_connect(sockfd, addr, addrlen);
    }

    toralize_log("Intercepting connection to %s:%d", host, port);

    /* create SOCKS5 ctx for Tor */
    socks5_ctx* ctx = socks5_create_ctx(toralize_config.tor_host, toralize_config.tor_port);
    if(!ctx) {
        errno = ECONNREFUSED;
        return -1;
    }

    /* set verbose */
    socks5_set_verbose(ctx, toralize_config.verbose);

    /* connect through tor */
    int res = socks5_connect(ctx, host, port);
    if(res < 0) {
        toralize_log("Failed to connect through Tor: %s", socks5_get_error(ctx));
        socks5_free(ctx);
        errno = ECONNREFUSED;
        return -1;
    }

    /* assoc SOCKS5 con with original sock */
    int flags = fcntl(sockfd, F_GETFL, 0);

    /* get cpy tor sock */
    int tor_sock = dup(res);
    if(tor_sock < 0) {
        toralize_log("Failed to dup Tor sock");
        socks5_close(ctx);
        socks5_free(ctx);
        errno = ECONNREFUSED;
        return -1;
    }

    /* close original sock and replace with tor sock */
    dup2(tor_sock, sockfd);
    close(tor_sock);

    /* restore og sock flags */
    fcntl(sockfd, F_SETFL, flags);

    /* register sock for tracking */
    register_socket(sockfd, ctx, 1, host, port);

    toralize_log("Connected to %s:%d through tor", host, port);
    return 0;
}

int close(int fd) {
    if(!toralize_config.init) {
        return original_close(fd);
    }

    int idx = find_sock_index(fd);
    if(idx >= 0) {
        toralize_log("Closing managed socket %d", fd);

        if(managed_socks[idx].through_tor && managed_socks[idx].ctx) {
            socks5_close(managed_socks[idx].ctx);
            socks5_free(managed_socks[idx].ctx);
        }

        managed_socks[idx].og_fd = -1;
        managed_socks[idx].ctx = NULL;
    }

    return original_close(fd);
}
    
int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res) {
    static int (*original_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**);

    if(!original_getaddrinfo) {
        dlerror();
        original_getaddrinfo = dlsym(RTLD_NEXT, "getaddrinfo");
        char* err = dlerror();
        if(err) {
            fprintf(stderr, "dlsym error loading getaddrinfo: %s\n", err);
            exit(1);
        }
    }

    char* error = dlerror();
    if(error != NULL) {
        fprintf(stderr, "dlsym error: %s\n", error);
        exit(1);
    }

    if(!toralize_config.init) {
        init_toralize();
    }

    if(!node || is_host_excluded(node)) {
        return original_getaddrinfo(node, service, hints, res);
    }

    toralize_log("DNS resolution for %s will go through connect() later", node);

    /* for non-excluded hosts, resolve via socks later
     * for now, resolve placeholder addr to be replaced in connect */
    
    struct addrinfo* ai = malloc(sizeof(struct addrinfo));
    if(!ai) {
        return EAI_MEMORY;
    }

    memset(ai, 0, sizeof(struct addrinfo));

    if(hints) {
        ai->ai_family = hints->ai_family;
        ai->ai_socktype = hints->ai_socktype;
        ai->ai_protocol = hints->ai_protocol;
        ai->ai_flags = hints->ai_flags;
    }
    else {
        ai->ai_family = AF_INET;
        ai->ai_socktype = SOCK_STREAM;
        ai->ai_protocol = 0;
    }

    if(ai->ai_family == AF_UNSPEC) {
        ai->ai_family = AF_INET;
    }

    /* allocate and set sockaddr */
    if(ai->ai_family == AF_INET) {
        struct sockaddr_in* sin = malloc(sizeof(struct sockaddr_in));
        if(!sin) {
            free(ai);
            return EAI_MEMORY;
        }

        memset(sin, 0, sizeof(struct sockaddr_in));
        sin->sin_family = AF_INET;

        /* parse port */
        if(service) {
            if(isdigit((unsigned char)*service)) {
                sin->sin_port = htons((uint16_t)atoi(service));
            }
            else {
                struct servent* se = getservbyname(service, NULL);
                if(se) {
                    sin->sin_port = se->s_port;
                }
            }
        }

        sin->sin_addr.s_addr = inet_addr("240.0.0.1");
        
        ai->ai_addr = (struct sockaddr*)sin;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
    }
    else if(ai->ai_family == AF_INET6) {
        struct sockaddr_in6* sin6 = malloc(sizeof(struct sockaddr_in6));
        if(!sin6) {
            free(ai);
            return EAI_MEMORY;
        }

        memset(sin6, 0, sizeof(struct sockaddr_in6));
        sin6->sin6_family = AF_INET6;

        /* parse port */
        if(service) {
            if(isdigit((unsigned char)*service)) {
                sin6->sin6_port = htons((uint16_t)atoi(service));
            }
            else {
                struct servent* se = getservbyname(service, NULL);
                if(se) {
                    sin6->sin6_port = se->s_port;
                }
            }
        }

        inet_pton(AF_INET6, "::1", &sin6->sin6_addr);

        ai->ai_addr = (struct sockaddr*)sin6;
        ai->ai_addrlen = sizeof(struct sockaddr_in6);
    }
    else {
        free(ai);
        return EAI_MEMORY;
    }

    /* set canonical name if requested */
    if(node && (hints == NULL || !(hints->ai_flags & AI_NUMERICHOST))) {
        ai->ai_canonname = strdup(node);
        if(!ai->ai_canonname) {
            free(ai->ai_addr);
            free(ai);
            return EAI_MEMORY;
        }
    }

    ai->ai_next = NULL;
    *res = ai;

    return 0;
}

/* library constructor */
__attribute__((constructor))
static void toralize_init(void) {
    pthread_mutex_init(&toralize_config.mutex, NULL);
    init_toralize();
}

/* library destructor */
__attribute__((destructor))
static void toralize_destroy(void) {
    /* free excluded hosts */
    for(int i = 0; i < toralize_config.excluded_cnt; i++) {
        free(toralize_config.excluded[i]);
    }
    free(toralize_config.excluded);

    /* close any open SOCKS connections */
    for(int i = 0; i < MAX_MANAGED_SOCKS; i++) {
        if(managed_socks[i].og_fd != -1 && managed_socks[i].ctx) {
            socks5_close(managed_socks[i].ctx);
            socks5_free(managed_socks[i].ctx);
        }
    }

    pthread_mutex_destroy(&toralize_config.mutex);
}

