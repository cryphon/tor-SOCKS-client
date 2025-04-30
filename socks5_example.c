#include "socks5_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TOR_PROXY_HOST "127.0.0.1"
#define TOR_PROXY_PORT 9050

int main(int argc, char* argv[]) {
    if(argc != 3) {
        fprintf(stderr, "Usage: %s <host> <port>\n", argv[0]);
        return 1;
    }

    const char* host = argv[1];
    uint16_t port = (uint16_t)atoi(argv[2]);

    // create socks5 context for Tor
    socks5_ctx* ctx = socks5_create_ctx(TOR_PROXY_HOST, TOR_PROXY_PORT);
    if(!ctx) {
        fprintf(stderr, "Failed to create SOCKS5 context\n");
        return 1;
    }

    socks5_set_timeout(ctx, 30);

    int sock = socks5_connect(ctx, host, port);
    if(sock < 0) {
        fprintf(stderr, "Connection failed\n");
        socks5_free(ctx);
        return 1;
    }

    printf("Connect to %s:%d through Tor successfully!\n", host, port);

    if(port == 80) {
        const char* request = "GET / HTTP/1.1\r\n"
                              "Host: %s\r\n"
                              "User-Agent: SOCKS5 Example Client\r\n"
                              "Connection: close\r\n\r\n";

        char http_request[512];
        snprintf(http_request, sizeof(http_request), request, host);

        printf("Sending HTTP request: \n%s\n", http_request);
        write(sock, http_request, strlen(http_request));

        char buffer[4096];
        ssize_t bytes_read;
        while ((bytes_read = read(sock, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            printf("%s", buffer);
        }
    } 
    else {
        printf("Connected to non-HTTP port. You can now send/receive data manually.\n");
    }

    socks5_close(ctx);
    socks5_free(ctx);

    return 0;
}
