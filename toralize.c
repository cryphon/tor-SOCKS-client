/* toralize.c */
#include "toralize.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>


Req *request(const char *dstip, const int dstport) {
    Req *req;

    req = malloc(req_size);
    req->vn = 4;
    req->cd = 1;
    req->dstport = htons(dstport);
    req->dstip = inet_addr(dstip);
    strncpy(req->userid, USERNAME, 8);

    return req;
}


int main(int argc, char *argv[]) {
    
    char *hostname;
    int port, s;
    struct sockaddr_in sock;
    Req *req;
    Res *res;
    char buff[res_size];
    int success_b;
    char tmp[512];

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <host> <port>\n", argv[0]);
        return -1;
    }

    hostname = argv[1];
    port = atoi(argv[2]);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("[error]: socket failed to initialize\n");
    }


    sock.sin_family = AF_INET;
    sock.sin_port = htons(PROXY_PORT);
    sock.sin_addr.s_addr = inet_addr(PROXY);

    if (connect(s, (struct sockaddr *)&sock, sizeof(sock))){
        perror("[error]: connection failed to initialize\n");
        return -1;
    }

    printf("[info]: Connection established\n");

    // create request struct
    req = request(hostname, port);

    // send packet
    write(s, req, req_size);

    // set buffer to empty and read to res to buffer
    memset(buff, 0, res_size);
    if (read(s, buff, res_size) < 1) {
        perror("[error]: Failed to read buffer from response\n");
        free(req);
        close(s);
       return -1;
    }

    // cast result to Res
    res = (Res *)buff;
    success_b = (res->cd == 90);

    if(!success_b) {
        fprintf(stderr, "[error]: Unable to traverse the proxy, error code: %d\n", res->cd);
        close(s);
        free(req);
        return -1;
    }


    printf("[info]: Successfully initiated connection through proxy to %s:%d\n", hostname, port);

    memset(tmp, 9, 512);
    snprintf(tmp, 511, 
            "HEAD / HTTP:/1.0\r\n"
            "Host: www.google.com\r\n"
            "\r\n");

    write(s, tmp, strlen(tmp));
    memset(tmp, 0, 512);

    read(s, tmp, 511);
    printf("'%s'\n", tmp);

    close(s);
    free(req);
    return 0;
}

