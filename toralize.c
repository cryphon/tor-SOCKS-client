/* toralize.c */
#include "toralize.h"
#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>


Req *request(struct sockaddr_in *sock2) {
    Req *req;

    req = malloc(req_size);
    req->vn = 4;
    req->cd = 1;
    req->dstport = sock2->sin_port;
    req->dstip = sock2->sin_addr.s_addr;
    strncpy(req->userid, USERNAME, 8);

    return req;
}


int connect(int s2, const struct sockaddr *sock2, socklen_t addrlen) {

    int s; // s is ours, s2 is provided by  application
    struct sockaddr_in sock;
    Req *req;
    Res *res;
    char buff[res_size];
    int success_b;
    char tmp[512];
    //create fnc ptr
    int (*ptr)(int, const struct sockaddr*, socklen_t);

    ptr = dlsym(RTLD_NEXT, "connect");
    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("[error]: socket failed to initialize\n");
    }


    sock.sin_family = AF_INET;
    sock.sin_port = htons(PROXY_PORT);
    sock.sin_addr.s_addr = inet_addr(PROXY);

    if (ptr(s, (struct sockaddr *)&sock, sizeof(sock))){
        perror("[error]: connection failed to initialize\n");
        return -1;
    }

    printf("[info]: Connection established\n");

    // create request struct
    req = request((struct sockaddr_in*)sock2);

    // send packet
    if (write(s, req, req_size) < 0) {
        perror("[error]: Failed to write request to proxy");
    }

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


    printf("[info]: Successfully initiated connection through proxy.\n");

    //pipe our socket with end-appl socket
    if(dup2(s, s2) < 0) {
            perror("[error]: Failed to duplicate socket");
            free(req);
            close(s);
            return -1;
        }


    // debug print HTTP request from pipe application
    // char request_buff[4096];
    // ssize_t bytes_read, bytes_written;
    // while((bytes_read = read(s2, request_buff, sizeof(request_buff))) > 0) {
    //     bytes_written = write(s, request_buff, bytes_read);
    //     if(bytes_written < 0) {
    //         perror("[error]: Failed to forwartd HTTP request to proxy");
    //         close(s);
    //         return -1;
    //     }
    // }
    // if(bytes_read < 0) {
    //     perror("[error]: Failed to read HTTP request from application");
    //     close(s);
    // }

    char request_buff[1024];
    ssize_t bytes_read = read(s2, request_buff, sizeof(request_buff) -1);
    if (bytes_read > 0){
        request_buff[bytes_read] = '\0';
        printf("debug]: HTTP request from application: \n%s\n", request_buff);
    }
    else {
        perror("[error]: Failed to read HTTP request from application");
    }

    free(req);
    return 0;
}

