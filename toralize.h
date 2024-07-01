/* toralize.h */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>


#define PROXY "127.0.0.1"
#define PROXY_PORT 9050
#define USERNAME "nazuna"
#define req_size sizeof(struct proxy_request)
#define res_size sizeof(struct proxy_response)

typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned int int32;


/*
link: https://www.openssh.com/txt/socks4.protocol
The client includes in the request packet the IP address and the port number of the
destination host, and userid, in the following format.

                +----+----+----+----+----+----+----+----+----+----+....+----+
                | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
                +----+----+----+----+----+----+----+----+----+----+....+----+
 # of bytes:	   1    1      2              4           variable       1
*/
struct proxy_request {
    int8 vn;                    // SOCKS version protocol
    int8 cd;                    // command code, 1 for CONNECT request
    int16 dstport;              // destination port
    int32 dstip;
    unsigned char userid[8];
};
typedef struct proxy_request Req;
/* 
If the request is granted, the SOCKS server makes a connection to the specified port of the destination host;
A reply packet is sent to the clinent when this connection is established, or when the request is rejected or the operation fails.

                +----+----+----+----+----+----+----+----+
                | VN | CD | DSTPORT |      DSTIP        |
                +----+----+----+----+----+----+----+----+
 # of bytes:	   1    1      2              4

 _, __ = non relevant variables
*/
struct proxy_response {
    int8 vn;
    int8 cd;
    int16 _;
    int32 __;
};
typedef struct proxy_response Res;


Req *request(const char*, const int);
int main(int, char**);