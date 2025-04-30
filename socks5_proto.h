#ifndef SOCKS5_PROTO_H
#define SOCKS5_PROTO_H

/* SOCKS5 protocol constants */
#define SOCKS5_VERSION          0x05
#define SOCKS5_AUTH_NONE        0x00
#define SOCKS_AUTH_GSSAPI       0x01
#define SOCKS5_AUTH_PASSWORD    0x02
#define SOCKS5_AUTH_NO_ACCEPT   0xFF

/* SOCKS5 command codes */
#define SOCKS5_CMD_CONNECT      0x01
#define SOCKS5_CMD_BIND         0x02
#define SOCKS5_CMD_UDP_ASSOC    0x03

/* SOCKS5 ADDR types */
#define SOCKS5_ADDR_IPV4        0x01
#define SOCKS5_ADDR_DOMAIN      0x03
#define SOCKS5_ADDR_IPV6        0x04

/* SOCKS response codes */
#define SOCKS5_REP_SUCCESS      0x00
#define SOCKS5_REP_GEN_FAILURE  0x01
#define SOCKS5_REP_CONN_DENIED  0x02
#define SOCKS5_REP_NET_UNREACH  0x03
#define SOCKS5_REP_HOST_UNREACH 0x04
#define SOCKS5_REP_CONN_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED  0x06
#define SOCKS5_REP_CMD_NOTSUP   0x07
#define SOCKS5_REP_ADDR_NOTSUP  0x08

/* Max buffer sizes */
#define MAX_DOMAIN_LEN          255
#define MAX_AUTH_LEN            255
#define MAX_BUFFER_SIZE         1024

#define DEFAULT_TIMEOUT         10

#endif // SOCKS5_PROTO_H
