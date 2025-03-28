#ifndef _SERVER_H
#define _SERVER_H

#include <stdint.h>

#define WS_FR_OP_CONT 0
#define WS_FR_OP_TXT  1
#define WS_FR_OP_BIN  2
#define WS_FR_OP_CLSE 8
#define WS_FR_OP_PING 0x9
#define WS_FR_OP_PONG 0xA

struct tcp_server_t;
struct conn_state_t;

size_t tcp_server_connection_get_id(struct conn_state_t *conn);
void *tcp_server_connection_get_context(struct conn_state_t *conn);
const char * tcp_server_connection_get_ip(struct conn_state_t *conn);

struct tcp_server_t *tcp_server_create(uint16_t port, void *userdata);
struct tcp_server_t *tcp_server_create_with_host(const char *host, uint16_t port, void *userdata);

void tcp_server_set_onopen(struct tcp_server_t *ctx, void (*callback)(struct conn_state_t *conn));
void tcp_server_set_ondata(struct tcp_server_t *ctx, void (*callback)(struct conn_state_t *conn, int opcode, const char *data, size_t length));
void tcp_server_set_onclose(struct tcp_server_t *ctx, void (*callback)(struct conn_state_t *conn));

int tcp_server_start(struct tcp_server_t *ctx);
void tcp_server_destroy(struct tcp_server_t *ctx);

void tcp_server_send_text(struct conn_state_t *conn, const char *data);
void tcp_server_send(struct conn_state_t *conn, int opcode, const char *data, size_t len);
void tcp_server_send_boardcast(struct conn_state_t *conn, int opcode, const char *data, size_t len);
void tcp_server_send_all(struct tcp_server_t *ctx, int opcode, const char *data, size_t len);

void tcp_server_close_connection(struct conn_state_t *cli);
void tcp_server_close_connection_reason(struct conn_state_t *cli, int code);

void tcp_server_send_ping(struct conn_state_t *cli);
void tcp_server_ping_all(struct tcp_server_t *ctx);

#endif
