#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "hashmap.h"
#include "server.h"

struct app_data {
  char *name;
  map_t connections;
};

void tcp_chat_on_data(
  struct conn_state_t *conn, int opcode, const char *data, size_t length
);
void tcp_chat_on_open(struct conn_state_t *conn);
void tcp_chat_on_close(struct conn_state_t *conn);

int main(int argc, char const *argv[]) {
  uint16_t port_num;
  struct app_data app;
  struct tcp_server_t *ctx = NULL;

  if (argc != 3) {
    puts("IP and PORT should be the only arguments\n ./chat_app_server <IP> <PORT>");
    exit(1);
  }

  memset(&app, 0, sizeof(struct app_data));
  app.connections = hashmap_new();
  if (!app.connections) {
    return -1;
  }

  app.name = strdup("Simple Chat App");

  port_num = (uint16_t)strtol(argv[2], (char **)NULL, 10);

  ctx = tcp_server_create_with_host(argv[1], port_num, &app);

  if (!ctx) return -1;

  tcp_server_set_onopen(ctx, tcp_chat_on_open);
  tcp_server_set_onclose(ctx, tcp_chat_on_close);
  tcp_server_set_ondata(ctx, tcp_chat_on_data);

  tcp_server_start(ctx);
  tcp_server_destroy(ctx);

  free(app.name);
  hashmap_free(app.connections);
  
  return 0;
}

void tcp_chat_on_data(
  struct conn_state_t *conn, int opcode, const char *data, size_t length
) {
  if (opcode != WS_FR_OP_TXT) return;
  if (!data || length == 0) return;
  printf("Client #%ld send %ld bytes\n%s\n", tcp_server_connection_get_id(conn), length, data);
}
void tcp_chat_on_open(struct conn_state_t *conn) {
  printf("Client #%ld connected\n", tcp_server_connection_get_id(conn));
  struct app_data *app = (struct app_data *)tcp_server_connection_get_context(conn);
  if (!app) return;
  hashmap_put(app->connections, (char *)tcp_server_connection_get_ip(conn), conn);
}
void tcp_chat_on_close(struct conn_state_t *conn) {
  printf("Client #%ld disconnected\n", tcp_server_connection_get_id(conn));
  struct app_data *app = (struct app_data *)tcp_server_connection_get_context(conn);
  if (!app) return;
  hashmap_remove(app->connections, (char *)tcp_server_connection_get_ip(conn));
}
