#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <errno.h>
#include <inttypes.h>
#include <math.h>

#include "hashmap.h"
#include "base64.h"
#include "sha1.h"
#include "server.h"

#ifndef BUFFER_SIZE
  #define BUFFER_SIZE 1024
#endif

#define WS_FR_OP_CONT 0
#define WS_FR_OP_TXT  1
#define WS_FR_OP_BIN  2
#define WS_FR_OP_CLSE 8
#define WS_FR_OP_PING 0x9
#define WS_FR_OP_PONG 0xA

#define MAX_EVENTS 1000
#define MAX_CLIENTS 1000
#define HTTP_PROTOCOL 0
#define WEBSOCKET_PROTOCOL 1

#define safe_free(p) { \
  if (p) {             \
    free(p);           \
    p = NULL;          \
  }                    \
}

#define close_handle(fd)                                          \
{                                                                 \
  if (fd != -1 && shutdown(fd, SHUT_RDWR) == 0 && close(fd) == 0) \
  {                                                               \
    fd = -1;                                                      \
  }                                                               \
}

char *header_too_big = "HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n";
char *content_not_found = "HTTP/1.1 404 Not Found\r\n\r\n";
char *method_not_supported = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";


struct write_state_t {
  struct write_state_t *next;
  char *buf;
  size_t msg_len;
  size_t bytes_wrote;
};

struct write_queue_t {
  struct write_state_t *head;
  struct write_state_t *tail;
  size_t size;
};

// used to store state of connection if we got partial read or write
struct conn_state_t {
  char protocol;  // 0 - HTTP, 1 - WebSocket
  int fd;
  char ip[36];
  size_t bytes_read;
  size_t buf_len;
  char *buf;
  size_t msg_len;
  char *msg;
  char data_frame_received;
  char opcode;
  char fin;
  char skip;
  char mask[4];
  // write needs a queue in case we had partial write and then read which
  // started another write
  struct write_queue_t queue;
  struct tcp_server_t *ctx;
};

struct tcp_server_t {
  int fd;
  int efd;
  struct conn_state_t conn_states[MAX_CLIENTS];
  void (*onopen)(struct conn_state_t *conn);
  void (*onclose)(struct conn_state_t *conn);
  void (*ondata)(struct conn_state_t *conn, int opcode, const char *data, size_t length);
  void *userdata;
};

static int add_to_epoll(int efd, int fd, uint32_t flags) {
  struct epoll_event ev;
  memset(&ev, 0, sizeof(struct epoll_event));
  ev.data.fd = fd;
  ev.events = flags;
  return epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
}

static int update_epoll(int efd, int fd, uint32_t flags) {
  struct epoll_event ev;
  memset(&ev, 0, sizeof(struct epoll_event));
  ev.data.fd = fd;
  ev.events = flags;
  return epoll_ctl(efd, EPOLL_CTL_MOD, fd, &ev);
}

static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void queue_append(struct write_queue_t *queue, struct write_state_t *state) {
  if (queue->size == 0) {
    queue->head = state;
    queue->tail = state;
  } else {
    queue->tail->next = state;
    queue->tail = state;
  }
  queue->size++;
}

static void queue_remove_front(struct write_queue_t *queue) {
  if (queue->size == 0)
    return;
  if (queue->size == 1) {
    safe_free(queue->head);
    memset(queue, 0, sizeof(struct write_queue_t));
    return;
  } else {
    struct write_state_t *temp = queue->head->next;
    safe_free(queue->head);
    queue->head = temp;
    queue->size--;
  }
}

static void release_and_reset(struct conn_state_t *conn) {
  puts("Clearing");
  struct write_state_t *state = conn->queue.head;

  if (conn->protocol == WEBSOCKET_PROTOCOL) {
    if (conn->ctx && *conn->ctx->onclose) {
      (*conn->ctx->onclose)(conn);
    }
  }

  while (state != NULL) {
    safe_free(state->buf);
    state = state->next;
  }

  close_handle(conn->fd);
  memset(conn, 0, sizeof(struct conn_state_t));
}


static void parse_data_frame(struct conn_state_t *conn) {
  if (conn->bytes_read < 6)
    return;

  char *buf = conn->buf;
  size_t msg_len = (unsigned int) (*(buf + 1) & 127);
  conn->fin = (buf[0] & 128) ? (char) 1 : (char) 0;
  conn->opcode = buf[0] & 0b00001111;
  if (msg_len <= 125) {
    conn->skip = 6;
    conn->buf_len = msg_len + conn->skip;
    memcpy(conn->mask, buf + 2, sizeof(conn->mask));
    conn->data_frame_received = 1;
  } else if (msg_len == 126 && conn->bytes_read >= 8) {
    uint16_t u16;
    memcpy(&u16, buf + 2, sizeof(uint16_t));
    conn->skip = 8;
    conn->buf_len = ntohs(u16) + conn->skip;
    memcpy(conn->mask, buf + 4, sizeof(conn->mask));
    conn->data_frame_received = 1;
  } else if (msg_len == 127 && conn->bytes_read >= 14) {
    uint64_t u64;
    memcpy(&u64, buf + 2, sizeof(uint64_t));
    conn->skip = 14;
    conn->buf_len = (size_t) be64toh(u64) + conn->skip;
    memcpy(conn->mask, buf + 10, sizeof(conn->mask));
    conn->data_frame_received = 1;
  }
}

static void resume_write(int clientfd, struct conn_state_t* conn) {
  // data is already packed into frames if we were writing to websocket
  char *msg = conn->queue.head->buf;
  size_t remaining_bytes = conn->queue.head->msg_len - conn->queue.head->bytes_wrote;
  struct tcp_server_t *ctx = conn->ctx;

  while (1) {
    size_t offset = conn->queue.head->bytes_wrote;
    size_t to_write = remaining_bytes < BUFFER_SIZE ? remaining_bytes : BUFFER_SIZE;
    ssize_t bytes_wrote = write(clientfd, msg + offset, to_write);
    if (bytes_wrote == -1) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        // we didn't fit it all - need to check again later
        // epoll is still polling for write, no need to rearm the descriptor
        break;
      } else if (errno == EPIPE) {
        printf("Client %d has terminated connection\n", clientfd);
        release_and_reset(conn);
        break;
      } else {
        remaining_bytes -= bytes_wrote;
        conn->queue.head->bytes_wrote += bytes_wrote;
        if (remaining_bytes == 0) {
          // were done -> remove head from queue and start writing next
          // message. Stop polling for write event
          // and return if there are no enqueued operations
          queue_remove_front(
                &conn->queue);
          if (conn->queue.size == 0) {
            if (ctx)
              update_epoll(ctx->efd, clientfd, EPOLLIN | EPOLLET);
            break;
          } else {
            // update variables so that next write starts to write next message
            msg = conn->queue.head->buf;
            remaining_bytes =
                    conn->queue.head->msg_len - conn->queue.head->bytes_wrote;
          }
        }
        // otherwise continue writing until we get EAGAIN or finish the write
      }
    }
  }
}

static void write_to_socket(
  int clientfd, char* msg, size_t msg_len, struct conn_state_t* conn
) {
  size_t remaining_bytes = msg_len;
  size_t bytes_sent = 0;
  struct tcp_server_t *ctx = conn->ctx;
  while (1) {
    size_t to_write = remaining_bytes < BUFFER_SIZE ? remaining_bytes : BUFFER_SIZE;
    ssize_t bytes_wrote = write(clientfd, msg + bytes_sent, to_write);
    if (bytes_wrote == -1) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        // we didn't fit it all - need to check again later
        if (ctx)
          update_epoll(ctx->efd, clientfd, EPOLLIN | EPOLLOUT | EPOLLET);
        // also save the state
        struct write_state_t* state = calloc(1, sizeof(struct write_state_t));
        if (!state) {
          perror("calloc struct write_state_t");
          exit(1);
        }
        state->buf = malloc(remaining_bytes * sizeof(char));
        memcpy(state->buf, msg + bytes_sent, remaining_bytes);
        state->msg_len = remaining_bytes;
        state->bytes_wrote = 0;
        queue_append(&conn->queue, state);
      } else if (errno == EPIPE) {
        printf("Client %d has terminated connection\n", clientfd);
        release_and_reset(conn);
        break;
      } else {
        perror("Error on writing to client");
        exit(1);
      }
    } else {
      bytes_sent += bytes_wrote;
      remaining_bytes -= bytes_wrote;
      if (remaining_bytes == 0) {
        // were done
        break;
      }
      // else continue
    }
  }
}

static void accept_protocol_upgrade(int clientfd, struct conn_state_t *conn, char *key) {
  printf("Upgrading protocol for client %d\n", clientfd);
  const char *magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  unsigned char buf[255] = {0};
  memcpy(buf, key, strlen(key));
  memcpy(buf + strlen(key), magic_string, strlen(magic_string));
  unsigned char sha1_result[SHA1_BLOCK_SIZE];
  memset(sha1_result, 0, sizeof(sha1_result));
  SHA1(buf, strlen(buf), sha1_result);
  char encodedData[120];
  memset(encodedData, 0, sizeof(encodedData));
  base64_encode((const unsigned char *)sha1_result, SHA1_BLOCK_SIZE, encodedData);
  const char *response_template =
    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection:"
    " Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n";
  char response[256];
  sprintf(response, response_template, encodedData);
  write_to_socket(clientfd, response, strlen(response), conn);
  conn->protocol = WEBSOCKET_PROTOCOL;

  if (!conn->ctx) return;
  if (*conn->ctx->onopen) {
    (*conn->ctx->onopen)(conn);
  }
}

static void parse_header(int clientfd, char *msg, struct conn_state_t *conn) {
  char *first_line = strtok(msg, "\r\n");
  char *rest = msg + strlen(first_line) + 2;
  char *method = strtok(first_line, " ");
  char *resource = strtok(NULL, " ");

  if (strcmp(method, "GET") == 0) {
    // protocol upgrade
     if (strcmp(resource, "/chat") == 0) {
      char *line = strtok(rest, "\r\n");
      size_t len = strlen(line);
      line = strtok(line, ":");
      line = line + len + 2;
      while (line != NULL) {
        line = strtok(line, "\r\n");
        len = strlen(line);
        line = strtok(line, ":");
        if (strcmp(line, "Sec-WebSocket-Key") == 0)
          break;
        else
          line = line + len + 2;
      }
      if (line == NULL) {
        puts("Bad request");
        write_to_socket(clientfd, bad_request, strlen(bad_request), conn);
        return;
      }
      line[strlen(line)] = ':';
      char *key = strtok(line, ": ") + strlen(line) + 2;
      accept_protocol_upgrade(clientfd, conn, key);
    } else {
      puts("Not found");
      write_to_socket(
        clientfd, content_not_found, strlen(content_not_found), conn
      );
    }
  } else {
    puts("Method not supported");
    write_to_socket(
      clientfd, method_not_supported, strlen(method_not_supported), conn
    );
  }
}

static void read_http_request(int clientfd, struct conn_state_t *conn) {
  char finished = 0;
  // if read is not resumed allocate some space
  if (conn->bytes_read == 0) {
    conn->buf = calloc(BUFFER_SIZE, sizeof(char));
    if (!conn->buf) {
      perror("alloc buffer fail");
      exit(1);
    }
    conn->buf_len = BUFFER_SIZE;
  }
  while (1) {
    ssize_t bytes_read = read(clientfd, conn->buf + conn->bytes_read,
                      conn->buf_len - conn->bytes_read);
    if (bytes_read == -1) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        if (finished) {
          safe_free(conn->buf);
          conn->bytes_read = 0;
          conn->buf_len = 0;
        }
        break;
      } else {
        perror("On reading http request");
        exit(1);
      }
    } else if (bytes_read == 0) {
      printf("Client %d has disconnected\n", clientfd);
      release_and_reset(conn);
      break;
    } else {
      // we expected EAGAIN but new data arrived
      finished = 0;
      conn->bytes_read += bytes_read;
      if (conn->bytes_read > conn->buf_len) {
        // header too big
        write_to_socket(
          clientfd, header_too_big, strlen(header_too_big), conn
        );
        finished = 1;
      }
      char *delim = "\r\n\r\n";
      char *p = strstr(conn->buf + conn->bytes_read - bytes_read, delim);
      size_t bytes_after_header = 0;
      while (p != NULL) {
        // found header
        // since we don't expect anything in a request body, any data after
        // header is part of (or a whole) new header
        p = p + strlen(delim);
        size_t header_len = p - conn->buf;
        bytes_after_header = conn->bytes_read - header_len;
        char *buf = malloc(header_len * sizeof(char));
        if (!buf) {
          perror("allocate buffer fail");
          exit(1);
        }
        memcpy(buf, conn->buf, header_len);
        parse_header(clientfd, buf, conn);
        safe_free(buf);
        memcpy(conn->buf, conn->buf + header_len, bytes_after_header);
        memset(
          conn->buf + bytes_after_header, 0, conn->buf_len - bytes_after_header
        );
        conn->bytes_read = bytes_after_header;
        p = strstr(conn->buf, delim);
      }
      if (bytes_after_header == 0)
        finished = 1;
    }
    //else continue reading
  }
}

static char *decode_ws_message(struct conn_state_t *conn, size_t *decoded_msg_len) {
  char *payload = conn->buf + conn->skip;
  *decoded_msg_len = conn->buf_len - conn->skip;
  char *msg = calloc(*decoded_msg_len, sizeof(char));
  if (!msg) {
    perror("allocate msg failed");
    exit(1);
  }
  for (int i = 0; i < *decoded_msg_len; ++i)
    msg[i] = payload[i] ^ conn->mask[i % 4];
  return msg;
}

static void dispatch_clients_request(char *msg, struct conn_state_t *conn, size_t length) {
  if (!conn->ctx) return;
  if (*conn->ctx->ondata) {
    (*conn->ctx->ondata)(conn, conn->opcode, msg, length);
  }
}

static void read_ws_message(int clientfd, struct conn_state_t *conn) {
  char finished = 0;
  // if read is not resumed allocate some space
  if (conn->bytes_read == 0) {
    conn->buf = calloc(BUFFER_SIZE, sizeof(char));
    if (!conn->buf)  {
      perror("allocate buffer failed");
      exit(1);
    }
    conn->buf_len = BUFFER_SIZE;
  }
  while (1) {
    ssize_t bytes_read = read(clientfd, conn->buf + conn->bytes_read,
                      conn->buf_len - conn->bytes_read);
    if (bytes_read == -1) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        if (finished) {
          safe_free(conn->buf);
        }
        break;
      } else {
        perror("on reading from websocket");
        exit(1);
      }
    } else if (bytes_read == 0) {
      printf("Client %d has disconnected", clientfd);
      release_and_reset(conn);
      break;
    } else {
      // we expected EAGAIN but new data arrived
      finished = 0;
      conn->bytes_read += bytes_read;
      // that needs to be done only once
      if (!conn->data_frame_received) {
        size_t old_buf_len = conn->buf_len;
        parse_data_frame(conn);
        if (conn->buf_len > old_buf_len) {
          // allocate more space
          char *new_buffer = calloc(conn->buf_len, sizeof(char));
          if (!new_buffer) {
            perror("allocate new buffer failed");
            exit(1);
          }
          memcpy(new_buffer, conn->buf, conn->bytes_read);
          safe_free(conn->buf);
          conn->buf = new_buffer;
        }
      }
      while (conn->bytes_read >= conn->buf_len) {
        // we had more than one message or more in the buffer
        size_t decoded_msg_len;
        char *decoded_msg = decode_ws_message(conn, &decoded_msg_len);
        if (decoded_msg_len == 2) {
          puts("Closing handshake");
          release_and_reset(conn);
          return;
        }
        if (conn->fin) {
          if (conn->opcode == WS_FR_OP_PING) {
            // it's a ping
            tcp_server_send(conn, WS_FR_OP_PONG, NULL, 0);
          } else {
            // process message
            dispatch_clients_request(decoded_msg, conn, decoded_msg_len);
          }
          safe_free(decoded_msg);
        } else if (conn->opcode == WS_FR_OP_CLSE) {
          // it's a close
          puts("Closing handshake");
          release_and_reset(conn);
          return;
        } else if (conn->opcode == WS_FR_OP_TXT ||
               conn->opcode == WS_FR_OP_BIN) {
          // new message that will be continued, were saving it
          conn->msg = decoded_msg;
          conn->msg_len = decoded_msg_len;
        } else if (conn->opcode == WS_FR_OP_CONT) {
          // continuation of a message
          char *new_buffer = calloc(decoded_msg_len + conn->msg_len, sizeof(char));
          if (!new_buffer) {
            perror("allocate new buffer failed");
            exit(1);
          }
          memcpy(new_buffer, conn->msg, conn->msg_len);
          memcpy(new_buffer + conn->msg_len, decoded_msg, decoded_msg_len);
          conn->msg_len += decoded_msg_len;
        }
        memcpy(conn->buf, conn->buf + conn->buf_len,
             conn->bytes_read - conn->buf_len);
        memset(conn->buf + conn->bytes_read - conn->buf_len, 0, conn->buf_len);
        conn->bytes_read -= conn->buf_len;
        conn->data_frame_received = 0;
        if (conn->bytes_read == 0) {
          finished = 1;
        } else if (conn->bytes_read > 0) {
          // if there was another message, or at least its frame we need
          // to extract the information here
          size_t old_buf_len = conn->buf_len;
          parse_data_frame(conn);
          if (conn->buf_len > old_buf_len) {
            // allocate more space
            char *new_buffer = calloc(conn->buf_len, sizeof(char));
            if (!new_buffer) {
              perror("allocate new buffer failed");
              exit(1);
            }
            memcpy(new_buffer, conn->buf, conn->bytes_read);
            safe_free(conn->buf);
            conn->buf = new_buffer;
          }
        }
      }
    }
  }
}
static int create_socket(const char *bind_addr, uint16_t bind_port) {
  int ret, on = 1;
  int tcp_fd = -1;
  struct addrinfo hints, *result, *rp;
  char port[20] = {0};

  if (sprintf(port, "%d", bind_port) <= 0)
  {
    perror("sprintf(): ");
    return -1;
  }

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  if (getaddrinfo(bind_addr, port, &hints, &result) != 0) {
    perror("getaddrinfo(): ");
    return -1;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    tcp_fd = socket(
      rp->ai_family, rp->ai_socktype, rp->ai_protocol
    );
    if (tcp_fd < 0) continue;

    ret = setsockopt(
      tcp_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on)
    );

    if (ret == 0 && bind(tcp_fd, rp->ai_addr, rp->ai_addrlen) == 0) {
      break;
    }
    close_handle(tcp_fd);
  }

  freeaddrinfo(result);

  if (rp == NULL || tcp_fd < 0) {
    return -1;
  }
  return tcp_fd;
}
struct tcp_server_t *tcp_server_create(uint16_t port, void *userdata) {
  return tcp_server_create_with_host(NULL, port, userdata);
}
struct tcp_server_t *tcp_server_create_with_host(const char *host, uint16_t port, void *userdata) {
  struct tcp_server_t *ctx = (struct tcp_server_t *)calloc(1, sizeof(struct tcp_server_t));
  int res;

  if (!ctx) return NULL;

  memset(ctx->conn_states, 0, sizeof(ctx->conn_states));

  ctx->onopen = NULL;
  ctx->ondata = NULL;
  ctx->onclose = NULL;

  ctx->userdata = userdata;

  ctx->fd = create_socket(host, port);
  if (ctx->fd < 0) {
    #ifndef NDEBUG
    perror("socket error");
    #endif
    safe_free(ctx);
    return NULL;
  }

  res = set_nonblocking(ctx->fd);
  if (res == -1) {
    perror("error on setting socket as non-blocking");
    close_handle(ctx->fd);
    safe_free(ctx);
    return NULL;
  }

  res = listen(ctx->fd, 0);
  if (res == -1) {
    perror("listen error");
    close_handle(ctx->fd);
    safe_free(ctx);
    return NULL;
  }

  ctx->efd = epoll_create1(0);
  if (ctx->efd == -1) {
    perror("epoll create: ");
    close_handle(ctx->fd);
    safe_free(ctx);
    return NULL;
  }

  res = add_to_epoll(ctx->efd, ctx->fd, EPOLLIN | EPOLLET);
  if (res == -1) {
    perror("on adding sockfd to epoll");
    close_handle(ctx->fd);
    close_handle(ctx->efd);
    safe_free(ctx);
    return NULL;
  }

  return ctx;
}

void tcp_server_set_onopen(struct tcp_server_t *ctx, void (*callback)(struct conn_state_t *conn)) {
  if (!ctx) return;
  ctx->onopen = callback;
}

void tcp_server_set_onclose(struct tcp_server_t *ctx, void (*callback)(struct conn_state_t *conn)) {
  if (!ctx) return;
  ctx->onclose = callback;
}

void tcp_server_set_ondata(struct tcp_server_t *ctx, void (*callback)(struct conn_state_t *conn, int opcode, const char *data, size_t length)) {
  if (!ctx) return;
  ctx->ondata = callback;
}

int tcp_server_start(struct tcp_server_t *ctx) {
  struct epoll_event events[MAX_EVENTS];
  int res, i, numready, clientfd;

  struct sockaddr_in client_info;
  size_t client_info_size = sizeof(struct sockaddr_in);
  struct conn_state_t *conn = NULL;

  if (!ctx) return -1;

  memset(&client_info, 0, client_info_size);

  printf("Starting to listen socket %d\n", ctx->fd);

  while (1) {
    puts("Epoll wait");
    numready = epoll_wait(ctx->efd, events, MAX_EVENTS, -1);
    if (numready == -1) {
      perror("epoll_wait");
      return -1;
    }
    for (i = 0; i < numready; ++i) {
      if (events[i].data.fd == ctx->fd) {
        clientfd = accept(
          ctx->fd, (struct sockaddr *) &client_info,
          (socklen_t *) &client_info_size
        );
        if (clientfd == -1) {
          if (errno == EWOULDBLOCK || errno == EAGAIN) {
            /* that can happen for some reason */
            puts("EWOULDBLOCK || EAGAIN on accept");
          } else {
            perror("accept");
            exit(1);
          }
        } else {
          printf("Accepted %d\n", clientfd);
          /* no error - mark as non blocking and add to epoll set */
          res = set_nonblocking(clientfd);
          if (res == -1) {
            perror("error on setting socket as non-blocking");
            exit(1);
          }

          if (add_to_epoll(ctx->efd, clientfd, EPOLLIN) == -1) {
            perror("epoll_ctl: on adding client socked");
            exit(1);
          }
          // get client's info and add to hashmap
          char client_name[INET6_ADDRSTRLEN];
          char port_name[6];
          if (getnameinfo((const struct sockaddr *) &client_info,
                        sizeof client_info,
                        client_name, sizeof(client_name), NULL, 0,
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            char *key = calloc(1, strlen(client_name));
            if (!key) {
              perror("allocate key failed");
              exit(1);
            }
            memcpy(key, client_name, strlen(client_name));
            printf("New client with IP %s\n", key);
            memcpy(ctx->conn_states[clientfd].ip, key, strlen(key));
            ctx->conn_states[clientfd].fd = clientfd;
            ctx->conn_states[clientfd].ctx = ctx;
          } else {
            printf("Unable to get address\n");
            release_and_reset(&ctx->conn_states[clientfd]);
          }
        }
      } else {
        clientfd = events[i].data.fd;
        conn = &ctx->conn_states[events[i].data.fd];
        if (events[i].events & EPOLLOUT) {
          resume_write(clientfd, conn);
        } else {
          if (conn->protocol == HTTP_PROTOCOL) {
            printf("Http request from client %d, from %s\n",
              clientfd, conn->ip);
            read_http_request(clientfd, conn);
          } else {
            printf("WebSocket message from client %d, from %s\n",
              clientfd, conn->ip);
            read_ws_message(clientfd, conn);
          }
        }
      }

    }
  }

  return 0;
}

void tcp_server_destroy(struct tcp_server_t *ctx) {
  if (!ctx) return;
  close_handle(ctx->fd);
  close_handle(ctx->efd);
  safe_free(ctx);
}
size_t tcp_server_connection_get_id(struct conn_state_t *conn) {
  if (!conn) return 0;
  return (size_t)conn->fd;
}
void *tcp_server_connection_get_context(struct conn_state_t *conn) {
  if (!conn || !conn->ctx) return NULL;
  return conn->ctx->userdata;
}
const char * tcp_server_connection_get_ip(struct conn_state_t *conn) {
  if (!conn) return NULL;
  return conn->ip;
}

void tcp_server_send_text(struct conn_state_t *conn, const char *data) {
  tcp_server_send(conn, WS_FR_OP_TXT, data, data ? strlen(data) : 0);
}
void tcp_server_send(struct conn_state_t *conn, int opcode, const char *data, size_t len) {
  size_t frame_len = 0, head_len = 0, flen, i;
  char *buf = NULL;
  if (opcode == WS_FR_OP_TXT || opcode == WS_FR_OP_BIN) {
    if (!data || len == 0) return;
  }
  if (!conn || conn->protocol != WEBSOCKET_PROTOCOL) return;
  if (len <= 125) {
    head_len = 2;
  } else if (len <= 65535) {
    head_len = 4;
  } else {
    head_len = 10;
  }
  frame_len = len + head_len;
  buf = calloc(frame_len, sizeof(char));
  if (!buf) return;
  buf[0] = 0x80 | opcode;
  if (head_len == 2) {
    buf[1] = len;
  } else if (head_len == 4) {
    buf[1] = 126;
    buf[2] = (len >> 8) & 0xff;
    buf[3] = len & 0xff;
  } else {
    buf[1] = 127;
    flen = len;
    for (i = 2; i < 10; i++) {
      buf[i] = flen & 0xff;
      flen >>= 8;
    }
  }
  if (data)
    memcpy(buf + head_len, data, len);

  write_to_socket(conn->fd, buf, frame_len, conn);
  safe_free(buf);
} 
void tcp_server_send_boardcast(struct conn_state_t *conn, int opcode, const char *data, size_t len) {
  int i;
  struct tcp_server_t *ctx;
  if (!conn || !conn->ctx) return;
  ctx = conn->ctx;
  for (i = 0; i < MAX_CLIENTS; i++) {
    if (ctx->conn_states[i].fd > 0 && ctx->conn_states[i].fd == conn->fd) {
      tcp_server_send(&ctx->conn_states[i], opcode, data, len);
    }
  }
}
void tcp_server_send_all(struct tcp_server_t *ctx, int opcode, const char *data, size_t len) {
  int i;
  if (!ctx) return;
  for (i = 0; i < MAX_CLIENTS; i++) {
    if (ctx->conn_states[i].fd > 0)
      tcp_server_send(&ctx->conn_states[i], opcode, data, len);
  }
}

void tcp_server_close_connection(struct conn_state_t *cli) {
  tcp_server_close_connection_reason(cli, 1000);
}
void tcp_server_close_connection_reason(struct conn_state_t *cli, int code) {
  unsigned char clse_code[2];
  clse_code[0] = (code >> 8);
  clse_code[1] = (code & 0xff);
  tcp_server_send(cli, WS_FR_OP_CLSE, (const char *)clse_code, 2);
}
void tcp_server_send_ping(struct conn_state_t *cli) {
  tcp_server_send(cli, WS_FR_OP_PING, NULL, 0);
}
void tcp_server_ping_all(struct tcp_server_t *ctx) {
  tcp_server_send_all(ctx, WS_FR_OP_PING, NULL, 0);
}
