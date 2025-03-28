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

map_t connections;
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

void queue_append(struct write_queue_t *queue, struct write_state_t *state) {
  if (queue->size == 0) {
    queue->head = state;
    queue->tail = state;
  } else {
    queue->tail->next = state;
    queue->tail = state;
  }
  queue->size++;
}

void queue_remove_front(struct write_queue_t *queue) {
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

void release_and_reset(struct conn_state_t *conn) {
  puts("Clearing");
  struct write_state_t *state = conn->queue.head;
  while (state != NULL) {
    safe_free(state->buf);
    state = state->next;
  }
  hashmap_remove(connections, conn->ip);
  close_handle(conn->fd);
  memset(conn, 0, sizeof(struct conn_state_t));
}


void parse_data_frame(struct conn_state_t *conn) {
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

void resume_write(int clientfd, struct conn_state_t* conn, int efd) {
  // data is already packed into frames if we were writing to websocket
  char *msg = conn->queue.head->buf;
  size_t remaining_bytes = conn->queue.head->msg_len - conn->queue.head->bytes_wrote;

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
            update_epoll(efd, clientfd, EPOLLIN | EPOLLET);
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

void write_to_socket(
  int clientfd, char* msg, size_t msg_len, struct conn_state_t* conn, int efd
) {
  size_t remaining_bytes = msg_len;
  size_t bytes_sent = 0;
  while (1) {
    size_t to_write = remaining_bytes < BUFFER_SIZE ? remaining_bytes : BUFFER_SIZE;
    ssize_t bytes_wrote = write(clientfd, msg + bytes_sent, to_write);
    if (bytes_wrote == -1) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        // we didn't fit it all - need to check again later
        update_epoll(efd, clientfd, EPOLLIN | EPOLLOUT | EPOLLET);
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

void accept_protocol_upgrade(int clientfd, struct conn_state_t *conn, char *key, int efd) {
  printf("Upgrading protocol for client %d\n", clientfd);
  const char *magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  unsigned char *buf = malloc((strlen(magic_string) + strlen(key)) * sizeof(char));
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
  write_to_socket(clientfd, response, strlen(response), conn, efd);
  conn->protocol = WEBSOCKET_PROTOCOL;
  safe_free(buf);
}

void parse_header(int clientfd, char *msg, struct conn_state_t *conn, int efd) {
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
        write_to_socket(clientfd, bad_request, strlen(bad_request), conn, efd);
        return;
      }
      line[strlen(line)] = ':';
      char *key = strtok(line, ": ") + strlen(line) + 2;
      accept_protocol_upgrade(clientfd, conn, key, efd);
    } else {
      puts("Not found");
      write_to_socket(
        clientfd, content_not_found, strlen(content_not_found), conn, efd
      );
    }
  } else {
    puts("Method not supported");
    write_to_socket(
      clientfd, method_not_supported, strlen(method_not_supported), conn, efd
    );
  }
}


void read_http_request(int clientfd, struct conn_state_t *conn, int efd) {
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
          clientfd, header_too_big, strlen(header_too_big), conn, efd
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
        parse_header(clientfd, buf, conn, efd);
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


char *decode_ws_message(struct conn_state_t *conn, size_t *decoded_msg_len) {
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

void enframe(size_t msg_len, char *frame, size_t *frame_len) {
  frame[0] = 0b10000001;
  if (msg_len <= 125) {
    frame[1] = msg_len & 127;
    *frame_len = 2;
  } else if (msg_len <= 65365) {
    frame[1] = 126;
    frame[2] = msg_len >> 4;  // probably not right
    frame[3] = msg_len << 4;
    *frame_len = 4;
  } else {
    // 8 next bytes
    // we aren't going to send messages that big
    ;
  }
}

void dispatch_clients_request(char *msg, struct conn_state_t *conn, int efd) {
  size_t frame_len;
  char frame[10];
  char *first_line = strtok(msg, "\n");
  char *payload = msg + strlen(first_line) + 1;
  char *action = strtok(first_line, " ");
  char *target = msg + strlen(action) + 1;
  int clientfd;
  int len = conn->buf_len - conn->skip - 2 - strlen(action) - strlen(target);
  char* extracted_payload = calloc(len, sizeof(char));
  if (!extracted_payload) {
    perror("allocate extracted_payload failed");
    exit(1);
  }
  memcpy(extracted_payload, payload, len);
  printf("%s\n", extracted_payload);
  int code = hashmap_get(connections, target, (void *)&clientfd);
  if (code != 0) {
    printf("%s not found, sending NOT_CONNECTED\n", target);
    char *buf = calloc(128, sizeof(char));
    if (!buf) {
      perror("allocate buffer failed");
      exit(1);
    }
    snprintf(buf, 128 + strlen(payload), "NOT_CONNECTED %s\n", target);
    enframe(strlen(buf), frame, &frame_len);
    write_to_socket(conn->fd, frame, frame_len, conn, efd);
    write_to_socket(conn->fd, buf, strlen(buf), conn, efd);
    safe_free(buf);
  } else {
    printf("Message from %s to %s, socket %d\n", conn->ip, target, clientfd);
    printf("Payload: %s\n", extracted_payload);
    char *buf = calloc(128 + strlen(payload), sizeof(char));
    if (!buf)  {
      perror("allocate buffer failed");
      exit(1);
    }
    snprintf(
      buf, 128 + strlen(extracted_payload), "MESSAGE_TO %s\n%s",
      conn->ip, extracted_payload
    );
    enframe(strlen(buf), frame, &frame_len);
    write_to_socket(clientfd, frame, frame_len, conn, efd);
    write_to_socket(clientfd, buf, strlen(buf), conn, efd);
    safe_free(buf);
    safe_free(extracted_payload);
  }
}


void read_ws_message(int clientfd, struct conn_state_t *conn, int efd) {
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
            ;
          } else {
            // process message
            dispatch_clients_request(decoded_msg, conn, efd);
          }
          safe_free(decoded_msg);
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
int main(int argc, char const *argv[]) {

  if (argc != 3) {
    puts("IP and PORT should be the only arguments\n ./chat_app_server <IP> <PORT>");
    exit(1);
  }

  struct conn_state_t conn_states[MAX_CLIENTS];
  memset(conn_states, 0, sizeof(conn_states));

  connections = hashmap_new();

  u_int16_t PORT = (u_int16_t) strtol(argv[2], (char **)NULL, 10);
  int sockfd = create_socket(argv[1], PORT);

  if (sockfd < 0) {
    perror("socket failed");
    exit(1);
  }

  if (!connections) {
    perror("allocate connection");
    exit(0);
  }

  int res = set_nonblocking(sockfd);
  if (res == -1) {
    perror("error on setting socket as non-blocking");
    exit(1);
  }

  res = listen(sockfd, 0);
  if (res == -1) {
    perror("listen error");
    exit(1);
  }

  int efd = epoll_create1(0);
  if (efd == -1) {
    perror("epoll create: ");
    exit(1);
  }

  res = add_to_epoll(efd, sockfd, EPOLLIN | EPOLLET);
  if (res == -1) {
    perror("on adding sockfd to epoll");
    exit(1);
  }

  struct epoll_event events[MAX_EVENTS];

  struct sockaddr_in client_info;
  size_t client_info_size = sizeof(struct sockaddr_in);
  memset(&client_info, 0, client_info_size);

  printf("Starting to listen on: %s:%d, socket %d\n", argv[1], PORT, sockfd);
  while (1) {

    puts("Epoll wait");
    int numready = epoll_wait(efd, events, MAX_EVENTS, -1);
    if (numready == -1) {
      perror("epoll_wait");
      exit(EXIT_FAILURE);
    }
    for (int i = 0; i < numready; ++i) {
      if (events[i].data.fd == sockfd) {
        int clientfd = accept(
          sockfd, (struct sockaddr *) &client_info,
          (socklen_t *) &client_info_size
        );
        if (clientfd == -1) {
          if (errno == EWOULDBLOCK || errno == EAGAIN) {
            // that can happen for some reason
            puts("EWOULDBLOCK || EAGAIN on accept");
          } else {
            perror("accept");
            exit(1);
          }
        } else {
          printf("Accepted %d\n", clientfd);
          // no error - mark as non blocking and add to epoll set
          res = set_nonblocking(clientfd);
          if (res == -1) {
            perror("error on setting socket as non-blocking");
            exit(1);
          }

          if (add_to_epoll(efd,clientfd, EPOLLIN) == -1) {
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
            memcpy(conn_states[clientfd].ip, key, strlen(key));
            conn_states[clientfd].fd = clientfd;
            hashmap_put(connections, key, &clientfd);
          } else {
            printf("Unable to get address\n");
            release_and_reset(&conn_states[clientfd]);
          }
        }
      } else {
        int clientfd = events[i].data.fd;
        struct conn_state_t *conn = &conn_states[events[i].data.fd];
        if (events[i].events & EPOLLOUT) {
          resume_write(clientfd, conn, efd);
        } else {
          if (conn->protocol == HTTP_PROTOCOL) {
            printf(
              "Http request from client %d, from %s\n", clientfd, conn->ip
            );
            read_http_request(clientfd, conn, efd);
          } else {
            printf(
              "WebSocket message from client %d, from %s\n", clientfd, conn->ip
            );
            read_ws_message(clientfd, conn, efd);
          }
        }
      }

    }
  }

  hashmap_free(connections);
  return 0;
}
