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
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <inttypes.h>
#include <math.h>

#include "hashmap.h"

#define MAX_EVENTS 1000
#define MAX_CLIENTS 1000
#define HTTP_PROTOCOL 0
#define WEBSOCKET_PROTOCOL 1

map_t connections;
char *header_too_big = "HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n";
char *content_not_found = "HTTP/1.1 404 Not Found\r\n\r\n";
char *method_not_supported = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";


struct write_state {
    struct write_state *next;
    char *buf;
    size_t msg_len;
    size_t bytes_wrote;
};


struct write_queue {
    struct write_state *head;
    struct write_state *tail;
    size_t size;
};


struct conn_state {         //used to store state of connection if we got partial read or write
    char protocol;          //0 - HTTP, 1 - WebSocket
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
    struct write_queue write_queue;    //write needs a queue in case we had partial write and then read which started another write
};


void append(struct write_queue *write_queue, struct write_state *write_state) {
    if (write_queue->size == 0) {
        write_queue->head = write_state;
        write_queue->tail = write_state;
    } else {
        write_queue->tail->next = write_state;
        write_queue->tail = write_state;
    }
    write_queue->size++;
}

void remove_front(struct write_queue *write_queue) {
    if (write_queue->size == 0)
        return;
    if (write_queue->size == 1) {
        free(write_queue->head);
        memset(write_queue, 0, sizeof(struct write_queue));
        return;
    } else {
        struct write_state *temp = write_queue->head->next;
        free(write_queue->head);
        write_queue->head = temp;
        write_queue->size--;
    }
}

void release_and_reset(struct conn_state *conn_state) {
    puts("Clearing");
    struct write_state *write_state = conn_state->write_queue.head;
    while (write_state != NULL) {
        free(write_state->buf);
        write_state = write_state->next;
    }
    hashmap_remove(connections, conn_state->ip);
    close(conn_state->fd);
    memset(conn_state, 0, sizeof(struct conn_state));
}


void parse_data_frame(struct conn_state *conn_state) {
    if (conn_state->bytes_read < 6)
        return;
    char *buf = conn_state->buf;
    size_t msg_len = (unsigned int) (*(buf + 1) & 127);
    conn_state->fin = (buf[0] & 128) ? (char) 1 : (char) 0;
    conn_state->opcode = buf[0] & 0b00001111;
    if (msg_len <= 125) {
        conn_state->skip = 6;
        conn_state->buf_len = msg_len + conn_state->skip;
        memcpy(conn_state->mask, buf + 2, sizeof(conn_state->mask));
        conn_state->data_frame_received = 1;
    } else if (msg_len == 126 && conn_state->bytes_read >= 8) {
        uint16_t u16;
        memcpy(&u16, buf + 2, sizeof(uint16_t));
        conn_state->skip = 8;
        conn_state->buf_len = ntohs(u16) + conn_state->skip;
        memcpy(conn_state->mask, buf + 4, sizeof(conn_state->mask));
        conn_state->data_frame_received = 1;
    } else if (msg_len == 127 && conn_state->bytes_read >= 14) {
        uint64_t u64;
        memcpy(&u64, buf + 2, sizeof(uint64_t));
        conn_state->skip = 14;
        conn_state->buf_len = (size_t) be64toh(u64) + conn_state->skip;
        memcpy(conn_state->mask, buf + 10, sizeof(conn_state->mask));
        conn_state->data_frame_received = 1;
    }
}

void resume_write(int clientfd, struct conn_state* conn_state, int efd) {
    //data is already packed into frames if we were writing to websocket
    char *msg = conn_state->write_queue.head->buf;
    size_t remaining_bytes = conn_state->write_queue.head->msg_len - conn_state->write_queue.head->bytes_wrote;
    while (1) {
        size_t offset = conn_state->write_queue.head->bytes_wrote;
        size_t to_write = remaining_bytes < 4096 ? remaining_bytes : 4096;
        ssize_t bytes_wrote = write(clientfd, msg + offset, to_write);
        if (bytes_wrote == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                //we didn't fit it all - need to check again later
                //epoll is still polling for write, no need to rearm the descriptor
                break;
            } else if (errno == EPIPE) {
                printf("Client %d has terminated connection\n", clientfd);
                release_and_reset(conn_state);
                break;
            } else {
                remaining_bytes -= bytes_wrote;
                conn_state->write_queue.head->bytes_wrote += bytes_wrote;
                if (remaining_bytes == 0) {
                    //were done -> remove head from queue and start writing next message. Stop polling for write event
                    remove_front(
                            &conn_state->write_queue);                            //and return if there are no enqueued operations
                    if (conn_state->write_queue.size == 0) {
                        struct epoll_event event;
                        memset(&event, 0, sizeof(event));
                        event.data.fd = clientfd;
                        event.events = EPOLLIN | EPOLLET;
                        epoll_ctl(efd, EPOLL_CTL_MOD, clientfd, &event);
                        break;
                    } else {
                        //update variables so that next write starts to write next message
                        msg = conn_state->write_queue.head->buf;
                        remaining_bytes =
                                conn_state->write_queue.head->msg_len - conn_state->write_queue.head->bytes_wrote;
                    }
                }
                //otherwise continue writing until we get EAGAIN or finish the write
            }
        }
    }
}

void write_to_socket(int clientfd, char* msg, size_t msg_len, struct conn_state* conn_state, int efd) {
    size_t remaining_bytes = msg_len;
    size_t bytes_sent = 0;
    while (1) {
        size_t to_write = remaining_bytes < 4096 ? remaining_bytes : 4096;
        ssize_t bytes_wrote = write(clientfd, msg + bytes_sent, to_write);
        if (bytes_wrote == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                //we didn't fit it all - need to check again later
                struct epoll_event event;
                memset(&event, 0, sizeof(event));
                event.events = EPOLLIN | EPOLLOUT | EPOLLET;
                event.data.fd = clientfd;
                epoll_ctl(efd, EPOLL_CTL_MOD, clientfd, &event);
                //also save the state
                struct write_state* write_state = calloc(1, sizeof(struct write_state));
                write_state->buf = malloc(remaining_bytes * sizeof(char));
                memcpy(write_state->buf, msg + bytes_sent, remaining_bytes);
                write_state->msg_len = remaining_bytes;
                write_state->bytes_wrote = 0;
                append(&conn_state->write_queue, write_state);
            } else if (errno == EPIPE) {
                printf("Client %d has terminated connection\n", clientfd);
                release_and_reset(conn_state);
                break;
            } else {
                perror("Error on writing to client");
                exit(1);
            }
        } else {
            bytes_sent += bytes_wrote;
            remaining_bytes -= bytes_wrote;
            if (remaining_bytes == 0) {
                //were done
                break;
            }
            //else continue
        }
    }
}

void accept_protocol_upgrade(int clientfd, struct conn_state *conn_state, char *key, int efd) {
    printf("Upgrading protocol for client %d\n", clientfd);
    const char *magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char *buf = malloc((strlen(magic_string) + strlen(key)) * sizeof(char));
    memcpy(buf, key, strlen(key));
    memcpy(buf + strlen(key), magic_string, strlen(magic_string));
    unsigned char sha1_result[20];
    memset(sha1_result, 0, sizeof(sha1_result));
    SHA1(buf, strlen(buf), sha1_result);
    char encodedData[120];
    memset(encodedData, 0, sizeof(encodedData));
    EVP_EncodeBlock((unsigned char *) encodedData, sha1_result, sizeof(sha1_result));
    const char *response_template = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n";
    char response[256];
    sprintf(response, response_template, encodedData);
    write_to_socket(clientfd, response, strlen(response), conn_state, efd);
    conn_state->protocol = WEBSOCKET_PROTOCOL;
    free(buf);
}

void parse_header(int clientfd, char *msg, struct conn_state *conn_state, int efd) {
    char *first_line = strtok(msg, "\r\n");
    char *rest = msg + strlen(first_line) + 2;
    char *method = strtok(first_line, " ");
    char *resource = strtok(NULL, " ");
    if (strcmp(method, "GET") == 0) {
       if (strcmp(resource, "/chat") == 0) {    //protocol upgrade
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
                write_to_socket(clientfd, bad_request, strlen(bad_request), conn_state, efd);
                return;
            }
            line[strlen(line)] = ':';
            char *key = strtok(line, ": ") + strlen(line) + 2;
            accept_protocol_upgrade(clientfd, conn_state, key, efd);
        } else {
            puts("Not found");
            write_to_socket(clientfd, content_not_found, strlen(content_not_found), conn_state, efd);
        }
    } else {
        puts("Method not supported");
        write_to_socket(clientfd, method_not_supported, strlen(method_not_supported), conn_state, efd);
    }
}


void read_http_request(int clientfd, struct conn_state *conn_state, int efd) {
    char finished = 0;
    if (conn_state->bytes_read == 0) {                          //if read is not resumed allocate some space
        conn_state->buf = calloc(1024, sizeof(char));
        conn_state->buf_len = 1024;
    }
    while (1) {
        ssize_t bytes_read = read(clientfd, conn_state->buf + conn_state->bytes_read,
                                  conn_state->buf_len - conn_state->bytes_read);
        if (bytes_read == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                if (finished) {
                    free(conn_state->buf);
                    conn_state->bytes_read = 0;
                    conn_state->buf_len = 0;
                }
                break;
            } else {
                perror("On reading http request");
                exit(1);
            }
        } else if (bytes_read == 0) {
            printf("Client %d has disconnected\n", clientfd);
            release_and_reset(conn_state);
            break;
        } else {
            finished = 0;       //we expected EAGAIN but new data arrived
            conn_state->bytes_read += bytes_read;
            if (conn_state->bytes_read > conn_state->buf_len) {
                //header too big
                write_to_socket(clientfd, header_too_big, strlen(header_too_big), conn_state, efd);
                finished = 1;
            }
            char *delim = "\r\n\r\n";
            char *p = strstr(conn_state->buf + conn_state->bytes_read - bytes_read, delim);
            size_t bytes_after_header = 0;
            while (p != NULL) {
                //found header
                //since we don't expect anything in a request body, any data after header is part of (or a whole) new header
                p = p + strlen(delim);
                size_t header_len = p - conn_state->buf;
                bytes_after_header = conn_state->bytes_read - header_len;
                char *buf = malloc(header_len * sizeof(char));
                memcpy(buf, conn_state->buf, header_len);
                parse_header(clientfd, buf, conn_state, efd);
                free(buf);
                memcpy(conn_state->buf, conn_state->buf + header_len, bytes_after_header);
                memset(conn_state->buf + bytes_after_header, 0, conn_state->buf_len - bytes_after_header);
                conn_state->bytes_read = bytes_after_header;
                p = strstr(conn_state->buf, delim);
            }
            if (bytes_after_header == 0)
                finished = 1;
        }
        //else continue reading
    }
}


char *decode_ws_message(struct conn_state *conn_state, size_t *decoded_msg_len) {
    char *payload = conn_state->buf + conn_state->skip;
    *decoded_msg_len = conn_state->buf_len - conn_state->skip;
    char *msg = calloc(*decoded_msg_len, sizeof(char));
    for (int i = 0; i < *decoded_msg_len; ++i)
        msg[i] = payload[i] ^ conn_state->mask[i % 4];
    return msg;
}

void enframe(size_t msg_len, char *frame, size_t *frame_len) {
    frame[0] = 0b10000001;
    if (msg_len <= 125) {
        frame[1] = msg_len & 127;
        *frame_len = 2;
    } else if (msg_len <= 65365) {
        frame[1] = 126;
        frame[2] = msg_len >> 4;        //probably not right
        frame[3] = msg_len << 4;
        *frame_len = 4;
    } else {
        //8 next bytes
        //we aren't going to send messages that big
        ;
    }
}


void dispatch_clients_request(char *msg, struct conn_state *conn_state, int efd) {
    size_t frame_len;
    char frame[10];
    char *first_line = strtok(msg, "\n");
    char *payload = msg + strlen(first_line) + 1;
    char *action = strtok(first_line, " ");
    char *target = msg + strlen(action) + 1;
    int clientfd;
    int len = conn_state->buf_len - conn_state->skip - 2 - strlen(action) - strlen(target);
    char* extracted_payload = calloc(len, sizeof(char));
    memcpy(extracted_payload, payload, len);
    printf("%s\n", extracted_payload);
    int code = hashmap_get(connections, target, &clientfd);
    if (code != 0) {
        printf("%s not found, sending NOT_CONNECTED\n", target);
        char *buf = calloc(128, sizeof(char));
        snprintf(buf, 128 + strlen(payload), "NOT_CONNECTED %s\n", target);
        enframe(strlen(buf), frame, &frame_len);
        write_to_socket(conn_state->fd, frame, frame_len, conn_state, efd);
        write_to_socket(conn_state->fd, buf, strlen(buf), conn_state, efd);
        free(buf);
    } else {
        printf("Message from %s to %s, socket %d\n", conn_state->ip, target, clientfd);
        printf("Payload: %s\n", extracted_payload);
        char *buf = calloc(128 + strlen(payload), sizeof(char));
        snprintf(buf, 128 + strlen(extracted_payload), "MESSAGE_TO %s\n%s", conn_state->ip, extracted_payload);
        enframe(strlen(buf), frame, &frame_len);
        write_to_socket(clientfd, frame, frame_len, conn_state, efd);
        write_to_socket(clientfd, buf, strlen(buf), conn_state, efd);
        free(buf);
        free(extracted_payload);
    }
}


void read_ws_message(int clientfd, struct conn_state *conn_state, int efd) {
    char finished = 0;
    if (conn_state->bytes_read == 0) {              //if read is not resumed allocate some space
        conn_state->buf = calloc(1024, sizeof(char));
        conn_state->buf_len = 1024;
    }
    while (1) {
        ssize_t bytes_read = read(clientfd, conn_state->buf + conn_state->bytes_read,
                                  conn_state->buf_len - conn_state->bytes_read);
        if (bytes_read == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                if (finished) {
                    free(conn_state->buf);
                }
                break;
            } else {
                perror("on reading from websocket");
                exit(1);
            }
        } else if (bytes_read == 0) {
            printf("Client %d has disconnected", clientfd);
            release_and_reset(conn_state);
            break;
        } else {
            finished = 0;                                   //we expected EAGAIN but new data arrived
            conn_state->bytes_read += bytes_read;
            if (!conn_state->data_frame_received) {        //that needs to be done only once
                size_t old_buf_len = conn_state->buf_len;
                parse_data_frame(conn_state);
                if (conn_state->buf_len > old_buf_len) {
                    //allocate more space
                    char *new_buffer = calloc(conn_state->buf_len, sizeof(char));
                    memcpy(new_buffer, conn_state->buf, conn_state->bytes_read);
                    free(conn_state->buf);
                    conn_state->buf = new_buffer;
                }
            }
            while (conn_state->bytes_read >= conn_state->buf_len) {
                //we had more than one message or more in the buffer
                size_t decoded_msg_len;
                char *decoded_msg = decode_ws_message(conn_state, &decoded_msg_len);
                if (decoded_msg_len == 2) {
                    puts("Closing handshake");
                    release_and_reset(conn_state);
                    return;
                }
                if (conn_state->fin) {
                    if (conn_state->opcode == 0x9) {
                        //it's a ping
                        ;
                    } else {
                        //process message
                        dispatch_clients_request(decoded_msg, conn_state, efd);
                    }
                    free(decoded_msg);
                } else if (conn_state->opcode == 0x1 ||
                           conn_state->opcode == 0x2) {        //new message that will be continued, were saving it
                    conn_state->msg = decoded_msg;
                    conn_state->msg_len = decoded_msg_len;
                } else if (conn_state->opcode == 0x0) {                                     //continuation of a message
                    char *new_buffer = calloc(decoded_msg_len + conn_state->msg_len, sizeof(char));
                    memcpy(new_buffer, conn_state->msg, conn_state->msg_len);
                    memcpy(new_buffer + conn_state->msg_len, decoded_msg, decoded_msg_len);
                    conn_state->msg_len += decoded_msg_len;
                }
                memcpy(conn_state->buf, conn_state->buf + conn_state->buf_len,
                       conn_state->bytes_read - conn_state->buf_len);
                memset(conn_state->buf + conn_state->bytes_read - conn_state->buf_len, 0, conn_state->buf_len);
                conn_state->bytes_read -= conn_state->buf_len;
                conn_state->data_frame_received = 0;
                if (conn_state->bytes_read == 0) {
                    finished = 1;
                } else if (conn_state->bytes_read > 0) {   //if there was another message, or at least its frame we need to extract the information here
                    size_t old_buf_len = conn_state->buf_len;
                    parse_data_frame(conn_state);
                    if (conn_state->buf_len > old_buf_len) {
                        //allocate more space
                        char *new_buffer = calloc(conn_state->buf_len, sizeof(char));
                        memcpy(new_buffer, conn_state->buf, conn_state->bytes_read);
                        free(conn_state->buf);
                        conn_state->buf = new_buffer;
                    }
                }
            }
        }
    }
}


int main(int argc, char const *argv[]) {

    if (argc != 3) {
        puts("IP and PORT should be the only arguments\n ./chat_app_server <IP> <PORT>");
        exit(1);
    }

    struct conn_state conn_states[MAX_CLIENTS];
    memset(conn_states, 0, sizeof(conn_states));

    connections = hashmap_new();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    int reuse = 1;
    int res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *) &reuse, sizeof(reuse));
    if (res == -1) {
        perror("setsockopt reuseaddr error");
    }

    u_int16_t PORT = (u_int16_t) strtol(argv[2], (char **)NULL, 10);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(argv[1]);
    sa.sin_port = htons(PORT);

    res = bind(sockfd, (const struct sockaddr *) &sa, sizeof(struct sockaddr_in));
    if (res == -1) {
        perror("bind error");
        exit(1);
    }

    res = fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK);
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

    struct epoll_event event;
    memset(&event, 0, sizeof(struct epoll_event));
    event.data.fd = sockfd;
    event.events = EPOLLIN | EPOLLET;
    res = epoll_ctl(efd, EPOLL_CTL_ADD, sockfd, &event);
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
                int clientfd = accept(sockfd, (struct sockaddr *) &client_info, (socklen_t *) &client_info_size);
                if (clientfd == -1) {
                    if (errno == EWOULDBLOCK || errno == EAGAIN) {
                        //that can happen for some reason
                        puts("EWOULDBLOCK || EAGAIN on accept");
                    } else {
                        perror("accept");
                        exit(1);
                    }
                } else {
                    printf("Accepted %d\n", clientfd);
                    //no error - mark as non blocking and add to epoll set
                    res = fcntl(clientfd, F_SETFL, fcntl(clientfd, F_GETFL, 0) | O_NONBLOCK);
                    if (res == -1) {
                        perror("error on setting socket as non-blocking");
                        exit(1);
                    }
                    memset(&event, 0, sizeof(struct epoll_event));
                    event.events = EPOLLIN;
                    event.data.fd = clientfd;
                    if (epoll_ctl(efd, EPOLL_CTL_ADD, clientfd, &event) == -1) {
                        perror("epoll_ctl: on adding client socked");
                        exit(1);
                    }
                    // get client's info and add to hashmap
                    char client_name[INET6_ADDRSTRLEN];
                    char port_name[6];
                    if (getnameinfo((const struct sockaddr *) &client_info, sizeof client_info,
                                    client_name, sizeof(client_name), NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                        char *key = calloc(1, strlen(client_name));
                        memcpy(key, client_name, strlen(client_name));
                        printf("New client with IP %s\n", key);
                        memcpy(conn_states[clientfd].ip, key, strlen(key));
                        conn_states[clientfd].fd = clientfd;
                        hashmap_put(connections, key, clientfd);
                    } else {
                        printf("Unable to get address\n");
                        release_and_reset(&conn_states[clientfd]);
                    }
                }
            } else {
                int clientfd = events[i].data.fd;
                struct conn_state *conn_state = &conn_states[events[i].data.fd];
                if (events[i].events & EPOLLOUT) {
                    resume_write(clientfd, conn_state, efd);
                } else {
                    if (conn_state->protocol == HTTP_PROTOCOL) {
                        printf("Http request from client %d, from %s\n", clientfd, conn_state->ip);
                        read_http_request(clientfd, conn_state, efd);
                    } else {
                        printf("WebSocket message from client %d, from %s\n", clientfd, conn_state->ip);
                        read_ws_message(clientfd, conn_state, efd);
                    }
                }
            }

        }
    }

    hashmap_free(connections);
    return 0;

}
