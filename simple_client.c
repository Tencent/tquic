// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <errno.h>
#include <ev.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "openssl/ssl.h"
#include "tquic.h"

#define READ_BUF_SIZE 4096
#define MAX_DATAGRAM_SIZE 1200

int max_count_reply = 10;
int count_to_reply = 0;

// A simple client that supports HTTP/0.9 over QUIC
struct simple_client {
    struct quic_endpoint_t *quic_endpoint;
    ev_timer timer;
    int sock;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    struct quic_tls_config_t *tls_config;
    struct quic_conn_t *conn;
    struct ev_loop *loop;
};

void client_on_conn_created(void *tctx, struct quic_conn_t *conn) {
    struct simple_client *client = tctx;
    client->conn = conn;
}

void client_on_conn_established(void *tctx, struct quic_conn_t *conn) {
    printf("Connection established. Datagram extension enabled: %s\n", 
           quic_conn_is_datagram_enabled(conn) ? "yes" : "no");
    quic_conn_enable_all_datagram_notifications(conn);
    if (quic_conn_is_datagram_enabled(conn)) {
        printf("Peer max datagram frame size: %lu\n", 
               quic_conn_peer_max_datagram_frame_size(conn));
        
        // Send first datagram if we haven't reached the limit
        if (count_to_reply < max_count_reply) {
            count_to_reply++;
            char message[256];
            snprintf(message, sizeof(message), "Hello from client - message %d", count_to_reply);
            
            int64_t datagram_id = quic_conn_send_datagram(conn, (uint8_t*)message, strlen(message));
            if (datagram_id > 0) {
                printf("Sent datagram %d/%d (ID: %ld): %s\n", count_to_reply, max_count_reply, datagram_id, message);
            }
        } 
    }
}

void client_on_conn_closed(void *tctx, struct quic_conn_t *conn) {
    struct simple_client *client = tctx;
    ev_break(client->loop, EVBREAK_ALL);
}

void client_on_datagram_received(struct quic_conn_t *conn, uint64_t len) {
    // Get client context from connection (we'll set it when creating connection)
    
    // Read the received datagram
    static uint8_t buf[MAX_DATAGRAM_SIZE];
    int64_t received_len = quic_conn_recv_datagram_without_check(conn, buf, len);
    
    if (received_len > 0) {
        buf[received_len] = '\0'; // Null terminate for printing
        printf("Received echo datagram (%ld bytes): %s\n", received_len, buf);
        
        // Send next datagram if we haven't reached the limit
        if (count_to_reply < max_count_reply) {
            count_to_reply++;
            char message[256];
            snprintf(message, sizeof(message), "Hello from client - message %d", count_to_reply);
            
            int64_t datagram_id = quic_conn_send_datagram(conn, (uint8_t*)message, strlen(message));
            if (datagram_id > 0) {
                printf("Sent datagram %d/%d (ID: %ld): %s\n", count_to_reply, max_count_reply, datagram_id, message);
            }
        } else {
            printf("Reached maximum message count (%d), closing connection\n", max_count_reply);
            const char *reason = "done";
            quic_conn_close(conn, true, 0, (const uint8_t *)reason, strlen(reason));
        }

    }
}

void client_on_datagram_acked(struct quic_conn_t *conn, uint64_t datagram_id) {
    printf("Datagram %lu acknowledged\n", datagram_id);
    printf("before disable ack notify %d\n",quic_conn_is_datagram_notification_enabled(conn,DATAGRAM_NOTIFY_FLAG_DATAGRAM_ACKED));

    quic_conn_disable_datagram_notifications(conn,DATAGRAM_NOTIFY_FLAG_DATAGRAM_ACKED);
    printf("after disable ack notify %d\n",quic_conn_is_datagram_notification_enabled(conn,DATAGRAM_NOTIFY_FLAG_DATAGRAM_ACKED));
}

void client_on_datagram_lost(struct quic_conn_t *conn, uint64_t datagram_id) {
    printf("Datagram %lu lost\n", datagram_id);
}

int client_on_packets_send(void *psctx, struct quic_packet_out_spec_t *pkts,
                           unsigned int count) {
    struct simple_client *client = psctx;

    unsigned int sent_count = 0;
    int i, j = 0;
    for (i = 0; i < count; i++) {
        struct quic_packet_out_spec_t *pkt = pkts + i;
        for (j = 0; j < (*pkt).iovlen; j++) {
            const struct iovec *iov = pkt->iov + j;
            ssize_t sent =
                sendto(client->sock, iov->iov_base, iov->iov_len, 0,
                       (struct sockaddr *)pkt->dst_addr, pkt->dst_addr_len);

            if (sent != iov->iov_len) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    fprintf(stderr, "send would block, already sent: %d\n",
                            sent_count);
                    return sent_count;
                }
                return -1;
            }
            sent_count++;
        }
    }

    return sent_count;
}

const struct quic_transport_methods_t quic_transport_methods = {
    .on_conn_created = client_on_conn_created,
    .on_conn_established = client_on_conn_established,
    .on_conn_closed = client_on_conn_closed,
    .on_datagram_received = client_on_datagram_received,
    .on_datagram_acked = client_on_datagram_acked,
    .on_datagram_lost = client_on_datagram_lost,
};

const struct quic_packet_send_methods_t quic_packet_send_methods = {
    .on_packets_send = client_on_packets_send,
};

static void process_connections(struct simple_client *client) {
    quic_endpoint_process_connections(client->quic_endpoint);
    double timeout = quic_endpoint_timeout(client->quic_endpoint) / 1e3f;
    if (timeout < 0.0001) {
        timeout = 0.0001;
    }
    client->timer.repeat = timeout;
    ev_timer_again(client->loop, &client->timer);
}

static void read_callback(EV_P_ ev_io *w, int revents) {
    struct simple_client *client = w->data;
    static uint8_t buf[READ_BUF_SIZE];

    while (true) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(client->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                break;
            }

            fprintf(stderr, "failed to read\n");
            return;
        }

        quic_packet_info_t quic_packet_info = {
            .src = (struct sockaddr *)&peer_addr,
            .src_len = peer_addr_len,
            .dst = (struct sockaddr *)&client->local_addr,
            .dst_len = client->local_addr_len,
        };

        int r = quic_endpoint_recv(client->quic_endpoint, buf, read,
                                   &quic_packet_info);
        if (r != 0) {
            fprintf(stderr, "recv failed %d\n", r);
            continue;
        }
    }

    process_connections(client);
}

static void timeout_callback(EV_P_ ev_timer *w, int revents) {
    struct simple_client *client = w->data;
    quic_endpoint_on_timeout(client->quic_endpoint);
    process_connections(client);
}

static void debug_log(const uint8_t *data, size_t data_len, void *argp) {
    fwrite(data, sizeof(uint8_t), data_len, stderr);
}

static int create_socket(const char *host, const char *port,
                         struct addrinfo **peer, struct simple_client *client) {
    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};
    if (getaddrinfo(host, port, &hints, peer) != 0) {
        fprintf(stderr, "failed to resolve host\n");
        return -1;
    }

    int sock = socket((*peer)->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "failed to create socket\n");
        return -1;
    }
    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        fprintf(stderr, "failed to make socket non-blocking\n");
        return -1;
    }

    client->local_addr_len = sizeof(client->local_addr);
    if (getsockname(sock, (struct sockaddr *)&client->local_addr,
                    &client->local_addr_len) != 0) {
        fprintf(stderr, "failed to get local address of socket\n");
        return -1;
    };
    client->sock = sock;

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "%s <dest_addr> <dest_port>\n", argv[0]);
        return -1;
    }

    // Set logger.
    quic_set_logger(debug_log, NULL, "INFO");

    // Create client.
    struct simple_client client;
    client.quic_endpoint = NULL;
    client.tls_config = NULL;
    client.conn = NULL;
    client.loop = NULL;
    quic_config_t *config = NULL;
    int ret = 0;

    // Create socket.
    const char *host = argv[1];
    const char *port = argv[2];
    struct addrinfo *peer = NULL;
    if (create_socket(host, port, &peer, &client) != 0) {
        ret = -1;
        goto EXIT;
    }

    // Create quic config.
    config = quic_config_new();
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        ret = -1;
        goto EXIT;
    }
    quic_config_set_max_idle_timeout(config, 5000);
    quic_config_set_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quic_config_set_max_datagram_frame_size(config, MAX_DATAGRAM_SIZE);
    // Create and set tls config.
    const char *const protos[1] = {"echo"};
    client.tls_config = quic_tls_config_new_client_config(protos, 1, true);
    if (client.tls_config == NULL) {
        ret = -1;
        goto EXIT;
    }
    quic_config_set_tls_config(config, client.tls_config);

    // Create quic endpoint
    client.quic_endpoint =
        quic_endpoint_new(config, false, &quic_transport_methods, &client,
                          &quic_packet_send_methods, &client);
    if (client.quic_endpoint == NULL) {
        fprintf(stderr, "failed to create quic endpoint\n");
        ret = -1;
        goto EXIT;
    }

    // Init event loop.
    client.loop = ev_default_loop(0);
    ev_init(&client.timer, timeout_callback);
    client.timer.data = &client;

    // Connect to server.
    ret = quic_endpoint_connect(
        client.quic_endpoint, (struct sockaddr *)&client.local_addr,
        client.local_addr_len, peer->ai_addr, peer->ai_addrlen,
        NULL /* server_name */, NULL /* session */, 0 /* session_len */,
        NULL /* token */, 0 /* token_len */, NULL /* config */,
        NULL /* index */);
    if (ret < 0) {
        fprintf(stderr, "failed to connect to client: %d\n", ret);
        ret = -1;
        goto EXIT;
    }
    
    process_connections(&client);

    // Start event loop.
    ev_io watcher;
    ev_io_init(&watcher, read_callback, client.sock, EV_READ);
    ev_io_start(client.loop, &watcher);
    watcher.data = &client;
    ev_loop(client.loop, 0);

EXIT:
    if (peer != NULL) {
        freeaddrinfo(peer);
    }
    if (client.tls_config != NULL) {
        quic_tls_config_free(client.tls_config);
    }
    if (client.sock > 0) {
        close(client.sock);
    }
    if (client.quic_endpoint != NULL) {
        quic_endpoint_free(client.quic_endpoint);
    }
    if (client.loop != NULL) {
        ev_loop_destroy(client.loop);
    }
    if (config != NULL) {
        quic_config_free(config);
    }

    return ret;
}