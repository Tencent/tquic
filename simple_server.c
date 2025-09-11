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

#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "tquic.h"

#define READ_BUF_SIZE 4096
#define MAX_DATAGRAM_SIZE 1200

// A simple server that supports HTTP/0.9 over QUIC
struct simple_server {
    struct quic_endpoint_t *quic_endpoint;
    ev_timer timer;
    int sock;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    struct quic_tls_config_t *tls_config;
    struct ev_loop *loop;
};

void server_on_conn_created(void *tctx, struct quic_conn_t *conn) {
    fprintf(stderr, "new connection created\n");
}

void server_on_conn_established(void *tctx, struct quic_conn_t *conn) {
    fprintf(stderr, "connection established\n");
    // quic_conn_enable_all_datagram_notifications(conn);
    quic_conn_set_datagram_notifications(conn,DATAGRAM_NOTIFY_FLAG_DATAGRAM_ACKED | DATAGRAM_NOTIFY_FLAG_DATAGRAM_LOST);
}

void server_on_conn_closed(void *tctx, struct quic_conn_t *conn) {
    fprintf(stderr, "connection closed\n");
}
void server_on_datagram_received(struct quic_conn_t *conn, uint64_t len) {

    printf("datagram receiverd\n");
    // Read all available datagrams
    static uint8_t buf[MAX_DATAGRAM_SIZE];
    
    while (true) {
        int64_t received_len = quic_conn_recv_datagram_without_check(conn, buf, len);
        if (received_len < 0) {
            break; // No more datagrams
        }
        
        buf[received_len] = '\0'; // Null terminate for printing
        printf("Received datagram (%ld bytes): %s\n", received_len, buf);
        
        // Echo the datagram back with a prefix
        char echo_message[2048];
        snprintf(echo_message, sizeof(echo_message), "Echo from server: %s", buf);
        
        int64_t datagram_id = quic_conn_send_datagram(conn, (uint8_t*)echo_message, strlen(echo_message));
        if (datagram_id > 0) {
            printf("Sent echo datagram (ID: %ld): %s\n", datagram_id, echo_message);
        } else {
            fprintf(stderr, "Failed to send echo datagram: %ld\n", datagram_id);
        }
    }
}

void server_on_datagram_acked(struct quic_conn_t *conn, uint64_t datagram_id) {
    printf("Datagram %lu acknowledged\n", datagram_id);
    printf("before disable, the notify flag: %d\n",quic_conn_datagram_notification_flags(conn));
    quic_conn_disable_all_datagram_notifications(conn);
    printf("after disable, the notify flag: %d\n",quic_conn_datagram_notification_flags(conn));

}

void server_on_datagram_lost(struct quic_conn_t *conn, uint64_t datagram_id) {
    printf("Datagram %lu lost\n", datagram_id);
}

int server_on_packets_send(void *psctx, struct quic_packet_out_spec_t *pkts,
                           unsigned int count) {
    struct simple_server *server = psctx;

    unsigned int sent_count = 0;
    int i, j = 0;
    for (i = 0; i < count; i++) {
        struct quic_packet_out_spec_t *pkt = pkts + i;
        for (j = 0; j < (*pkt).iovlen; j++) {
            const struct iovec *iov = pkt->iov + j;
            ssize_t sent =
                sendto(server->sock, iov->iov_base, iov->iov_len, 0,
                       (struct sockaddr *)pkt->dst_addr, pkt->dst_addr_len);

            if (sent != iov->iov_len) {
                if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                    fprintf(stderr, "send would block, already sent: %d\n",
                            sent_count);
                    return sent_count;
                }
                return -1;
            }
            fprintf(stderr, "send packet, length %ld\n", sent);
            sent_count++;
        }
    }

    return sent_count;
}

struct quic_tls_config_t *server_get_default_tls_config(void *ctx) {
    struct simple_server *server = ctx;
    return server->tls_config;
}

struct quic_tls_config_t *server_select_tls_config(void *ctx,
                                                   const uint8_t *server_name,
                                                   size_t server_name_len) {
    struct simple_server *server = ctx;
    return server->tls_config;
}

const struct quic_transport_methods_t quic_transport_methods = {
    .on_conn_created = server_on_conn_created,
    .on_conn_established = server_on_conn_established,
    .on_conn_closed = server_on_conn_closed,
    .on_datagram_received = server_on_datagram_received,
    .on_datagram_acked = server_on_datagram_acked,
    .on_datagram_lost = server_on_datagram_lost,
};

const struct quic_packet_send_methods_t quic_packet_send_methods = {
    .on_packets_send = server_on_packets_send,
};

const struct quic_tls_config_select_methods_t tls_config_select_method = {
    .get_default = server_get_default_tls_config,
    .select = server_select_tls_config,
};

static void read_callback(EV_P_ ev_io *w, int revents) {
    struct simple_server *server = w->data;
    static uint8_t buf[READ_BUF_SIZE];

    while (true) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(server->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *)&peer_addr, &peer_addr_len);
        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            fprintf(stderr, "failed to read\n");
            return;
        }

        quic_packet_info_t quic_packet_info = {
            .src = (struct sockaddr *)&peer_addr,
            .src_len = peer_addr_len,
            .dst = (struct sockaddr *)&server->local_addr,
            .dst_len = server->local_addr_len,
        };

        int r = quic_endpoint_recv(server->quic_endpoint, buf, read,
                                   &quic_packet_info);
        if (r != 0) {
            fprintf(stderr, "recv failed %d\n", r);
            continue;
        }
    }

    quic_endpoint_process_connections(server->quic_endpoint);
    double timeout = quic_endpoint_timeout(server->quic_endpoint) / 1e3f;
    if (timeout < 0.0001) {
        timeout = 0.0001;
    }
    server->timer.repeat = timeout;
    ev_timer_again(loop, &server->timer);
}

static void timeout_callback(EV_P_ ev_timer *w, int revents) {
    struct simple_server *server = w->data;
    quic_endpoint_on_timeout(server->quic_endpoint);
    quic_endpoint_process_connections(server->quic_endpoint);

    double timeout = quic_endpoint_timeout(server->quic_endpoint) / 1e3f;
    if (timeout < 0.0001) {
        timeout = 0.0001;
    }
    server->timer.repeat = timeout;
    ev_timer_again(loop, &server->timer);
}

static void debug_log(const uint8_t *data, size_t data_len, void *argp) {
    fwrite(data, sizeof(uint8_t), data_len, stderr);
}

static int create_socket(const char *host, const char *port,
                         struct addrinfo **local,
                         struct simple_server *server) {
    const struct addrinfo hints = {.ai_family = PF_UNSPEC,
                                   .ai_socktype = SOCK_DGRAM,
                                   .ai_protocol = IPPROTO_UDP};
    if (getaddrinfo(host, port, &hints, local) != 0) {
        fprintf(stderr, "failed to resolve host\n");
        return -1;
    }

    int sock = socket((*local)->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "failed to create socket\n");
        return -1;
    }
    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        fprintf(stderr, "failed to make socket non-blocking\n");
        return -1;
    }
    if (bind(sock, (*local)->ai_addr, (*local)->ai_addrlen) < 0) {
        fprintf(stderr, "failed to bind socket\n");
        return -1;
    }

    server->local_addr_len = sizeof(server->local_addr);
    if (getsockname(sock, (struct sockaddr *)&server->local_addr,
                    &server->local_addr_len) != 0) {
        fprintf(stderr, "failed to get local address of socket\n");
        return -1;
    };
    server->sock = sock;

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "%s <listen_addr> <listen_port>\n", argv[0]);
        return -1;
    }

    // Set logger.
    quic_set_logger(debug_log, NULL, "INFO");

    // Create simple server.
    struct simple_server server;
    server.quic_endpoint = NULL;
    server.tls_config = NULL;
    server.loop = NULL;
    quic_config_t *config = NULL;
    int ret = 0;

    // Create socket.
    const char *host = argv[1];
    const char *port = argv[2];
    struct addrinfo *local = NULL;
    if (create_socket(host, port, &local, &server) != 0) {
        ret = -1;
        goto EXIT;
    }

    // Create quic config.
    config = quic_config_new();
    if (config == NULL) {
        ret = -1;
        goto EXIT;
    }
    quic_config_set_max_idle_timeout(config, 5000);
    quic_config_set_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quic_config_set_max_datagram_frame_size(config, MAX_DATAGRAM_SIZE);
    // Create and set tls config.
    const char *const protos[1] = {"echo"};
    server.tls_config = quic_tls_config_new_server_config(
        "target/release/cert.crt", "target/release/cert.key", protos, 1, true);
    if (server.tls_config == NULL) {
        ret = -1;
        goto EXIT;
    }
    quic_config_set_tls_selector(config, &tls_config_select_method, &server);

    // Create quic endpoint
    server.quic_endpoint =
        quic_endpoint_new(config, true, &quic_transport_methods, &server,
                          &quic_packet_send_methods, &server);
    if (server.quic_endpoint == NULL) {
        fprintf(stderr, "failed to create quic endpoint\n");
        ret = -1;
        goto EXIT;
    }

    // Start event loop.
    server.loop = ev_default_loop(0);
    ev_init(&server.timer, timeout_callback);
    server.timer.data = &server;

    ev_io watcher;
    ev_io_init(&watcher, read_callback, server.sock, EV_READ);
    ev_io_start(server.loop, &watcher);
    watcher.data = &server;
    ev_loop(server.loop, 0);

EXIT:
    if (local != NULL) {
        freeaddrinfo(local);
    }
    if (server.tls_config != NULL) {
        quic_tls_config_free(server.tls_config);
    }
    if (server.sock > 0) {
        close(server.sock);
    }
    if (server.quic_endpoint != NULL) {
        quic_endpoint_free(server.quic_endpoint);
    }
    if (server.loop != NULL) {
        ev_loop_destroy(server.loop);
    }
    if (config != NULL) {
        quic_config_free(config);
    }

    return ret;
}