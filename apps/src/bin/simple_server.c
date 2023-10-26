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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>

#include <tquic.h>

#define READ_BUF_SIZE 4096
#define MAX_DATAGRAM_SIZE 1200

// Simple QUIC http/0.9 server, return same response to any requests.
struct simple_server {
    struct quic_endpoint_t *quic_endpoint;
    ev_timer timer;
    int sock;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
    SSL_CTX *ssl_ctx;
};

void server_on_conn_created(void *tctx, struct quic_conn_t *conn)
{
    fprintf(stderr, "new connection created\n");
}

void server_on_conn_established(void *tctx, struct quic_conn_t *conn)
{
    fprintf(stderr, "connection established\n");
}

void server_on_conn_closed(void *tctx, struct quic_conn_t *conn)
{
    fprintf(stderr, "connection closed\n");
}

void server_on_stream_created(void *tctx, struct quic_conn_t *conn,
                              uint64_t stream_id)
{
    fprintf(stderr, "new stream created %ld\n", stream_id);
}

void server_on_stream_readable(void *tctx, struct quic_conn_t *conn,
                               uint64_t stream_id)
{
    static uint8_t buf[READ_BUF_SIZE];
    bool fin = false;
    ssize_t r = quic_stream_read(conn, stream_id, buf, READ_BUF_SIZE, &fin);
    if (r < 0) {
        fprintf(stderr, "stream[%ld] read error\n", stream_id);
        return;
    }

    printf("Got request:\n");
    printf("%.*s\n", (int) r, buf);

    if (fin) {
        static const char *resp = "OK";
        quic_stream_write(conn, stream_id, (uint8_t *) resp, 2, true);
    }
}

void server_on_stream_writable(void *tctx, struct quic_conn_t *conn,
                               uint64_t stream_id)
{}

void server_on_stream_closed(void *tctx, struct quic_conn_t *conn,
                             uint64_t stream_id)
{
    fprintf(stderr, "new stream closed %ld\n", stream_id);
}

int server_on_packets_send(void *psctx, struct quic_packet_out_spec_t *pkts,
                           unsigned int count)
{
    struct simple_server *server = psctx;

    unsigned int sent_count = 0;
    int i, j = 0;
    for (i = 0; i < count; i++) {
        struct quic_packet_out_spec_t *pkt = pkts + i;
        for (j = 0; j < (*pkt).iovlen; j++) {
            const struct iovec *iov = pkt->iov + j;
            ssize_t sent = sendto(server->sock, iov->iov_base, iov->iov_len, 0,
                              (struct sockaddr *) pkt->dst_addr,
                              pkt->dst_addr_len);

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

const SSL_CTX *server_get_default_tls_config(void *ctx)
{
    struct simple_server *server = ctx;
    return server->ssl_ctx;
}

const SSL_CTX *server_select_tls_config(void *ctx,
                                        const uint8_t *server_name,
                                        size_t server_name_len)
{
    struct simple_server *server = ctx;
    return server->ssl_ctx;
}

static char s_alpn[0x100];

static int add_alpn (const char *alpn)
{
    size_t alpn_len, all_len;

    alpn_len = strlen(alpn);
    if (alpn_len > 255)
        return -1;

    all_len = strlen(s_alpn);
    if (all_len + 1 + alpn_len + 1 > sizeof(s_alpn))
        return -1;

    s_alpn[all_len] = alpn_len;
    memcpy(&s_alpn[all_len + 1], alpn, alpn_len);
    s_alpn[all_len + 1 + alpn_len] = '\0';
    return 0;
}

static int select_alpn (SSL *ssl, const unsigned char **out,
                        unsigned char *outlen, const unsigned char *in,
                        unsigned int inlen, void *arg)
{
    int r = SSL_select_next_proto((unsigned char **) out, outlen, in, inlen,
                                    (unsigned char *) s_alpn, strlen(s_alpn));
    if (r == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    else
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

int server_load_ssl_ctx(struct simple_server *server)
{
    add_alpn("http/0.9");
    server->ssl_ctx = SSL_CTX_new(TLS_method());
    if (SSL_CTX_use_certificate_chain_file(server->ssl_ctx,  "./cert.crt") != 1) {
        fprintf(stderr, "failed to load cert\n");
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(server->ssl_ctx, "./cert.key", SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "failed to load key\n");
        return -1;
    }
    SSL_CTX_set_default_verify_paths(server->ssl_ctx);
    SSL_CTX_set_alpn_select_cb(server->ssl_ctx, select_alpn, NULL);

    return 0;
}

const struct quic_transport_methods_t quic_transport_methods = {
    .on_conn_created = server_on_conn_created,
    .on_conn_established = server_on_conn_established,
    .on_conn_closed = server_on_conn_closed,
    .on_stream_created = server_on_stream_created,
    .on_stream_readable = server_on_stream_readable,
    .on_stream_writable = server_on_stream_writable,
    .on_stream_closed = server_on_stream_closed,
};

const struct quic_packet_send_methods_t quic_packet_send_methods = {
    .on_packets_send = server_on_packets_send,
};

const struct quic_tls_config_select_methods_t tls_config_select_method = {
    .get_default = server_get_default_tls_config,
    .select = server_select_tls_config,
};

static void read_callback(EV_P_ ev_io *w, int revents)
{
    struct simple_server *server = w->data;
    static uint8_t buf[READ_BUF_SIZE];

    while (true) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(server->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);
        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            fprintf(stderr, "failed to read\n");
            return;
        }

        quic_packet_info_t quic_packet_info = {
            .src = (struct sockaddr *) &peer_addr,
            .src_len = peer_addr_len,
            .dst = (struct sockaddr *) &server->local_addr,
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
    double timeout = quic_endpoint_timeout(server->quic_endpoint) /1e3f;
    server->timer.repeat = timeout;
    ev_timer_again(loop, &server->timer);
}

static void timeout_callback(EV_P_ ev_timer *w, int revents)
{
    struct simple_server *server = w->data;
    quic_endpoint_on_timeout(server->quic_endpoint);
    quic_endpoint_process_connections(server->quic_endpoint);

    double timeout = quic_endpoint_timeout(server->quic_endpoint) /1e3f;
    server->timer.repeat = timeout;
    ev_timer_again(loop, &server->timer);
}

static void debug_log(const unsigned char *line, void *argp)
{
    fprintf(stderr, "%s\n", line);
}

int main(int argc, char *argv[])
{
    // TODO: add more arguments and command line parsing.
    const char *host = argv[1];
    const char *port = argv[2];

    // Set logger.
    quic_set_logger(debug_log, NULL, "TRACE");

    // Bind socket.
    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    struct addrinfo *local;
    if (getaddrinfo(host, port, &hints, &local) != 0) {
        fprintf(stderr, "failed to resolve host\n");
        freeaddrinfo(local);
        return -1;
    }

    int sock = socket(local->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "failed to create socket\n");
        freeaddrinfo(local);
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        fprintf(stderr, "failed to make socket non-blocking\n");
        freeaddrinfo(local);
        return -1;
    }

    if (bind(sock, local->ai_addr, local->ai_addrlen) < 0) {
        fprintf(stderr, "failed to bind socket\n");
        freeaddrinfo(local);
        return -1;
    }

    // Create quic config.
    quic_config_t *config = quic_config_new();
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }
    quic_config_set_max_idle_timeout(config, 5000);
    quic_config_set_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);

    // Create simple server.
    struct simple_server server;
    server.sock = sock;
    server.local_addr_len = sizeof(server.local_addr);
    if (getsockname(sock, (struct sockaddr *)&server.local_addr,
                    &server.local_addr_len) != 0)
    {
        fprintf(stderr, "failed to get local address of socket\n");
        return -1;
    };

    quic_transport_handler_t quic_transport_handler = {
        .methods = &quic_transport_methods,
        .context = &server,
    };

    quic_packet_send_handler_t quic_packet_send_handler = {
        .methods = &quic_packet_send_methods,
        .context = &server,
    };

    struct quic_endpoint_t *quic_endpoint =
        quic_endpoint_new(config, true, &quic_transport_handler,
                          &quic_packet_send_handler);
    if (quic_endpoint == NULL) {
        fprintf(stderr, "failed to create quic endpoint\n");
        return -1;
    }
    server.quic_endpoint = quic_endpoint;

    // Create and set tls conf selector for quic config.
    if (server_load_ssl_ctx(&server) != 0) {
        return -1;
    }
    quic_config_set_tls_selector(config, &tls_config_select_method, &server);

    // Start event loop.
    struct ev_loop *loop = ev_default_loop(0);
    ev_init(&server.timer, timeout_callback);
    server.timer.data = &server;
   
    ev_io watcher;
    ev_io_init(&watcher, read_callback, sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = &server;
    ev_loop(loop, 0);

    // Event loop end.
    freeaddrinfo(local);
    SSL_CTX_free(server.ssl_ctx);
    // TODO: solve memory release problem.
    quic_endpoint_free(quic_endpoint);

    return 0;
}
