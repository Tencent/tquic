---
title: C/C++ HTTP/3 API Reference
sidebar_position: 4
---

# C/C++ HTTP/3 API Reference

## Preliminaries

The declarations are all in `tquic.h`, so you just need to include it in each source file:

```c
#include <tquic.h>
```

## Common types

The TQUIC HTTP/3 library defines several types that are commonly used by its public functions.

| Types | Description |
|-------|-------------|
| `http3_config_t` | The behavior of the HTTP/3 library can be managed through various parameters in `http3_config_t`. |
| `http3_conn_t` | HTTP/3 connection, which can manitain muliple requests simultaneously. |
| `http3_header_t` | HTTP/3 header structure. |
| `http3_headers_t` | HTTP/3 headers list. |
| `http3_methods_t` | The structure lists the callbacks used by the connection to interact with the user code. |
| `http3_context_t` | User-provided HTTP/3 context that can be used to associate information during event callbacks. |
| `http3_priority_t` | Extensible HTTP/3 priority, as described in [RFC9218](https://www.rfc-editor.org/rfc/rfc9218.html). |


## Configurations


### HTTP/3 configurations initialization

#### http3_config_new

```c
struct http3_config_t *http3_config_new(void);
```
* Create an instance of `http3_config_t` and initialize it with default values. The caller is responsible for managing the memory and should free it by calling `http3_config_free`.


#### http3_config_free

```c
void http3_config_free(struct http3_config_t *config);
```
* Free HTTP/3 configuration.


### HTTP/3 configurations customization

#### http3_config_set_max_field_section_size
```c
void http3_config_set_max_field_section_size(struct http3_config_t *config, uint64_t v);
```
* Set the `max_field_section_size` setting parameter in bytes.
* The default value is set to `0`, which means there is no limit on the size of headers received from the peer. The calculation rules for headers size constraints can be found in [RFC9114 Headers Size Constraints](https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints).


## HTTP/3 Connection

### Instantiation and destruction

#### http3_conn_new
```c
struct http3_conn_t *http3_conn_new(struct quic_conn_t *quic_conn, struct http3_config_t *config);
```
* Create an HTTP/3 connection. The caller is responsible for the memory of the connection and properly free it by calling `http3_conn_free`.


#### http3_conn_free
```c
void http3_conn_free(struct http3_conn_t *conn);
```
* Free an HTTP/3 connection.


### Event-driven and Callbacks

#### http3_conn_set_events_handler
```c
void http3_conn_set_events_handler(struct http3_conn_t *conn,
                                   const struct http3_methods_t *methods,
                                   http3_context_t context);
```
* Sets the callback and context for processing HTTP/3 connection events.


#### http3_conn_process_streams
```c
int http3_conn_process_streams(struct http3_conn_t *conn, struct quic_conn_t *quic_conn);
```
* Drives the HTTP/3 connection to process internal events for all maintained streams.


### HTTP/3 Callbacks

The `http3_methods_t` lists the callbacks used by the HTTP/3 connection to interact with the user code.


#### on_stream_headers
```c
typedef struct http3_methods_t {
  void (*on_stream_headers)(void *ctx, uint64_t stream_id, const struct http3_headers_t *headers, bool fin);
  /* ... */
} http3_methods_t;
```
 * `on_stream_headers` is called when request or response headers are received from the peer. In this callback, the upper-layer application can parse the headers using `http3_for_each_header`.


#### on_stream_data
```c
typedef struct http3_methods_t {
  void (*on_stream_data)(void *ctx, uint64_t stream_id);
  /* ... */
} http3_methods_t;
```
 * `on_stream_data` is called when DATA frames are received from the peer. Note that this event is edge-triggered.


#### on_stream_finished
```c
typedef struct http3_methods_t {
  void (*on_stream_finished)(void *ctx, uint64_t stream_id);
  /* ... */
} http3_methods_t;
```
 * `on_stream_finished` is called when all incoming data for a stream has been read.


#### on_stream_reset
```c
typedef struct http3_methods_t {
  void (*on_stream_reset)(void *ctx, uint64_t stream_id, uint64_t error_code);
  /* ... */
} http3_methods_t;
```
 * `on_stream_reset` is called when a RESET_STREAM frame is received from the peer. This callback is optional.


#### on_stream_priority_update
```c
typedef struct http3_methods_t {
  void (*on_stream_priority_update)(void *ctx, uint64_t stream_id);
  /* ... */
} http3_methods_t;
```
 * `on_stream_priority_update` is called when a PRIORITY_UPDATE frame is received from the peer. This callback is optional, and the upper-layer application can use `http3_take_priority_update` to get the priority update info for the associated stream.


#### on_conn_goaway
```c
typedef struct http3_methods_t {
  void (*on_conn_goaway)(void *ctx, uint64_t stream_id);
  /* ... */
} http3_methods_t;
```
 * `on_conn_goaway` is called when a GOAWAY frame is received from the peer. This callback is optional, and after receiving this event, the upper-layer application should not initiate new streams on the connection.


### Miscellaneous functions

#### http3_for_each_setting
```c
int http3_for_each_setting(const struct http3_conn_t *conn, int (*cb)(uint64_t identifier,
                                                                      uint64_t value,
                                                                      void *argp), void *argp);
```
* For each settings parameter, execute the `cb` callback.


#### http3_send_goaway
```c
int64_t http3_send_goaway(struct http3_conn_t *conn, struct quic_conn_t *quic_conn, uint64_t id);
```
* Send a GOAWAY frame to the peer and disconnect gracefully.


## HTTP/3 request

### Request and Response

#### http3_stream_new
```c
int64_t http3_stream_new(struct http3_conn_t *conn, struct quic_conn_t *quic_conn);
```
* Create a new HTTP/3 request stream.


#### http3_stream_new_with_priority
```c
int64_t http3_stream_new_with_priority(struct http3_conn_t *conn,
                                       struct quic_conn_t *quic_conn,
                                       const struct http3_priority_t *priority);
```
* Create a new HTTP/3 request stream with a specified priority using the `priority` parameter.


#### http3_stream_close
```c
int http3_stream_close(struct http3_conn_t *conn,
                       struct quic_conn_t *quic_conn,
                       uint64_t stream_id);
```
* Close HTTP/3 request stream.


#### http3_send_headers
```c
int http3_send_headers(struct http3_conn_t *conn,
                       struct quic_conn_t *quic_conn,
                       uint64_t stream_id,
                       const struct http3_header_t *headers,
                       size_t headers_len,
                       bool fin);
```
* Send HTTP/3 request or response headers, where the `fin` indicates whether there is more data to be sent.


#### http3_send_body
```c
ssize_t http3_send_body(struct http3_conn_t *conn,
                        struct quic_conn_t *quic_conn,
                        uint64_t stream_id,
                        const uint8_t *body,
                        size_t body_len,
                        bool fin);
```
* Send body for an HTTP/3 request or response, where the `fin` indicates whether there is more data to be sent.


#### http3_recv_body
```c
ssize_t http3_recv_body(struct http3_conn_t *conn,
                        struct quic_conn_t *quic_conn,
                        uint64_t stream_id,
                        uint8_t *out,
                        size_t out_len);
```
* Receive body for an HTTP/3 request or response.


#### http3_for_each_header
```c
int http3_for_each_header(const struct http3_headers_t *headers, int (*cb)(const uint8_t *name,
                                                                           size_t name_len,
                                                                           const uint8_t *value,
                                                                           size_t value_len,
                                                                           void *argp), void *argp);
```
* For each header, execute the `cb` callback.


#### http3_stream_read_finished
```c
bool http3_stream_read_finished(struct quic_conn_t *conn, uint64_t stream_id);
```
* Check if all incoming data has been fully read.


### HTTP/3 Extensiable priority

#### http3_stream_set_priority
```c
int http3_stream_set_priority(struct http3_conn_t *conn,
                              struct quic_conn_t *quic_conn,
                              uint64_t stream_id,
                              const struct http3_priority_t *priority);
```
* Set priority for an HTTP/3 stream.


#### http3_send_priority_update_for_request
```c
int http3_send_priority_update_for_request(struct http3_conn_t *conn,
                                           struct quic_conn_t *quic_conn,
                                           uint64_t stream_id,
                                           const struct http3_priority_t *priority);
```
* HTTP/3 client sends a PRIORITY_UPDATE frame for the given request stream to the server.


#### http3_take_priority_update
```c
int http3_take_priority_update(struct http3_conn_t *conn,
                               uint64_t prioritized_element_id,
                               int (*cb)(const uint8_t *priority_field_value,
                                         size_t priority_field_value_len,
                                         void *argp),
                               void *argp);
```
* When the application got a priority update event, it can use this api to get the priority_field value for the `prioritized_element_id` stream.


#### http3_parse_extensible_priority
```c
int http3_parse_extensible_priority(const uint8_t *priority,
                                    size_t priority_len,
                                    struct http3_priority_t *parsed);
```
* The application uses this api to parse the structured encoded priority_field into the `http3_priority_t` structure.



## Miscellaneous functions

#### http3_methods_t
```c
typedef struct http3_methods_t {
  /**
   * Called when the stream got headers.
   */
  void (*on_stream_headers)(void *ctx,
                            uint64_t stream_id,
                            const struct http3_headers_t *headers,
                            bool fin);
  /**
   * Called when the stream has buffered data to read.
   */
  void (*on_stream_data)(void *ctx, uint64_t stream_id);
  /**
   * Called when the stream is finished.
   */
  void (*on_stream_finished)(void *ctx, uint64_t stream_id);
  /**
   * Called when the stream receives a RESET_STREAM frame from the peer.
   */
  void (*on_stream_reset)(void *ctx, uint64_t stream_id, uint64_t error_code);
  /**
   * Called when the stream priority is updated.
   */
  void (*on_stream_priority_update)(void *ctx, uint64_t stream_id);
  /**
   * Called when the connection receives a GOAWAY frame from the peer.
   */
  void (*on_conn_goaway)(void *ctx, uint64_t stream_id);
} http3_methods_t;
```
* HTTP/3 callbacks.


#### http3_context_t 
```c
typedef void *http3_context_t;
```
* HTTP/3 context.


#### http3_header_t 

```c
typedef struct http3_header_t {
  uint8_t *name;
  uintptr_t name_len;
  uint8_t *value;
  uintptr_t value_len;
} http3_header_t;
``` 
* HTTP/3 header structure.


#### http3_headers_t 

```c
typedef struct http3_headers_t http3_headers_t;
``` 
* HTTP/3 headers list.


#### http3_priority_t 

```c
typedef struct http3_priority_t {
  uint8_t urgency;
  bool incremental;
} http3_priority_t;
``` 
* HTTP/3 stream priority.

