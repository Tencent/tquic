---
title: C/C++语言HTTP/3接口说明
sidebar_position: 4
---

# C/C++语言的HTTP/3接口说明

## 准备工作

所有声明包含在`tquic.h`文件中，因此你只需在每个源文件中包含:

```c
#include <tquic.h>
```

## 常见类型

TQUIC库HTTP/3模块定义了公共函数使用的几种常见类型：

| 类型 | 说明 |
|-------|-------------|
| `http3_config_t` | 可以通过`http3_config_t`中各类参数来定制HTTP/3模块的行为。|
| `http3_conn_t` | HTTP/3连接，连接上可能会同时维护多个请求。|
| `http3_header_t` | HTTP/3头域结构体。|
| `http3_headers_t` | HTTP/3头域集合。|
| `http3_methods_t` | 该结构列出了HTTP/3连接用于与用户代码交互的回调函数。|
| `http3_context_t` | 用户提供的HTTP/3上下文，可用于事件回调时做信息关联。|
| `http3_priority_t` | 可扩展的HTTP/3优先级参数，可参考[RFC9218](https://www.rfc-editor.org/rfc/rfc9218.html)。|


## 配置


### HTTP/3配置初始化

#### http3_config_new

```c
struct http3_config_t *http3_config_new(void);
```
* 创建一个`http3_config_t`实例并使用默认值初始化。调用方负责管理该内存, 通过调用`http3_config_free`来释放内存。


#### http3_config_free

```c
void http3_config_free(struct http3_config_t *config);
```
* 释放HTTP/3配置。


### HTTP/3配置定制

#### http3_config_set_max_field_section_size
```c
void http3_config_set_max_field_section_size(struct http3_config_t *config, uint64_t v);
```
* 设置`max_field_section_size`参数，单位是字节。
* 默认值是`0`，代表不限制对端发送过来的头域大小。头域大小计算规则，详见[RFC9114 Headers Size Constraints](https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints)。


## HTTP/3连接

### 创建和释放

#### http3_conn_new
```c
struct http3_conn_t *http3_conn_new(struct quic_conn_t *quic_conn, struct http3_config_t *config);
```
* 创建一个HTTP/3连接。调用方负责管理HTTP/3连接的内存, 并调用`http3_conn_free`进行释放。


#### http3_conn_free
```c
void http3_conn_free(struct http3_conn_t *conn);
```
* 释放一个HTTP/3连接。


### 事件驱动和回调

#### http3_conn_set_events_handler
```c
void http3_conn_set_events_handler(struct http3_conn_t *conn,
                                   const struct http3_methods_t *methods,
                                   http3_context_t context);
```
* 设置连接事件处理回调及上下文。


#### http3_conn_process_streams
```c
int http3_conn_process_streams(struct http3_conn_t *conn, struct quic_conn_t *quic_conn);
```
* 驱动连接处理其维护的各条流的内部事件。


### HTTP/3层回调函数

`http3_methods_t`包括供连接使用，用于与用户代码通信的一组回调函数。


#### on_stream_headers
```c
typedef struct http3_methods_t {
  void (*on_stream_headers)(void *ctx, uint64_t stream_id, const struct http3_headers_t *headers, bool fin);
  /* ... */
} http3_methods_t;
```
 * `on_stream_headers`在收到来自对端的请求或响应头时被调用。上层应用在此回调内，通过`http3_for_each_header`解析头域。


#### on_stream_data
```c
typedef struct http3_methods_t {
  void (*on_stream_data)(void *ctx, uint64_t stream_id);
  /* ... */
} http3_methods_t;
```
 * `on_stream_data`在收到来自对端的DATA帧时被调用。注意，此事件是边缘触发。


#### on_stream_finished
```c
typedef struct http3_methods_t {
  void (*on_stream_finished)(void *ctx, uint64_t stream_id);
  /* ... */
} http3_methods_t;
```
 * `on_stream_finished`在流的入方向数据均已读取时被调用。


#### on_stream_reset
```c
typedef struct http3_methods_t {
  void (*on_stream_reset)(void *ctx, uint64_t stream_id, uint64_t error_code);
  /* ... */
} http3_methods_t;
```
 * `on_stream_reset`在收到来自对端的RESET_STREAM帧时被调用。该回调函数是可选的。


#### on_stream_priority_update
```c
typedef struct http3_methods_t {
  void (*on_stream_priority_update)(void *ctx, uint64_t stream_id);
  /* ... */
} http3_methods_t;
```
 * `on_stream_priority_update`在收到来自对端的优先级更新时被调用。该回调函数是可选的，上层应用在该回调内可通过`http3_take_priority_update`获取对应流的优先级更新信息。


#### on_conn_goaway
```c
typedef struct http3_methods_t {
  void (*on_conn_goaway)(void *ctx, uint64_t stream_id);
  /* ... */
} http3_methods_t;
```
 * `on_conn_goaway`在收到来自对端的GOAWAY帧时被调用。该回调函数是可选的，上层收到此事件后，不应再在当前连接上发起新的请求。


### 其它函数

#### http3_for_each_setting
```c
int http3_for_each_setting(const struct http3_conn_t *conn, int (*cb)(uint64_t identifier,
                                                                      uint64_t value,
                                                                      void *argp), void *argp);
```
* 遍历HTTP/3连接接收到的来自对端的settings参数，并执行cb回调。


#### http3_send_goaway
```c
int64_t http3_send_goaway(struct http3_conn_t *conn, struct quic_conn_t *quic_conn, uint64_t id);
```
* 向对端发送GOAWAY帧，优雅断开连接。


## HTTP/3请求

### 请求和响应

#### http3_stream_new
```c
int64_t http3_stream_new(struct http3_conn_t *conn, struct quic_conn_t *quic_conn);
```
* 创建新的HTTP/3请求流。


#### http3_stream_new_with_priority
```c
int64_t http3_stream_new_with_priority(struct http3_conn_t *conn,
                                       struct quic_conn_t *quic_conn,
                                       const struct http3_priority_t *priority);
```
* 创建新的HTTP/3请求流，并通过priority参数指定流优先级。


#### http3_stream_close
```c
int http3_stream_close(struct http3_conn_t *conn,
                       struct quic_conn_t *quic_conn,
                       uint64_t stream_id);
```
* 关闭HTTP/3请求流。


#### http3_send_headers
```c
int http3_send_headers(struct http3_conn_t *conn,
                       struct quic_conn_t *quic_conn,
                       uint64_t stream_id,
                       const struct http3_header_t *headers,
                       size_t headers_len,
                       bool fin);
```
* 发送HTTP/3请求或响应的头域，用fin表明后续是否有body数据发送。


#### http3_send_body
```c
ssize_t http3_send_body(struct http3_conn_t *conn,
                        struct quic_conn_t *quic_conn,
                        uint64_t stream_id,
                        const uint8_t *body,
                        size_t body_len,
                        bool fin);
```
* 发送HTTP/3请求或响应的body数据，用fin表明当前body是否为最后一块数据。


#### http3_recv_body
```c
ssize_t http3_recv_body(struct http3_conn_t *conn,
                        struct quic_conn_t *quic_conn,
                        uint64_t stream_id,
                        uint8_t *out,
                        size_t out_len);
```
* 接收HTTP/3请求或响应的body数据。


#### http3_stream_read_finished
```c
bool http3_stream_read_finished(struct quic_conn_t *conn, uint64_t stream_id);
```
* 判断流数据是否已经全部读取结束。


#### http3_for_each_header
```c
int http3_for_each_header(const struct http3_headers_t *headers, int (*cb)(const uint8_t *name,
                                                                           size_t name_len,
                                                                           const uint8_t *value,
                                                                           size_t value_len,
                                                                           void *argp), void *argp);
```
* 遍历事件中携带的头域集，并针对每个头域执行cb回调。


### HTTP/3可扩展的优先级

#### http3_stream_set_priority
```c
int http3_stream_set_priority(struct http3_conn_t *conn,
                              struct quic_conn_t *quic_conn,
                              uint64_t stream_id,
                              const struct http3_priority_t *priority);
```
* 设置HTTP/3流优先级。


#### http3_send_priority_update_for_request
```c
int http3_send_priority_update_for_request(struct http3_conn_t *conn,
                                           struct quic_conn_t *quic_conn,
                                           uint64_t stream_id,
                                           const struct http3_priority_t *priority);
```
* 客户端向服务端发送更新指定请求流的优先级。


#### http3_take_priority_update
```c
int http3_take_priority_update(struct http3_conn_t *conn,
                               uint64_t prioritized_element_id,
                               int (*cb)(const uint8_t *priority_field_value,
                                         size_t priority_field_value_len,
                                         void *argp),
                               void *argp);
```
* 上层应用收到来自对端的优先级更新事件后，通过此接口获取指定流的优先级更新信息。


#### http3_parse_extensible_priority
```c
int http3_parse_extensible_priority(const uint8_t *priority,
                                    size_t priority_len,
                                    struct http3_priority_t *parsed);
```
* 上层应用通过此接口，将结构化编码的priority字节码解析成http3_priority_t结构。



## 其他类型

#### http3_methods_t
```c
typedef struct http3_methods_t {
  /**
   * 流收到头域时调用
   */
  void (*on_stream_headers)(void *ctx,
                            uint64_t stream_id,
                            const struct http3_headers_t *headers,
                            bool fin);
  /**
   * 流有数据可读取时调用。
   */
  void (*on_stream_data)(void *ctx, uint64_t stream_id);
  /**
   * 流读取结束时调用。
   */
  void (*on_stream_finished)(void *ctx, uint64_t stream_id);
  /**
   * 流收到来自对端的RESET_STREAM帧时调用。
   */
  void (*on_stream_reset)(void *ctx, uint64_t stream_id, uint64_t error_code);
  /**
   * 收到来自对端的PRIORITY_UPDATA帧时调用。
   */
  void (*on_stream_priority_update)(void *ctx, uint64_t stream_id);
  /**
   * 收到来自对端的GOAWAY帧时调用。
   */
  void (*on_conn_goaway)(void *ctx, uint64_t stream_id);
} http3_methods_t;
```
* HTTP/3回调句柄。


#### http3_context_t 
```c
typedef void *http3_context_t;
```
* HTTP/3连接上下文。


#### http3_header_t 

```c
typedef struct http3_header_t {
  uint8_t *name;
  uintptr_t name_len;
  uint8_t *value;
  uintptr_t value_len;
} http3_header_t;
``` 
* HTTP/3头域。


#### http3_headers_t 

```c
typedef struct http3_headers_t http3_headers_t;
``` 
* HTTP/3头域集合。


#### http3_priority_t 

```c
typedef struct http3_priority_t {
  uint8_t urgency;
  bool incremental;
} http3_priority_t;
``` 
* HTTP/3流优先级。
