#ifndef _TQUIC_DEF_H_
#define _TQUIC_DEF_H_

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SSIZE_T ssize_t;
struct iovec {
  void  *iov_base;    // starting address
  size_t iov_len;     // number of bytes to transfer
};
#else
#include <sys/socket.h>
#include <sys/types.h>
#endif

typedef enum http3_error {
    HTTP3_NO_ERROR = 0,

    // There is no error or no work to do
    HTTP3_ERR_DONE = -1,

    // The endpoint detected an error in the protocol
    HTTP3_ERR_GENERAL_PROTOCOL_ERROR = -2,

    // The endpoint encountered an internal error and cannot continue with the
    // connection
    HTTP3_ERR_INTERNAL_ERROR = -3,

    // The endpoint detected that its peer created a stream that it will not
    // accept
    HTTP3_ERR_STREAM_CREATION_ERROR = -4,

    // A stream required by the connection was closed or reset
    HTTP3_ERR_CLOSED_CRITICAL_STREAM = -5,

    // A frame was received which is not permitted in the current state or on
    // the current stream
    HTTP3_ERR_FRAME_UNEXPECTED = -6,

    // A frame that fails to satisfy layout requirements or with an invalid
    // size was received
    HTTP3_ERR_FRAME_ERROR = -7,

    // The endpoint detected that its peer is exhibiting a behavior that might
    // be generating excessive load
    HTTP3_ERR_EXCESSIVE_LOAD = -8,

    // A stream ID or push ID was used incorrectly, such as exceeding a limit,
    // reducing a limit, or being reused
    HTTP3_ERR_ID_ERROR = -9,

    // An endpoint detected an error in the payload of a SETTINGS frame
    HTTP3_ERR_SETTINGS_ERROR = -10,

    // No SETTINGS frame was received at the beginning of the control stream
    HTTP3_ERR_MISSING_SETTINGS = -11,

    // -12 reserved

    // The stream is blocked
    HTTP3_ERR_STREAM_BLOCKED = -13,

    // The server rejected the request without performing any application
    // processing
    HTTP3_ERR_REQUEST_REJECTED = -14,

    // The request or its response (including pushed response) is cancelled
    HTTP3_ERR_REQUEST_CANCELLED = -15,

    // The client's stream terminated without containing a fully-formed request
    HTTP3_ERR_REQUEST_INCOMPLETE = -16,

    // An HTTP message was malformed and cannot be processed
    HTTP3_ERR_MESSAGE_ERROR = -17,

    // The TCP connection established in response to a CONNECT request was
    // reset or abnormally closed
    HTTP3_ERR_CONNECT_ERROR = -18,

    // The requested operation cannot be served over HTTP/3. The peer should
    // retry over HTTP/1.1
    HTTP3_ERR_VERSION_FALLBACK = -19,

    // The decoder failed to interpret an encoded field section and is not
    // able to continue decoding that field section
    HTTP3_ERR_QPACK_DECOMPRESSION_FAILED = -20,

    // The decoder failed to interpret an encoder instruction received on the
    // encoder stream
    HTTP3_ERR_QPACK_ENCODER_STREAM_ERROR = -21,

    // The encoder failed to interpret a decoder instruction received on the
    // decoder stream
    HTTP3_ERR_QPACK_DECODER_STREAM_ERROR = -22,
} http3_error;

#endif /* _TQUIC_DEF_H_ */
