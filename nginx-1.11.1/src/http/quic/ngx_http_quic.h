/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NGX_HTTP_QUIC_H_INCLUDED_
#define _NGX_HTTP_QUIC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_quic_connection_s   ngx_http_quic_connection_t;
typedef struct ngx_http_quic_header_s	ngx_http_quic_header_t;

typedef u_char *(*ngx_http_quic_handler_pt) (ngx_http_quic_connection_t *qc,
    u_char *pos, u_char *end);

struct ngx_http_quic_header_s {
	ngx_str_t name;
	ngx_str_t value;
};

struct ngx_http_quic_stream_s {
    ngx_http_request_t              *request;
    ngx_http_quic_connection_t      *connection;
	void							*quic_stream;// point to stream in proto-quic
    ngx_uint_t                       queued;

    /*
     * A change to SETTINGS_INITIAL_WINDOW_SIZE could cause the
     * send_window to become negative, hence it's signed.
     */
    ssize_t                          send_window;
    size_t                           recv_window;

    ngx_buf_t                       *preread;

    ngx_array_t                     *cookies;

    size_t                           header_limit;

    ngx_pool_t                      *pool;

    unsigned                         handled:1;
    unsigned                         blocked:1;
    unsigned                         exhausted:1;
    unsigned                         in_closed:1;
    unsigned                         out_closed:1;
    unsigned                         rst_sent:1;
    unsigned                         skip_data:1;
};

struct ngx_http_quic_connection_s {
    ngx_connection_t                *connection;
    ngx_http_connection_t           *http_connection;

    ngx_uint_t                       processing;

    size_t                           send_window;
    size_t                           recv_window;
    size_t                           init_window;

    size_t                           frame_size;

    ngx_queue_t                      waiting;

    ngx_pool_t                      *pool;

    ngx_connection_t                *free_fake_connections;

    ngx_uint_t                       last_sid;

    unsigned                         closed_nodes:8;
    unsigned                         settings_ack:1;
    unsigned                         blocked:1;
    unsigned                         has_stream:1;
};


void ngx_http_quic_init(ngx_event_t *rev);

void
ngx_http_quic_switch_in_nginx(void *stream, const char *host, int64_t host_len, const char *path, int64_t path_len, const char *body, int64_t body_len);

ngx_int_t ngx_http_quic_init_http_request(void *quic_stream, void *connection, const char *request, int request_len, const char *body, int body_len);

ngx_int_t
ngx_http_quic_header_filter(ngx_http_request_t *r, ngx_chain_t *in);

void
ngx_http_quic_close_stream(ngx_http_quic_stream_t *stream, ngx_int_t rc);

#endif
