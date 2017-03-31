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


typedef u_char *(*ngx_http_quic_handler_pt) (ngx_http_quic_connection_t *qc,
    u_char *pos, u_char *end);


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
};


void ngx_http_quic_init(ngx_event_t *rev);

#endif
