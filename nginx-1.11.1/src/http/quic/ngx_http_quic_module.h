
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _NGX_HTTP_QUIC_MODULE_H_INCLUDED_
#define _NGX_HTTP_QUIC_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_quic_adaptor.h"

struct ngx_http_quic_dispatcher_s {
	void *proto_quic_dispatcher;
};

typedef struct ngx_http_quic_dispatcher_s ngx_http_quic_dispatcher_t;

typedef struct {
    size_t                           recv_buffer_size;
    u_char							*recv_buffer;
	ngx_http_quic_dispatcher_t		*quic_dispatcher;
} ngx_http_quic_main_conf_t;


typedef struct {
    size_t                          pool_size;
    ngx_uint_t                      concurrent_streams;
    size_t                          max_field_size;
    size_t                          max_header_size;
    size_t                          preread_size;
    ngx_uint_t                      streams_index_mask;
    ngx_msec_t                      recv_timeout;
    ngx_msec_t                      idle_timeout;
	ngx_http_quic_dispatcher_t     *quic_dispatcher;
} ngx_http_quic_srv_conf_t;


typedef struct {
    size_t                          chunk_size;
} ngx_http_quic_loc_conf_t;


extern ngx_module_t  ngx_http_quic_module;


#endif /* _NGX_HTTP_V2_MODULE_H_INCLUDED_ */
