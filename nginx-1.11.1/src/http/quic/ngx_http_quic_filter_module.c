
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <ngx_http_quic_module.h>


/*
 * This returns precise number of octets for values in range 0..253
 * and estimate number for the rest, but not smaller than required.
 */


static ngx_int_t ngx_http_quic_filter_init(ngx_conf_t *cf);

static ngx_inline ngx_int_t ngx_http_quic_filter_send(
    ngx_connection_t *fc, ngx_http_quic_stream_t *stream);

static ngx_http_module_t  ngx_http_quic_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_quic_filter_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_quic_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_quic_filter_module_ctx,        /* module context */
    NULL,                                  /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_quic_headers_filter(ngx_http_request_t *r)
{
    u_char                     status, *pos, *start, *p, *tmp;
    size_t                     len, tmp_len;
    ngx_str_t                  host, location;
    ngx_uint_t                 i, port;
    ngx_list_part_t           *part;
    ngx_table_elt_t           *header;
    ngx_connection_t          *fc;
    ngx_http_cleanup_t        *cln;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_core_srv_conf_t  *cscf;
    struct sockaddr_in        *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6       *sin6;
#endif
    u_char                     addr[NGX_SOCKADDR_STRLEN];

    static const u_char nginx[5] = "\x84\xaa\x63\x55\xe7";
#if (NGX_HTTP_GZIP)
    static const u_char accept_encoding[12] =
        "\x8b\x84\x84\x2d\x69\x5b\x05\x44\x3c\x86\xaa\x6f";
#endif
// lance_debug
    return ngx_http_next_header_filter(r);

    if (!r->quic_stream) {
        return ngx_http_next_header_filter(r);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "quic header filter");

    if (r->header_sent) {
        return NGX_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return NGX_OK;
    }

    if (r->method == NGX_HTTP_HEAD) {
        r->header_only = 1;
    }


    fc = r->connection;

    return ngx_http_quic_filter_send(fc, r->quic_stream);
}

static ngx_inline ngx_int_t
ngx_http_quic_filter_send(ngx_connection_t *fc, ngx_http_quic_stream_t *stream)
{
	ngx_http_quic_response_available(stream->quic_stream);
/*
    stream->blocked = 1;

    if (ngx_http_v2_send_output_queue(stream->connection) == NGX_ERROR) {
        fc->error = 1;
        return NGX_ERROR;
    }

    stream->blocked = 0;

    if (stream->queued) {
        fc->buffered |= NGX_HTTP_V2_BUFFERED;
        fc->write->active = 1;
        fc->write->ready = 0;
        return NGX_AGAIN;
    }

    fc->buffered &= ~NGX_HTTP_V2_BUFFERED;
*/
    return NGX_OK;
}

ngx_int_t
ngx_http_quic_filter_send_header(ngx_http_request_t *r, ngx_buf_t *out)
{
	return NGX_OK;
}

static ngx_int_t
ngx_http_quic_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_quic_headers_filter;

    return NGX_OK;
}

ngx_int_t
ngx_http_quic_header_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	ngx_http_quic_response_header_available(r->quic_stream->quic_stream, in->buf->start, in->buf->pos - in->buf->start);
	return NGX_OK;
}
