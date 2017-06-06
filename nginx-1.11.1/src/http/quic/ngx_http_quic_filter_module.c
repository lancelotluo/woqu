
/*
 * Copyright (C) Tencent, Inc.
 * 
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
static ngx_chain_t *
ngx_http_quic_send_chain(ngx_connection_t *fc, ngx_chain_t *in, off_t limit);

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

	fc = r->connection;

    if (r->quic_stream) {
		fc->send_chain = ngx_http_quic_send_chain;	
	}

    return ngx_http_next_header_filter(r);
}

static ngx_inline ngx_int_t
ngx_http_quic_filter_send(ngx_connection_t *fc, ngx_http_quic_stream_t *stream)
{
	ngx_http_quic_response_available(stream->quic_stream);
	//ngx_http_quic_response_header_available(r->quic_stream->quic_stream, in->buf->start, in->buf->last - in->buf->start);
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


ngx_int_t
ngx_http_quic_header_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "begin to ngx_http_quic_response_header_available");

    //if (r->quic_stream->skip_data && r->discard_body) {
    if (r->quic_stream->skip_data) {
        in->buf->last_buf = 1;
    }

    ngx_int_t sent = in->buf->last - in->buf->start;

	ngx_http_quic_response_header_available(r->quic_stream->quic_stream, in->buf->start, sent, in->buf->last_buf);

    ngx_chain_update_sent(in, sent);

	return NGX_OK;
}

static ngx_chain_t *
ngx_http_quic_send_chain(ngx_connection_t *fc, ngx_chain_t *in, off_t limit)
{
    off_t                      size, offset;
    size_t                     rest, frame_size;
	int						   last, buf_len;
    ngx_chain_t               *cl, *out, **ln;
    ngx_http_request_t        *r;
    ngx_http_quic_stream_t      *stream;
    ngx_http_quic_loc_conf_t    *qlcf;
    ngx_http_quic_connection_t  *qcc;

    r = fc->data;
    stream = r->quic_stream;

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, fc->log, 0,
				"quic send chain");
	out = in;	

	while (out) {
		last = 0;
		if (out->buf->last_buf) {
		//if (out->buf->last_buf || (out->buf->flush && !out->next)) {
			last = 1;
		} 
	
		buf_len = ngx_buf_size(out->buf);
		ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ngx_http_quic_response_body_available, buf_len:%d last:%d", buf_len, last);

		if (buf_len) {
			ngx_http_quic_response_body_available(r->quic_stream->quic_stream, out->buf->pos, buf_len, last);
			in = ngx_chain_update_sent(in, buf_len);
		}

		out = out->next;
	}
	
    return in;
}

static ngx_int_t
ngx_http_quic_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_quic_headers_filter;

    return NGX_OK;
}
