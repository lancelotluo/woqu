
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_quic_module.h>
#include <adaptor/ngx_http_quic_adaptor.h>


static void ngx_http_quic_read_handler(ngx_event_t *rev);
static void ngx_http_quic_write_handler(ngx_event_t *wev);
static void ngx_http_quic_handle_connection(ngx_http_quic_connection_t *qc);


void
ngx_http_quic_init(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_pool_cleanup_t        *cln;
    ngx_http_connection_t     *hc;
    ngx_http_quic_srv_conf_t    *qscf;
    ngx_http_quic_main_conf_t   *qmcf;
    ngx_http_quic_connection_t  *qc;
    ngx_http_quic_stream_t		*stream;

    c = rev->data;
    hc = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "init quic connection");

    c->log->action = "processing QUIC packet";

    qmcf = ngx_http_get_module_main_conf(hc->conf_ctx, ngx_http_quic_module);

    if (qmcf->recv_buffer == NULL) {
        qmcf->recv_buffer = ngx_palloc(ngx_cycle->pool,
                                        qmcf->recv_buffer_size);
        if (qmcf->recv_buffer == NULL) {
            ngx_http_close_connection(c);
            return;
        }
    }

    qc = ngx_pcalloc(c->pool, sizeof(ngx_http_quic_connection_t));
    if (qc == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    qc->connection = c;
    qc->http_connection = hc;

    qscf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_quic_module);

    qc->pool = ngx_create_pool(qscf->pool_size, qc->connection->log);
    if (qc->pool == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    cln = ngx_pool_cleanup_add(c->pool, 0);
    if (cln == NULL) {
        ngx_http_close_connection(c);
        return;
    }

    c->data = qc;

    rev->handler = ngx_http_quic_read_handler;
    c->write->handler = ngx_http_quic_write_handler;
	if (qscf->quic_dispatcher->proto_quic_dispatcher == NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "create dispatcher for debug");
		qscf->quic_dispatcher->proto_quic_dispatcher = ngx_http_quic_create_dispatcher(c->fd);
	}

    ngx_http_quic_dispatcher_process_packet(c, qscf->quic_dispatcher->proto_quic_dispatcher, c->buffer->start, c->buffer->last - c->buffer->start, c->sockaddr, c->local_sockaddr, c->fd);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "quic process packet for debug");
}


static void
ngx_http_quic_read_handler(ngx_event_t *rev)
{
    u_char                    *p, *end;
    size_t                     available;
    ssize_t                    n;
    ngx_connection_t          *c;
    ngx_http_quic_main_conf_t   *qmcf;
    ngx_http_quic_connection_t  *qc;
    c = rev->data;
	qc = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "quic read handler");

    ngx_http_quic_handle_connection(qc);
}


static void
ngx_http_quic_write_handler(ngx_event_t *wev)
{
    ngx_int_t                  rc;
    ngx_queue_t               *q;
    ngx_connection_t          *c;
    ngx_http_quic_connection_t  *qc;

    c = wev->data;
    qc = c->data;

    if (wev->timedout) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "quic write event timed out");
        c->error = 1;
        return;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "quic write handler");

    ngx_http_quic_handle_connection(qc);
}


static void
ngx_http_quic_handle_connection(ngx_http_quic_connection_t *qc)
{
    ngx_connection_t          *c;
    ngx_http_quic_srv_conf_t  *qscf;

    c = qc->connection;
    
	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "handle quic connection");


    qscf = ngx_http_get_module_srv_conf(qc->http_connection->conf_ctx,
                                         ngx_http_quic_module);

    c->write->handler = ngx_http_empty_handler;

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    ngx_add_timer(c->read, qscf->idle_timeout);

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "create quic dispatcher");

	//ngx_http_quic_create_dispatcher(c->fd);
}

/*
void
ngx_http_quic_run_request(void *stream, const char *host, int64_t host_len, const char *path, int64_t path_len, const char *body, int64_t body_len)
{
    if (ngx_http_quic_construct_request_line(r) != NGX_OK) {
        return;
    }

    if (ngx_http_quic_construct_cookie_header(r) != NGX_OK) {
        return;
    }

    r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

    if (ngx_http_process_request_header(r) != NGX_OK) {
        return;
    }

    ngx_http_process_request(r);
}

static ngx_http_quic_stream_t *
ngx_http_quic_create_stream(ngx_http_quic_connection_t *qc)
{
    ngx_log_t                 *log;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *fc;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_request_t        *r;
    ngx_http_quic_stream_t      *stream;
    ngx_http_quic_srv_conf_t    *h2scf;
    ngx_http_core_srv_conf_t  *cscf;

    fc = h2c->free_fake_connections;

    if (fc) {
        h2c->free_fake_connections = fc->data;

        rev = fc->read;
        wev = fc->write;
        log = fc->log;
        ctx = log->data;

    } else {
        fc = ngx_palloc(h2c->pool, sizeof(ngx_connection_t));
        if (fc == NULL) {
            return NULL;
        }

        rev = ngx_palloc(h2c->pool, sizeof(ngx_event_t));
        if (rev == NULL) {
            return NULL;
        }

        wev = ngx_palloc(h2c->pool, sizeof(ngx_event_t));
        if (wev == NULL) {
            return NULL;
        }

        log = ngx_palloc(h2c->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            return NULL;
        }

        ctx = ngx_palloc(h2c->pool, sizeof(ngx_http_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->connection = fc;
        ctx->request = NULL;
        ctx->current_request = NULL;
    }

    ngx_memcpy(log, h2c->connection->log, sizeof(ngx_log_t));

    log->data = ctx;
    log->action = "reading client request headers";

    ngx_memzero(rev, sizeof(ngx_event_t));

    rev->data = fc;
    rev->ready = 1;
    rev->handler = ngx_http_v2_close_stream_handler;
    rev->log = log;

    ngx_memcpy(wev, rev, sizeof(ngx_event_t));

    wev->write = 1;

    ngx_memcpy(fc, h2c->connection, sizeof(ngx_connection_t));

    fc->data = h2c->http_connection;
    fc->read = rev;
    fc->write = wev;
    fc->sent = 0;
    fc->log = log;
    fc->buffered = 0;
    fc->sndlowat = 1;
    fc->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    r = ngx_http_create_request(fc);
    if (r == NULL) {
        return NULL;
    }

    ngx_str_set(&r->http_protocol, "HTTP/2.0");

    r->http_version = NGX_HTTP_VERSION_20;
    r->valid_location = 1;

    fc->data = r;
    h2c->connection->requests++;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    r->header_in = ngx_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;

    stream = ngx_pcalloc(r->pool, sizeof(ngx_http_v2_stream_t));
    if (stream == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->stream = stream;

    stream->request = r;
    stream->connection = h2c;

    h2scf = ngx_http_get_module_srv_conf(r, ngx_http_v2_module);

    stream->send_window = h2c->init_window;
    stream->recv_window = h2scf->preread_size;

    h2c->processing++;

    return stream;
}

void
ngx_http_quic_switch_in_nginx(void *stream, const char *host, int64_t host_len, const char *path, int64_t path_len, const char *body, int64_t body_len)
{
		
	

}

*/
static ngx_int_t
ngx_http_quic_construct_request_line(ngx_http_request_t *r)
{
    u_char  *p;

    static const u_char ending[] = " HTTP/2.0";

    if (r->method_name.len == 0
        || r->unparsed_uri.len == 0)
    {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return NGX_ERROR;
    }

    r->request_line.len = r->method_name.len + 1
                          + r->unparsed_uri.len
                          + sizeof(ending) - 1;

    p = ngx_pnalloc(r->pool, r->request_line.len + 1);
    if (p == NULL) {
        ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    r->request_line.data = p;

    p = ngx_cpymem(p, r->method_name.data, r->method_name.len);

    *p++ = ' ';

    p = ngx_cpymem(p, r->unparsed_uri.data, r->unparsed_uri.len);

    ngx_memcpy(p, ending, sizeof(ending));

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 http request line: \"%V\"", &r->request_line);

    return NGX_OK;
}
