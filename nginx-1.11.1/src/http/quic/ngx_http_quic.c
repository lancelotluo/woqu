
/*
 * Copyright (C) Tencent, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_quic_module.h>
#include <adaptor/ngx_http_quic_adaptor.h>

static void ngx_http_quic_read_handler(ngx_event_t *rev);
static void ngx_http_quic_write_handler(ngx_event_t *wev);
static void ngx_http_quic_handle_connection(ngx_http_quic_connection_t *qc);
static void ngx_http_quic_run_request(ngx_http_request_t *r);
static ngx_int_t
ngx_http_quic_construct_host(ngx_http_request_t *r, const char *host, int64_t host_len);
static ngx_int_t
ngx_http_quic_parse_method(ngx_http_request_t *r, ngx_http_quic_header_t *header);

static ngx_http_quic_stream_t *ngx_http_quic_create_stream(
    ngx_http_quic_connection_t *qc, void *stream);
static void ngx_http_quic_close_stream_handler(ngx_event_t *ev);

static void
ngx_http_quic_close_stream(ngx_http_quic_stream_t *stream, ngx_int_t rc);

static ngx_int_t
ngx_http_quic_construct_request_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_quic_construct_cookie_header(ngx_http_request_t *r);
static ngx_int_t
ngx_http_quic_construct_header(ngx_http_request_t *r, ngx_http_quic_header_t *header);
static ngx_int_t
ngx_http_quic_parse_path(ngx_http_request_t *r, ngx_http_quic_header_t *header);

static ngx_int_t
ngx_http_quic_process_request_line(ngx_http_request_t *r);

static void
ngx_http_quic_process_request_headers(ngx_http_request_t *r);

static ngx_int_t
ngx_http_quic_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc);

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
	if (qscf == NULL) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "fail to get ngx_http_quic_module conf");
        ngx_http_close_connection(c);
		return;
	}

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
		ngx_http_quic_conf_t nqcf;
		nqcf.certificate		= qscf->certificate.data;
		nqcf.certificate_key	= qscf->certificate_key.data; 

		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "first to create dispatcher, only once");
		qscf->quic_dispatcher->proto_quic_dispatcher = ngx_http_quic_create_dispatcher(c->fd, &nqcf);
		if (qscf->quic_dispatcher->proto_quic_dispatcher == NULL) {
			ngx_log_error(NGX_LOG_EMERG, c->log, 0,
                          "fail to create proto-quic dispatcher");
			return;
		}
	}

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "quic begin to process packet c:%p", c);

    ngx_http_quic_dispatcher_process_packet(c, qscf->quic_dispatcher->proto_quic_dispatcher, (const char*)c->buffer->start, c->buffer->last - c->buffer->start, c->sockaddr, c->local_sockaddr, c->fd);

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
}

void
ngx_http_quic_run_request(ngx_http_request_t *r)
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
        ngx_http_quic_close_stream(r->quic_stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
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


void ngx_http_quic_init_http_request(void *quic_stream, void *connection, const char *request, int request_len, const char *body, int body_len)
{
    ngx_connection_t          *c;
    ngx_pool_cleanup_t        *cln;
    ngx_http_connection_t     *hc;
    ngx_http_quic_stream_t    *ngx_quic_stream;
    ngx_http_quic_srv_conf_t    *qscf;
    ngx_http_quic_main_conf_t   *qmcf;
    ngx_http_quic_connection_t  *qc;
	ngx_int_t					rc;

    c = connection;
    qc = c->data;
	hc = qc->http_connection;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "init quic http connection, c:%p", c);

    c->log->action = "processing QUIC packet";

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http response for quic");
	ngx_quic_stream = ngx_http_quic_create_stream(qc, quic_stream);

	// lance_debug simple code
	ngx_http_request_t *r = ngx_quic_stream->request;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http request from proto_quic:%s", request);

	r->header_in->start = (unsigned char*)request;
	r->header_in->pos   = (unsigned char*)request;
	r->header_in->last  = (unsigned char*)request + request_len;
	r->header_in->end   = (unsigned char*)request + request_len;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
			   "request header_in: %s", r->header_in->start);

	ngx_http_quic_process_request_line(r);

	/*
	rc = ngx_http_quic_construct_host(ngx_quic_stream->request, host, host_len);
	if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "fail to construct host");
	}
	ngx_http_quic_header_t *method_header = ngx_palloc(r->pool, sizeof(ngx_http_quic_header_t));
	method_header->value.len = 3;
	method_header->value.data = ngx_palloc(r->pool, method_header->value.len);
	ngx_memcpy(method_header->value.data, "GET", method_header->value.len);

	rc = ngx_http_quic_parse_method(r, method_header);
	if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "fail to parse method");
	}

	ngx_http_quic_header_t *path_header = ngx_palloc(r->pool, sizeof(ngx_http_quic_header_t));
	path_header->value.len = sizeof("/index.html") - 1;
	path_header->value.data = ngx_palloc(r->pool, path_header->value.len);
	ngx_memcpy(path_header->value.data, "/index.html", path_header->value.len);
	rc = ngx_http_quic_parse_path(r, path_header);
	if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "fail to parse path");
	}
	*/

	//ngx_http_quic_run_request(r);
	//ngx_http_quic_response_availble(stream);
}

static ngx_http_quic_stream_t *
ngx_http_quic_create_stream(ngx_http_quic_connection_t *qc, void *quic_stream)
{
    ngx_log_t                 *log;
    ngx_event_t               *rev, *wev;
    ngx_connection_t          *fc;
    ngx_http_log_ctx_t        *ctx;
    ngx_http_request_t        *r;
    ngx_http_quic_stream_t      *stream;
    ngx_http_quic_srv_conf_t    *qscf;
    ngx_http_core_srv_conf_t	*cscf;

    fc = qc->free_fake_connections;

    if (fc) {
        qc->free_fake_connections = fc->data;

        rev = fc->read;
        wev = fc->write;
        log = fc->log;
        ctx = log->data;

    } else {
        fc = ngx_palloc(qc->pool, sizeof(ngx_connection_t));
        if (fc == NULL) {
            return NULL;
        }

        rev = ngx_palloc(qc->pool, sizeof(ngx_event_t));
        if (rev == NULL) {
            return NULL;
        }

        wev = ngx_palloc(qc->pool, sizeof(ngx_event_t));
        if (wev == NULL) {
            return NULL;
        }

        log = ngx_palloc(qc->pool, sizeof(ngx_log_t));
        if (log == NULL) {
            return NULL;
        }

        ctx = ngx_palloc(qc->pool, sizeof(ngx_http_log_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        ctx->connection = fc;
        ctx->request = NULL;
        ctx->current_request = NULL;
    }

    ngx_memcpy(log, qc->connection->log, sizeof(ngx_log_t));

    log->data = ctx;
    log->action = "reading client quic request headers";

    ngx_memzero(rev, sizeof(ngx_event_t));

    rev->data = fc;
    rev->ready = 1;
    rev->handler = ngx_http_quic_close_stream_handler;
    rev->log = log;

    ngx_memcpy(wev, rev, sizeof(ngx_event_t));

    wev->write = 1;

    ngx_memcpy(fc, qc->connection, sizeof(ngx_connection_t));

    fc->data = qc->http_connection;
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
    qc->connection->requests++;

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

    stream = ngx_pcalloc(r->pool, sizeof(ngx_http_quic_stream_t));
    if (stream == NULL) {
        ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    r->quic_stream = stream;

    r->quic_stream->request = r;
    r->quic_stream->connection = qc;
    r->quic_stream->quic_stream = quic_stream;

    qc->processing++;

    return stream;
}

static void ngx_http_quic_close_stream_handler(ngx_event_t *ev)
{
	return;
}

void
ngx_http_quic_close_stream(ngx_http_quic_stream_t *stream, ngx_int_t rc)
{
	return;
}

static ngx_int_t
ngx_http_quic_construct_cookie_header(ngx_http_request_t *r)
{
    u_char                     *buf, *p, *end;
    size_t                      len;
    ngx_str_t                  *vals;
    ngx_uint_t                  i;
    ngx_array_t                *cookies;
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t cookie = ngx_string("cookie");

    cookies = r->quic_stream->cookies;

    if (cookies == NULL) {
        return NGX_OK;
    }

    vals = cookies->elts;

    i = 0;
    len = 0;

    do {
        len += vals[i].len + 2;
    } while (++i != cookies->nelts);

    len -= 2;

    buf = ngx_pnalloc(r->pool, len + 1);
    if (buf == NULL) {
        ngx_http_quic_close_stream(r->quic_stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    p = buf;
    end = buf + len;

    for (i = 0; /* void */ ; i++) {

        p = ngx_cpymem(p, vals[i].data, vals[i].len);

        if (p == end) {
            *p = '\0';
            break;
        }

        *p++ = ';'; *p++ = ' ';
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        ngx_http_v2_close_stream(r->stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    h->hash = ngx_hash_key(cookie.data, cookie.len);

    h->key.len = cookie.len;
    h->key.data = cookie.data;

    h->value.len = len;
    h->value.data = buf;

    h->lowcase_key = cookie.data;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        ngx_http_quic_close_stream(r->quic_stream, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NGX_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_multi_header_lines()
         */
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_quic_construct_host(ngx_http_request_t *r, const char *quic_host, int64_t host_len)
{
    ngx_table_elt_t            *h;
    ngx_http_header_t          *hh;
    ngx_http_core_main_conf_t  *cmcf;

    static ngx_str_t host = ngx_string("host");

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = ngx_hash_key(host.data, host.len);

    h->key.len = host.len;
    h->key.data = host.data;

    h->value.len = host_len;
    h->value.data = (unsigned char *)quic_host;

    h->lowcase_key = host.data;

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                       h->lowcase_key, h->key.len);

    if (hh == NULL) {
        return NGX_ERROR;
    }

    if (hh->handler(r, h, hh->offset) != NGX_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_host()
         */
        return NGX_ABORT;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_quic_parse_path(ngx_http_request_t *r, ngx_http_quic_header_t *header)
{
    if (r->unparsed_uri.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :path header");

        return NGX_DECLINED;
    }

    if (header->value.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent empty :path header");

        return NGX_DECLINED;
    }

    r->uri_start = header->value.data;
    r->uri_end = header->value.data + header->value.len;

    if (ngx_http_parse_uri(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent invalid :path header: \"%V\"",
                      &header->value);

        return NGX_DECLINED;
    }

    if (ngx_http_process_request_uri(r) != NGX_OK) {
        /*
         * request has been finalized already
         * in ngx_http_process_request_uri()
         */
        return NGX_ABORT;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_quic_parse_method(ngx_http_request_t *r, ngx_http_quic_header_t *header)
{
    size_t         k, len;
    ngx_uint_t     n;
    const u_char  *p, *m;

    /*
     * This array takes less than 256 sequential bytes,
     * and if typical CPU cache line size is 64 bytes,
     * it is prefetched for 4 load operations.
     */
    static const struct {
        u_char            len;
        const u_char      method[11];
        uint32_t          value;
    } tests[] = {
        { 3, "GET",       NGX_HTTP_GET },
        { 4, "POST",      NGX_HTTP_POST },
        { 4, "HEAD",      NGX_HTTP_HEAD },
        { 7, "OPTIONS",   NGX_HTTP_OPTIONS },
        { 8, "PROPFIND",  NGX_HTTP_PROPFIND },
        { 3, "PUT",       NGX_HTTP_PUT },
        { 5, "MKCOL",     NGX_HTTP_MKCOL },
        { 6, "DELETE",    NGX_HTTP_DELETE },
        { 4, "COPY",      NGX_HTTP_COPY },
        { 4, "MOVE",      NGX_HTTP_MOVE },
        { 9, "PROPPATCH", NGX_HTTP_PROPPATCH },
        { 4, "LOCK",      NGX_HTTP_LOCK },
        { 6, "UNLOCK",    NGX_HTTP_UNLOCK },
        { 5, "PATCH",     NGX_HTTP_PATCH },
        { 5, "TRACE",     NGX_HTTP_TRACE }
    }, *test;

    if (r->method_name.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :method header");

        return NGX_DECLINED;
    }

    if (header->value.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent empty :method header");

        return NGX_DECLINED;
    }

    r->method_name.len = header->value.len;
    r->method_name.data = header->value.data;

    len = r->method_name.len;
    n = sizeof(tests) / sizeof(tests[0]);
    test = tests;

    do {
        if (len == test->len) {
            p = r->method_name.data;
            m = test->method;
            k = len;

            do {
                if (*p++ != *m++) {
                    goto next;
                }
            } while (--k);

            r->method = test->value;
            return NGX_OK;
        }

    next:
        test++;

    } while (--n);

    p = r->method_name.data;

    do {
        if ((*p < 'A' || *p > 'Z') && *p != '_') {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                          "client sent invalid method: \"%V\"",
                          &r->method_name);

            return NGX_DECLINED;
        }

        p++;

    } while (--len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_quic_parse_scheme(ngx_http_request_t *r, ngx_http_quic_header_t *header)
{
    if (r->schema_start) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent duplicate :schema header");

        return NGX_DECLINED;
    }

    if (header->value.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "client sent empty :schema header");

        return NGX_DECLINED;
    }

    r->schema_start = header->value.data;
    r->schema_end = header->value.data + header->value.len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_quic_process_request_line(ngx_http_request_t *r)
{
	ngx_connection_t *c;
    ngx_int_t            rc, rv;
    ngx_str_t            host;

	c = r->connection;
	rc = ngx_http_parse_request_line(r, r->header_in);
	if (rc != NGX_OK) {
		ngx_log_error(NGX_LOG_ERR, c->log, 0,
			   "fail to parse request line: %d", rc);
		return  rc;
	}

	/* the request line has been parsed successfully */

	r->request_line.len = r->request_end - r->request_start;
	r->request_line.data = r->request_start;
	r->request_length = r->header_in->pos - r->request_start;

	ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
				   "http request line: \"%V\"", &r->request_line);

	r->method_name.len = r->method_end - r->request_start + 1;
	r->method_name.data = r->request_line.data;

	if (ngx_http_process_request_uri(r) != NGX_OK) {
		ngx_log_error(NGX_LOG_INFO, c->log, 0,
			   "fail to process request uri: %d", rc);
		return NGX_ERROR;
	}

	if (r->host_start && r->host_end) {

		host.len = r->host_end - r->host_start;
		host.data = r->host_start;

		rc = ngx_http_quic_validate_host(&host, r->pool, 0);

		if (rc == NGX_DECLINED) {
			ngx_log_error(NGX_LOG_INFO, c->log, 0,
						  "client sent invalid host in request line");
			return rc;
		}

		if (rc == NGX_ERROR) {
			//ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			return rc;
		}
/*
		if (ngx_http_set_virtual_server(r, &host) == NGX_ERROR) {
			return NGX_ERROR;
		}
*/
		r->headers_in.server = host;
	}

	if (ngx_list_init(&r->headers_in.headers, r->pool, 20,
					  sizeof(ngx_table_elt_t))
		!= NGX_OK)
	{
		//ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
		return NGX_ERROR;
	}

	c->log->action = "reading client request headers";

	ngx_http_quic_process_request_headers(r);

	return NGX_OK;
}

static void
ngx_http_quic_process_request_headers(ngx_http_request_t *r)
{
    u_char                     *p;
    size_t                      len;
    ssize_t                     n;
    ngx_int_t                   rc, rv;
    ngx_table_elt_t            *h;
    ngx_connection_t           *c;
    ngx_http_header_t          *hh;
    ngx_http_core_srv_conf_t   *cscf;
    ngx_http_core_main_conf_t  *cmcf;

    c = r->connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http process request header line");

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    rc = NGX_AGAIN;

    for ( ;; ) {

        if (rc == NGX_AGAIN) {

            if (r->header_in->pos == r->header_in->end) {

                //rv = ngx_http_alloc_large_header_buffer(r, 0);

                if (rv == NGX_ERROR) {
                    //ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return;
                }

                if (rv == NGX_DECLINED) {
                    p = r->header_name_start;

                    r->lingering_close = 1;

                    if (p == NULL) {
                        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                      "client sent too large request");
                        ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                        return;
                    }

                    len = r->header_in->end - p;

                    if (len > NGX_MAX_ERROR_STR - 300) {
                        len = NGX_MAX_ERROR_STR - 300;
                    }

                    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                                "client sent too long header line: \"%*s...\"",
                                len, r->header_name_start);

                    ngx_http_finalize_request(r,
                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);
                    return;
                }
            }

        }

        /* the host header could change the server configuration context */
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        rc = ngx_http_parse_header_line(r, r->header_in,
                                        cscf->underscores_in_headers);

        if (rc == NGX_OK) {

            r->request_length += r->header_in->pos - r->header_name_start;

            if (r->invalid_header && cscf->ignore_invalid_headers) {

                /* there was error while a header line parsing */

                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client sent invalid header line: \"%*s\"",
                              r->header_end - r->header_name_start,
                              r->header_name_start);
                continue;
            }

            /* a header line has been parsed successfully */

            h = ngx_list_push(&r->headers_in.headers);
            if (h == NULL) {
                //ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->key.data = r->header_name_start;
            h->key.data[h->key.len] = '\0';

            h->value.len = r->header_end - r->header_start;
            h->value.data = r->header_start;
            h->value.data[h->value.len] = '\0';

            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
            if (h->lowcase_key == NULL) {
                //ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (h->key.len == r->lowcase_index) {
                ngx_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = ngx_hash_find(&cmcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
                return;
            }

            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http header done");

            r->request_length += r->header_in->pos - r->header_name_start;

            r->http_state = NGX_HTTP_PROCESS_REQUEST_STATE;

            rc = ngx_http_process_request_header(r);

            if (rc != NGX_OK) {
                return;
            }

            ngx_http_process_request(r);

            return;
        }

        if (rc == NGX_AGAIN) {

            /* a header line parsing is still not complete */

            continue;
        }

        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client sent invalid header line");

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }
}

static ngx_int_t
ngx_http_quic_validate_host(ngx_str_t *host, ngx_pool_t *pool, ngx_uint_t alloc)
{
    u_char  *h, ch;
    size_t   i, dot_pos, host_len;

    enum {
        sw_usual = 0,
        sw_literal,
        sw_rest
    } state;

    dot_pos = host->len;
    host_len = host->len;

    h = host->data;

    state = sw_usual;

    for (i = 0; i < host->len; i++) {
        ch = h[i];

        switch (ch) {

        case '.':
            if (dot_pos == i - 1) {
                return NGX_DECLINED;
            }
            dot_pos = i;
            break;

        case ':':
            if (state == sw_usual) {
                host_len = i;
                state = sw_rest;
            }
            break;

        case '[':
            if (i == 0) {
                state = sw_literal;
            }
            break;

        case ']':
            if (state == sw_literal) {
                host_len = i + 1;
                state = sw_rest;
            }
            break;

        case '\0':
            return NGX_DECLINED;

        default:

            if (ngx_path_separator(ch)) {
                return NGX_DECLINED;
            }

            if (ch >= 'A' && ch <= 'Z') {
                alloc = 1;
            }

            break;
        }
    }

    if (dot_pos == host_len - 1) {
        host_len--;
    }

    if (host_len == 0) {
        return NGX_DECLINED;
    }

    if (alloc) {
        host->data = ngx_pnalloc(pool, host_len);
        if (host->data == NULL) {
            return NGX_ERROR;
        }

        ngx_strlow(host->data, h, host_len);
    }

    host->len = host_len;

    return NGX_OK;
}
