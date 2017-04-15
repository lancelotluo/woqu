
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

    ngx_http_quic_dispatcher_process_packet1(qscf->quic_dispatcher->proto_quic_dispatcher, c->buffer->start, c->buffer->last - c->buffer->start, c->sockaddr, c->local_sockaddr, c->fd);
   // ngx_http_quic_dispatcher_process_packet(c->buffer->start, c->buffer->last - c->buffer->start, c->sockaddr, c->local_sockaddr, c->fd);
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
