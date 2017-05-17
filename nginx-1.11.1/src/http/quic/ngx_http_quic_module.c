
/*
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_quic_module.h>

static ngx_int_t ngx_http_quic_proto_init(ngx_cycle_t *cycle);

static void *ngx_http_quic_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_quic_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_quic_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_quic_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static void *ngx_http_quic_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_quic_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

static char *ngx_http_quic_recv_buffer_size(ngx_conf_t *cf, void *post,
    void *data);
static char *ngx_http_quic_pool_size(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_quic_preread_size(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_quic_chunk_size(ngx_conf_t *cf, void *post, void *data);


static ngx_conf_post_t  ngx_http_quic_recv_buffer_size_post =
    { ngx_http_quic_recv_buffer_size };
static ngx_conf_post_t  ngx_http_quic_pool_size_post =
    { ngx_http_quic_pool_size };
static ngx_conf_post_t  ngx_http_quic_preread_size_post =
    { ngx_http_quic_preread_size };
static ngx_conf_post_t  ngx_http_quic_chunk_size_post =
    { ngx_http_quic_chunk_size };


static ngx_command_t  ngx_http_quic_commands[] = {

    { ngx_string("quic_recv_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_quic_main_conf_t, recv_buffer_size),
      &ngx_http_quic_recv_buffer_size_post },

    { ngx_string("quic_pool_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_quic_srv_conf_t, pool_size),
      &ngx_http_quic_pool_size_post },

    { ngx_string("quic_max_concurrent_streams"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_quic_srv_conf_t, concurrent_streams),
      NULL },

    { ngx_string("quic_max_field_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_quic_srv_conf_t, max_field_size),
      NULL },

    { ngx_string("quic_max_header_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_quic_srv_conf_t, max_header_size),
      NULL },

    { ngx_string("quic_body_preread_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_quic_srv_conf_t, preread_size),
      &ngx_http_quic_preread_size_post },

    { ngx_string("quic_recv_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_quic_srv_conf_t, recv_timeout),
      NULL },

    { ngx_string("quic_idle_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_quic_srv_conf_t, idle_timeout),
      NULL },

    { ngx_string("quic_chunk_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_quic_loc_conf_t, chunk_size),
      &ngx_http_quic_chunk_size_post },

    { ngx_string("quic_ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_quic_srv_conf_t, certificate),
      NULL },

    { ngx_string("quic_ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_quic_srv_conf_t, certificate_key),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_quic_module_ctx = {
    NULL,						             /* preconfiguration */
    NULL,                                    /* postconfiguration */

    ngx_http_quic_create_main_conf,          /* create main configuration */
    ngx_http_quic_init_main_conf,            /* init main configuration */

    ngx_http_quic_create_srv_conf,           /* create server configuration */
    ngx_http_quic_merge_srv_conf,            /* merge server configuration */

    ngx_http_quic_create_loc_conf,           /* create location configuration */
    ngx_http_quic_merge_loc_conf             /* merge location configuration */
};


ngx_module_t  ngx_http_quic_module = {
    NGX_MODULE_V1,
    &ngx_http_quic_module_ctx,             /* module context */
    ngx_http_quic_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,						           /* init module */
    ngx_http_quic_proto_init,              /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_quic_vars[] = {
    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static void *
ngx_http_quic_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_quic_main_conf_t  *hqmcf;

    hqmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_quic_main_conf_t));
    if (hqmcf == NULL) {
        return NULL;
    }

    hqmcf->recv_buffer_size = NGX_CONF_UNSET_SIZE;

    return hqmcf;
}


static char *
ngx_http_quic_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_quic_main_conf_t *hqmcf = conf;

    ngx_conf_init_size_value(hqmcf->recv_buffer_size, 256 * 1024);

	//hqmcf->quic_dispatcher = 

    return NGX_CONF_OK;
}


static void *
ngx_http_quic_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_quic_srv_conf_t  *hqscf;

    hqscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_quic_srv_conf_t));
    if (hqscf == NULL) {
        return NULL;
    }

    hqscf->pool_size = NGX_CONF_UNSET_SIZE;

    hqscf->concurrent_streams = NGX_CONF_UNSET_UINT;

    hqscf->max_field_size = NGX_CONF_UNSET_SIZE;
    hqscf->max_header_size = NGX_CONF_UNSET_SIZE;

    hqscf->preread_size = NGX_CONF_UNSET_SIZE;

    hqscf->recv_timeout = NGX_CONF_UNSET_MSEC;
    hqscf->idle_timeout = NGX_CONF_UNSET_MSEC;

	hqscf->quic_dispatcher = ngx_pcalloc(cf->pool, sizeof(ngx_http_quic_dispatcher_t));
	if (hqscf->quic_dispatcher == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "fail to alloc quic_dispatcher");
		return NULL;
	}

    return hqscf;
}


static char *
ngx_http_quic_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_quic_srv_conf_t *prev = parent;
    ngx_http_quic_srv_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->pool_size, prev->pool_size, 4096);

    ngx_conf_merge_uint_value(conf->concurrent_streams,
                              prev->concurrent_streams, 128);

    ngx_conf_merge_size_value(conf->max_field_size, prev->max_field_size,
                              4096);
    ngx_conf_merge_size_value(conf->max_header_size, prev->max_header_size,
                              16384);

    ngx_conf_merge_size_value(conf->preread_size, prev->preread_size, 65536);
    
	ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");

    ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");

    ngx_conf_merge_msec_value(conf->recv_timeout,
                              prev->recv_timeout, 30000);
    ngx_conf_merge_msec_value(conf->idle_timeout,
                              prev->idle_timeout, 3000);
                              //prev->idle_timeout, 180000);

    return NGX_CONF_OK;
}


static void *
ngx_http_quic_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_quic_loc_conf_t  *qlcf;

    qlcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_quic_loc_conf_t));
    if (qlcf == NULL) {
        return NULL;
    }

    qlcf->chunk_size = NGX_CONF_UNSET_SIZE;

    return qlcf;
}


static char *
ngx_http_quic_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_quic_loc_conf_t *prev = parent;
    ngx_http_quic_loc_conf_t *conf = child;

    ngx_conf_merge_size_value(conf->chunk_size, prev->chunk_size, 8 * 1024);

    return NGX_CONF_OK;
}


static char *
ngx_http_quic_recv_buffer_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp <= 2 * NGX_HTTP_V2_STATE_BUFFER_SIZE) {
        return "value is too small";
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_quic_pool_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp < NGX_MIN_POOL_SIZE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be no less than %uz",
                           NGX_MIN_POOL_SIZE);

        return NGX_CONF_ERROR;
    }

    if (*sp % NGX_POOL_ALIGNMENT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the pool size must be a multiple of %uz",
                           NGX_POOL_ALIGNMENT);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_quic_preread_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp > NGX_HTTP_V2_MAX_WINDOW) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the maximum body preread buffer size is %uz",
                           NGX_HTTP_V2_MAX_WINDOW);

        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_quic_chunk_size(ngx_conf_t *cf, void *post, void *data)
{
    size_t *sp = data;

    if (*sp == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "the quic chunk size cannot be zero");

        return NGX_CONF_ERROR;
    }

    if (*sp > NGX_HTTP_V2_MAX_FRAME_SIZE) {
        *sp = NGX_HTTP_V2_MAX_FRAME_SIZE;
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_quic_proto_init(ngx_cycle_t *cycle) 
{
	ngx_http_quic_main_conf_t *qmcf;

//todo
//maybe we should initialize quid_dispatcher here
//
	qmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_quic_module);
/*
	if (!qmcf) {
		return NGX_ERROR;
	}
*/
	return NGX_OK;
}

