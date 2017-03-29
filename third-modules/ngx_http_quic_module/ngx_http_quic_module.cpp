extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
}

#include <iostream>

#include "net/quic/core/crypto/crypto_handshake.h"
#include "net/quic/core/crypto/quic_random.h"
#include "net/quic/core/quic_crypto_stream.h"
#include "net/quic/core/quic_data_reader.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/tools/quic/platform/impl/quic_epoll_clock.h"
#include "net/tools/quic/platform/impl/quic_socket_utils.h"
#include "net/tools/quic/quic_dispatcher.h"
#include "net/tools/quic/quic_epoll_alarm_factory.h"
#include "net/tools/quic/quic_epoll_connection_helper.h"
#include "net/tools/quic/quic_http_response_cache.h"
#include "net/tools/quic/quic_packet_reader.h"
#include "net/tools/quic/quic_simple_crypto_server_stream_helper.h"
#include "net/tools/quic/quic_simple_dispatcher.h"


using namespace std;

#define HELLO_WORLD "hello world"

static char *ngx_http_quic(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_quic_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_quic_commands[] = {

    { ngx_string("hello_world"), /* directive */
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS, /* location context and takes
                                            no arguments*/
      ngx_http_quic, /* configuration setup function */
      0, /* No offset. Only one context is supported. */
      0, /* No offset when storing the module configuration on struct. */
      NULL},

    ngx_null_command /* command termination */
};

/* The hello world string. */
static u_char ngx_hello_world[] = HELLO_WORLD;

/* The module context. */
static ngx_http_module_t ngx_http_quic_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_quic_module = {
    NGX_MODULE_V1,
    &ngx_http_quic_module_ctx, /* module context */
    ngx_http_quic_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t ngx_http_quic_handler(ngx_http_request_t *r)
{
	cout << "hello quic"<<endl;
    return NGX_OK;
} 

char *ngx_http_quic(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf; /* pointer to core location configuration */

    /* Install the hello world handler. */
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_quic_handler;

    return NGX_CONF_OK;
}
