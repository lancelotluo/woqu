#ifndef _NGX_HTTP_QUIC_ADAPTOR_INCLUDED_
#define _NGX_HTTP_QUIC_ADAPTOR_INCLUDED_

#ifdef __cplusplus

#include "ngx_quic_simple_dispatcher.h"
#include "net/tools/quic/quic_simple_server_session_helper.h"

#include "net/quic/core/quic_connection.h"
#include "net/base/ip_endpoint.h"
#include "net/spdy/core/spdy_header_block.h"
#include <string>

using net::QuicSimpleDispatcher;
using std::string;

extern "C" {
#else
#include "ngx_http_quic_module.h"

typedef void QuicSimpleDispatcher;
/*QuicCryptoServerConfig* ngx_http_quic_init_crypto_config(
    struct GoQuicServerConfig* go_config,
    ProofSourceGoquic* proof_source,
    char* source_address_token_secret,
    size_t source_address_token_secret_len);
*/
#endif

struct ngx_http_quic_conf_s {
	const char *certificate;
	const char *certificate_key;
};

typedef struct ngx_http_quic_conf_s ngx_http_quic_conf_t;

QuicSimpleDispatcher *ngx_http_quic_create_dispatcher(int fd, ngx_http_quic_conf_t *conf);

void ngx_http_quic_set_log_level(int level);

void ngx_http_quic_dispatcher_process_packet(void *ngx_http_connection, QuicSimpleDispatcher *dispatcher,
			char *buffer, size_t length, struct sockaddr *peer_sockaddr, 
			struct sockaddr *local_sockaddr, int fd);
void ngx_http_quic_send_quic_to_nginx(void * x, char *host, int64_t host_len, char *path, int64_t path_len, char *body, int64_t body_len);

void ngx_http_quic_send_to_nginx(void *stream, const char *request, int request_len, const char *body, int body_len);
void ngx_http_quic_send_to_nginx_test(void *stream, const char *host, int64_t host_len, const char *path, int64_t path_len, const char *body, int64_t body_len);
void ngx_http_quic_response_availble(void *stream);
int ngx_http_quic_response_header_available(void *stream, const char *buf, const int buf_len);
int ngx_http_quic_response_body_available(void *stream, const char *buf, const int buf_len);
#ifdef __cplusplus
}
#endif
#endif
