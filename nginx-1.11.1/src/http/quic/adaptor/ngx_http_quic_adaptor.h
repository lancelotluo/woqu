#ifndef _NGX_HTTP_QUIC_ADAPTOR_INCLUDED_
#define _NGX_HTTP_QUIC_ADAPTOR_INCLUDED_

#ifdef __cplusplus

#include "net/tools/quic/quic_simple_dispatcher.h"
#include "net/tools/quic/quic_simple_server_session_helper.h"

#include "net/quic/core/quic_connection.h"
#include "net/base/ip_endpoint.h"
#include "net/spdy/spdy_header_block.h"

extern "C" {
#endif
/*QuicCryptoServerConfig* ngx_http_quic_init_crypto_config(
    struct GoQuicServerConfig* go_config,
    ProofSourceGoquic* proof_source,
    char* source_address_token_secret,
    size_t source_address_token_secret_len);
*/

struct ngx_quic_dispatcher_s {
	void *proto_quic_dispatcher;
};

typedef struct ngx_quic_dispatcher_s ngx_quic_dispatcher_t;


void *ngx_http_quic_create_dispatcher(int fd);

void ngx_http_quic_set_log_level(int level);
void ngx_http_quic_dispatcher_process_packet(ngx_quic_dispatcher_t* dispatcher, uint8_t* self_address_ip,  size_t self_address_len, uint16_t self_address_port, uint8_t* peer_address_ip, size_t peer_address_len, uint16_t peer_address_port, char* buffer, size_t length);


#ifdef __cplusplus
}
#endif
#endif
