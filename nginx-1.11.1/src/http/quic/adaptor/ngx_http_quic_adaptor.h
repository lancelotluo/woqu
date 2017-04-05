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

void *ngx_http_quic_create_dispatcher();

void ngx_http_quic_set_log_level(int level);



#ifdef __cplusplus
}
#endif
#endif
