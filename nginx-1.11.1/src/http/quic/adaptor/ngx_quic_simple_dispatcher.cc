// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ngx_quic_simple_dispatcher.h"

#include "ngx_quic_simple_server_session.h"

namespace net {

QuicSimpleDispatcher::QuicSimpleDispatcher(
    const QuicConfig& config,
    const QuicCryptoServerConfig* crypto_config,
    QuicVersionManager* version_manager,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory,
    QuicHttpResponseCache* response_cache)
    : QuicDispatcher(config,
                     crypto_config,
                     version_manager,
                     std::move(helper),
                     std::move(session_helper),
                     std::move(alarm_factory)),
      response_cache_(response_cache) {}

QuicSimpleDispatcher::~QuicSimpleDispatcher() {}

QuicServerSessionBase* QuicSimpleDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const QuicSocketAddress& client_address) {
  // The QuicServerSessionBase takes ownership of |connection| below.
  QUIC_DLOG(INFO)  << "begin to new Connection, helper: " << helper();
  QuicConnection* connection = new QuicConnection(
      connection_id, client_address, helper(), alarm_factory(),
      CreatePerConnectionWriter(),
      /* owns_writer= */ true, Perspective::IS_SERVER, GetSupportedVersions());
//lance debug	
  std::string data;
	data.resize(52);
	char *ret = &data[0];
  QuicRandom *rand = connection->random_generator(); 
  QUIC_DLOG(INFO)  << "begin to get randbytes after Connection";
  rand->RandBytes(ret, 12);
  //
  QuicServerSessionBase* session = new QuicSimpleServerSession(
      config(), connection, this, session_helper(), crypto_config(),
      compressed_certs_cache(), response_cache_);
  session->Initialize();
  //lance_debug
  QuicConnectionHelperInterface *test_h = helper();
  QUIC_DLOG(INFO) << "lance_debug helper(): " << test_h;
  /*<< "config(): " << config()
				<< "session_helper(): " << session_helper()
				<< "crypto_config(): " << crypto_config();
				*/
  //
  return session;
}

void *QuicSimpleDispatcher::GetQuicNgxConnection() {
	return ngx_connection_;
}

void QuicSimpleDispatcher::SetQuicNgxConnection(void *ngx_connection) {
	ngx_connection_ = ngx_connection;
}

}  // namespace net
