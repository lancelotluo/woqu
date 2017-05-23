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

int QuicSimpleDispatcher::GetRstErrorCount(
    QuicRstStreamErrorCode error_code) const {
  auto it = rst_error_map_.find(error_code);
  if (it == rst_error_map_.end()) {
    return 0;
  } else {
    return it->second;
  }
}

void QuicSimpleDispatcher::OnRstStreamReceived(
    const QuicRstStreamFrame& frame) {
  auto it = rst_error_map_.find(frame.error_code);
  if (it == rst_error_map_.end()) {
    rst_error_map_.insert(std::make_pair(frame.error_code, 1));
  } else {
    it->second++;
  }
}

QuicServerSessionBase* QuicSimpleDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const QuicSocketAddress& client_address) {
  // The QuicServerSessionBase takes ownership of |connection| below.
  QUIC_DLOG(INFO)  << "begin to new Connection, helper: " << helper();
  QuicConnection* connection = new QuicConnection(
      connection_id, client_address, helper(), alarm_factory(),
      CreatePerConnectionWriter(),
      /* owns_writer= */ true, Perspective::IS_SERVER, GetSupportedVersions());
  
  QUIC_DLOG(INFO)  << "begin to create QuicSimpleServerSession ngx_connection:" << ngx_connection_;
  QuicServerSessionBase* session = new QuicSimpleServerSession(
      config(), connection, this, session_helper(), crypto_config(),
      compressed_certs_cache(), response_cache_, ngx_connection_, ngx_addr_conf_);
  session->Initialize();
  //lance_debug
  //
  return session;
}

void *QuicSimpleDispatcher::GetQuicNgxAddrConf() {
	return ngx_addr_conf_;
}
/*void *QuicSimpleDispatcher::GetQuicNgxConnection() {
	return ngx_connection_;
}
*/

void QuicSimpleDispatcher::SetQuicNgxAddrConf(void *addr_conf) {
    QUIC_DLOG(INFO) << "lance_debug QuicSimpleDispatcher::SetQuicNgxAddrConf: " << addr_conf;
	ngx_addr_conf_ = addr_conf;
}

/*
void QuicSimpleDispatcher::SetQuicNgxConnection(void *ngx_connection) {
    QUIC_DLOG(INFO) << "lance_debug QuicSimpleDispatcher::SetQuicNgxConnection: " << ngx_connection;
	ngx_connection_ = ngx_connection;
}
*/
}  // namespace net
