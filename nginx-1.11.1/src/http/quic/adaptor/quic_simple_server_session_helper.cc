// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic_simple_server_session_helper.h"

namespace net {

QuicSimpleServerSessionHelper::QuicSimpleServerSessionHelper(QuicRandom* random)
    : random_(random) {}

QuicSimpleServerSessionHelper::~QuicSimpleServerSessionHelper() {}

QuicConnectionId QuicSimpleServerSessionHelper::GenerateConnectionIdForReject(
    QuicConnectionId /*connection_id*/) const {
  //return random_->RandUint64(); lc debug
	//random_;
	uint64_t random = 
	    (((uint64_t) rand() <<  0) & 0x00000000FFFFFFFFull) | 
		  (((uint64_t) rand() << 32) & 0xFFFFFFFF00000000ull);
	return random;
}

bool QuicSimpleServerSessionHelper::CanAcceptClientHello(
    const CryptoHandshakeMessage& message,
    const QuicSocketAddress& self_address,
    std::string* error_details) const {
  return true;
}
void QuicSimpleServerSessionHelper::MockRandom(){
	random_->RandUint64();
}

}  // namespace net
