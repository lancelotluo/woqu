#include "ngx_http_quic_connection_helper.h"

#include "net/quic/core/quic_connection.h"
#include "net/quic/core/crypto/quic_random.h"

namespace net {

NgxQuicConnectionHelper::NgxQuicConnectionHelper(QuicClock* clock,
                                               QuicRandom* random_generator)
    : random_generator_(random_generator) {
  clock_.reset(clock);
}

NgxQuicConnectionHelper::~NgxQuicConnectionHelper() {}

const QuicClock* NgxQuicConnectionHelper::GetClock() const {
  return clock_.get();
}

QuicRandom* NgxQuicConnectionHelper::GetRandomGenerator() {
  return random_generator_;
}

QuicBufferAllocator* NgxQuicConnectionHelper::GetBufferAllocator() {
  return &buffer_allocator_;
}

}  // namespace net
