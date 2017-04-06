#ifndef __NGX_HTTP_QUIC_CONNECTION_HELPER_H_
#define __NGX_HTTP_QUIC_CONNECTION_HELPER_H_
#include "net/quic/core/quic_connection.h"
#include "net/quic/platform/api/quic_clock.h"
#include "net/quic/core/quic_simple_buffer_allocator.h"
//#include "go_structs.h"

namespace net {

class QuicRandom;

using QuicStreamBufferAllocator = SimpleBufferAllocator;

class NgxQuicConnectionHelper : public QuicConnectionHelperInterface {
 public:
  NgxQuicConnectionHelper(QuicClock* clock,
                         QuicRandom* random_generator);
  ~NgxQuicConnectionHelper() override;

  // QuicConnectionHelperInterface
  const QuicClock* GetClock() const override;
  QuicRandom* GetRandomGenerator() override;

  QuicBufferAllocator* GetBufferAllocator() override;

 private:

  std::unique_ptr<QuicClock> clock_;
  QuicRandom* random_generator_;
  QuicStreamBufferAllocator buffer_allocator_;

  DISALLOW_COPY_AND_ASSIGN(NgxQuicConnectionHelper);
};

}  // namespace net

#endif  // GO_QUIC_CONNECTION_HELPER_H_
