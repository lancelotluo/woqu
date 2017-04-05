#include "ngx_http_quic_adaptor.h"

#include "base/logging.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/chromium/crypto/proof_source_chromium.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/chromium/quic_chromium_alarm_factory.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/tools/quic/quic_http_response_cache.h"
#include "net/tools/quic/quic_server.h"

using namespace net;
// The port the quic server will listen on.

std::unique_ptr<net::ProofSource> CreateProofSource(
    const base::FilePath& cert_path,
    const base::FilePath& key_path) {
  std::unique_ptr<net::ProofSourceChromium> proof_source(
      new net::ProofSourceChromium());
  CHECK(proof_source->Initialize(cert_path, key_path, base::FilePath()));
  return std::move(proof_source);
}

void *ngx_http_quic_create_dispatcher()
{
/*
	QuicSimpleDispatcher *dispatcher = new QuicSimpleDispatcher(
      config_, &crypto_config_, &version_manager_,
      std::unique_ptr<QuicConnectionHelperInterface>(helper_),
      std::unique_ptr<QuicCryptoServerStream::Helper>(
          new QuicSimpleServerSessionHelper(QuicRandom::GetInstance())),
      std::unique_ptr<QuicAlarmFactory>(alarm_factory_), response_cache_);
    int64_t go_writer,
    int64_t go_quic_dispatcher,
    int64_t go_task_runner,
    QuicCryptoServerConfig* crypto_config) {
*/
  QuicConfig* config = new QuicConfig();
  // Deleted by ~GoQuicDispatcher()
  QuicClock* clock =
      new QuicClock();  // Deleted by scoped ptr of GoQuicConnectionHelper
  QuicRandom* random_generator = QuicRandom::GetInstance();
  
  std::unique_ptr<QuicConnectionHelperInterface> helper(new GoQuicConnectionHelper(clock, random_generator));
  std::unique_ptr<QuicAlarmFactory> alarm_factory(new GoQuicAlarmFactory(clock, go_task_runner));
  std::unique_ptr<QuicCryptoServerStream::Helper> session_helper(new GoQuicSimpleServerSessionHelper(QuicRandom::GetInstance()));
  // XXX: quic_server uses QuicSimpleCryptoServerStreamHelper, 
  // while quic_simple_server uses QuicSimpleServerSessionHelper.
  // Pick one and remove the other later
  
  QuicVersionManager* version_manager = new QuicVersionManager(net::AllSupportedVersions());

  /* Initialize Configs ------------------------------------------------*/

  // If an initial flow control window has not explicitly been set, then use a
  // sensible value for a server: 1 MB for session, 64 KB for each stream.
  const uint32_t kInitialSessionFlowControlWindow = 1 * 1024 * 1024;  // 1 MB
  const uint32_t kInitialStreamFlowControlWindow = 64 * 1024;         // 64 KB
  if (config->GetInitialStreamFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindow);
  }
  if (config->GetInitialSessionFlowControlWindowToSend() ==
      kMinimumFlowControlSendWindow) {
    config->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindow);
  }
  /* Initialize Configs Ends ----------------------------------------*/

  // Deleted by delete_go_quic_dispatcher()
/*
  QuicSimpleDispatcher* dispatcher =
      new GoQuicSimpleDispatcher(*config, crypto_config, version_manager,
          std::move(helper), std::move(session_helper), std::move(alarm_factory), go_quic_dispatcher);

  GoQuicServerPacketWriter* writer = new GoQuicServerPacketWriter(
      go_writer, dispatcher);  // Deleted by scoped ptr of GoQuicDispatcher

  dispatcher->InitializeWithWriter(writer);
*/

	return (reinterpret_cast< void * >(dispatcher));
}

void ngx_http_quic_set_log_level(int level)
{
	logging::SetMinLogLevel(level);
}
