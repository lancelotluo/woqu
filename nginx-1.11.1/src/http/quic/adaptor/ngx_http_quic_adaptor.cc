#include "ngx_http_quic_adaptor.h"
extern "C" {
	#include "ngx_http_quic.h"
}
#include "ngx_http_quic_connection_helper.h"
#include "ngx_http_quic_alarm_factory.h"
#include "ngx_quic_simple_server_stream.h"

#include "net/quic/platform/impl/quic_chromium_clock.h"

#include "base/at_exit.h"
#include "base/command_line.h"
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
static base::AtExitManager* exit_manager;
//g_disable_managers = true;	

std::unique_ptr<net::ProofSource> CreateProofSource(
    const base::FilePath& cert_path,
    const base::FilePath& key_path) {
  	std::unique_ptr<net::ProofSourceChromium> proof_source(
      new net::ProofSourceChromium());
  	CHECK(proof_source->Initialize(cert_path, key_path, base::FilePath()));
  	return std::move(proof_source);
}

QuicSimpleDispatcher* ngx_http_quic_create_dispatcher(int fd, ngx_http_quic_conf_t *conf)
{
	const char kSourceAddressTokenSecret[] = "secret";

	int fake_argc = 2 ;
	char arg0[] = "-h" ;
	char arg1[] = "help" ;
	char **fake_argv = new char *[fake_argc]{ arg0 , arg1 } ;

	base::CommandLine::Init(fake_argc, fake_argv);
	//ngx_http_quic_set_log_level(conf->quic_log_level);
	ngx_http_quic_set_log_level(-1);
	exit_manager = new base::AtExitManager;
    //exit_manager->DisableAllAtExitManagers();
    QuicConfig* config = new QuicConfig();

	QuicChromiumClock* clock = new QuicChromiumClock();  // Deleted by scoped ptr of    QuicConnectionHelper
	QuicRandom* random_generator = QuicRandom::GetInstance();
	if (random_generator == nullptr) {
		QUIC_DVLOG(1) << "lance_debug get null random";	
		return nullptr;
	}

	QUIC_DVLOG(1) << "lance_debug create quic dispatcher, cert:"<<conf->certificate << "key:" << conf->certificate_key;	
  
	std::unique_ptr<QuicConnectionHelperInterface> helper(new QuicChromiumConnectionHelper(clock, QuicRandom::GetInstance()));
	std::unique_ptr<QuicAlarmFactory> alarm_factory(new QuicEpollAlarmFactory());
  // XXX: quic_server uses QuicSimpleCryptoServerStreamHelper, 
  // while quic_simple_server uses QuicSimpleServerSessionHelper.
  // Pick one and remove the other later

	//std::unique_ptr<ProofSource> proof_source = CreateProofSource(base::FilePath("./cert/quic.cert"), base::FilePath("./cert/quic.key.pkcs8"));
	std::unique_ptr<ProofSource> proof_source = CreateProofSource(base::FilePath(reinterpret_cast<char*>(conf->certificate)), base::FilePath(reinterpret_cast<char*>(conf->certificate_key)));
	QuicCryptoServerConfig *crypto_config = new QuicCryptoServerConfig(kSourceAddressTokenSecret, random_generator,
			  std::move(proof_source));
	//net::EphemeralKeySource* keySource = new GoEphemeralKeySource();
	//crypto_config->SetEphemeralKeySource(keySource); 
	crypto_config->set_replay_protection(false); 
	net::QuicCryptoServerConfig::ConfigOptions *crypto_scfg = new net::QuicCryptoServerConfig::ConfigOptions();
	std::unique_ptr<CryptoHandshakeMessage> scfg(crypto_config->AddDefaultConfig( 
					helper->GetRandomGenerator(), clock, *crypto_scfg));
					//QuicRandom::GetInstance(), clock, *crypto_scfg));
  
	QuicVersionManager* version_manager = new QuicVersionManager(net::AllSupportedVersions());
	QuicHttpResponseCache* response_cache = new QuicHttpResponseCache();
	response_cache->InitializeFromDirectory("./html/quic/html");
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

	QuicSimpleDispatcher* dispatcher =
    new QuicSimpleDispatcher(*config, crypto_config, version_manager,
          std::move(helper), std::unique_ptr<QuicCryptoServerStream::Helper>(new QuicSimpleServerSessionHelper(QuicRandom::GetInstance())), std::move(alarm_factory), response_cache);

	QuicDefaultPacketWriter* writer = new QuicDefaultPacketWriter(fd);

	dispatcher->InitializeWithWriter(writer);

	QUIC_DVLOG(1) << "lance_debug return  quic dispatcher" << dispatcher;

	return dispatcher;
}

void ngx_http_quic_set_log_level(int level)
{
	logging::LoggingSettings settings;
	settings.logging_dest = logging::LOG_TO_ALL;
	settings.log_file = "./logs/quic.log";
	logging::InitLogging(settings);
	logging::SetMinLogLevel(level); //work
	//logging::InitLogging("debug2.log", LOG_TO_BOTH_FILE_AND_SYSTEM_DEBUG_LOG,
//				                DONT_LOCK_LOG_FILE, DELETE_OLD_LOG_FILE,
//								DISABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS);
}
/*
int ngx_http_quic_dispatcher_process_packet(void *ngx_connection, void *addr_conf, QuicSimpleDispatcher* dispatcher,
			const char *buffer, size_t length, struct sockaddr *peer_sockaddr, 
			struct sockaddr *local_sockaddr, int fd) {

	QUIC_DVLOG(1) << "lance_debug quic dispatcher process packet" << dispatcher << "packet_len:" << length << "ngx_connection:" << ngx_connection << "ngx_addr_conf:" << addr_conf;	
	
	struct sockaddr_storage *generic_localsock = (struct sockaddr_storage*) local_sockaddr;
	struct sockaddr_storage *generic_peersock = (struct sockaddr_storage*) peer_sockaddr;
	QuicSocketAddress server_address(*generic_localsock);
	QuicSocketAddress client_address(*generic_peersock);

	QuicReceivedPacket packet(
      buffer, length, dispatcher->helper()->GetClock()->Now(),
      false );
	// Do not own the buffer, so will not free buffer in the destructor 

	dispatcher->SetQuicNgxConnection(ngx_connection);
	dispatcher->SetQuicNgxAddrConf(addr_conf);
	return dispatcher->ProcessPacket(server_address, client_address, packet);
}
*/
int ngx_http_quic_dispatcher_process_packet(void *ngx_connection, QuicSimpleDispatcher* dispatcher,
			const char *buffer, size_t length, struct sockaddr *peer_sockaddr, 
			struct sockaddr *local_sockaddr, int fd) {

	QUIC_DVLOG(1) << "lance_debug quic dispatcher process packet" << dispatcher << "packet_len:" << length << "ngx_connection:" << ngx_connection;	
	
	struct sockaddr_storage *generic_localsock = (struct sockaddr_storage*) local_sockaddr;
	struct sockaddr_storage *generic_peersock = (struct sockaddr_storage*) peer_sockaddr;
	QuicSocketAddress server_address(*generic_localsock);
	QuicSocketAddress client_address(*generic_peersock);

	QuicReceivedPacket packet(
      buffer, length, dispatcher->helper()->GetClock()->Now(),
      false /* Do not own the buffer, so will not free buffer in the destructor */);

	dispatcher->SetQuicNgxConnection(ngx_connection);
	return dispatcher->ProcessPacket(server_address, client_address, packet);
}

int ngx_http_quic_send_to_nginx(void *stream, const char *request, int request_len, const char *body, int body_len)
{

	QuicSimpleServerStream *quic_stream = reinterpret_cast< QuicSimpleServerStream * >(stream);
	//void *ngx_addr_conf = quic_stream->GetQuicNgxAddrConf();
	void *ngx_connection = quic_stream->GetQuicNgxConnection();
	if (ngx_connection == nullptr) {
		QUIC_DVLOG(1) << "lance_debug ngx_connection is nullptr";	
		return -1;
	}

	QUIC_DVLOG(1) << "lance_debug quic request:" << request << " len: "<< request_len  << " ngx_connection:" << ngx_connection << "quic_version:" << quic_stream->version() << "quic_connection_id:" << "quic_stream_id:" << quic_stream->id();

    string full_version = "q0"+ std::to_string(quic_stream->version()); 
    string sid = std::to_string(quic_stream->id());

    ngx_quic_stream_info_t nq_info;
    memcpy(&nq_info.quic_version, full_version.c_str(), 4);
    memcpy(&nq_info.stream_id, sid.c_str(), 32);

	return ngx_http_quic_init_http_request(stream, ngx_connection, request, request_len, body, body_len, &nq_info);
	//ngx_http_quic_init_http_request_test(stream, ngx_connection, request, request_len, body, body_len);
	//quic_stream->OnNginxDataAvailable();
}

void ngx_http_quic_send_to_nginx_test(void *stream, const char *host, int64_t host_len, const char *path, int64_t path_len, const char *body, int64_t body_len)
{
	QUIC_DVLOG(1) << "lance_debug quic host:" << host << " len: "<< host_len << " quic path:" << path << " path_len: " << path_len;	

	//ngx_http_quic_run_request(stream, host, host_len, path, path_len, body, body_len);
	QuicSimpleServerStream *quic_stream = reinterpret_cast< QuicSimpleServerStream * >(stream);
	void *ngx_connection = quic_stream->GetQuicNgxConnection();
	if (ngx_connection == nullptr) {
		QUIC_DVLOG(1) << "lance_debug ngx_connection is nullptr";	
		return;
	}

}

void ngx_http_quic_send_to_nginx_test(void *stream)
{
	QUIC_DVLOG(1) << "lance_debug quic_send_to_nginx_test";	
	QuicSimpleServerStream *quic_stream = reinterpret_cast< QuicSimpleServerStream * >(stream);
	quic_stream->OnNginxDataAvailable();
}

int ngx_http_quic_response_body_available(void *stream, unsigned char *buf, const int buf_len, int last_buf)
{
	QUIC_DVLOG(1) << "lance_debug begin to OnNginxBodyAvailable";	
	QuicSimpleServerStream *quic_stream = reinterpret_cast< QuicSimpleServerStream * >(stream);
	string ngx_body = string(reinterpret_cast<char*>(buf), buf_len);
	bool fin = last_buf ? true : false;
	quic_stream->OnNginxBodyAvailable(ngx_body, fin);
	return 0;
}

void ngx_http_quic_response_available(void *stream)
{
	QuicSimpleServerStream *quic_stream = reinterpret_cast< QuicSimpleServerStream * >(stream);
	quic_stream->OnNginxDataAvailable();
}

int ngx_http_quic_response_header_available(void *stream, unsigned char *buf, const int buf_len, int last_buf)
{
	QUIC_DVLOG(1) << "lance_debug begin to OnNginxHeaderAvailable";	
	QuicSimpleServerStream *quic_stream = reinterpret_cast< QuicSimpleServerStream * >(stream);
	string ngx_header = string(reinterpret_cast<char*>(buf), buf_len);
	bool fin = last_buf ? true : false;
	quic_stream->OnNginxHeaderAvailable(ngx_header, fin);
	return 0;
}
