// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ngx_quic_simple_server_stream.h"
#include "ngx_quic_simple_server_session.h"
#include "net/http/http_response_headers.h"
#include "ngx_http_quic_adaptor.h"

#include "net/http/http_request_headers.h"

#include <list>
#include <utility>

#include "net/quic/core/quic_spdy_stream.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_map_util.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/spdy/core/spdy_protocol.h"
#include "net/tools/quic/quic_http_response_cache.h"

namespace net {
const char* const kForbiddenHttpHeaderFields[] = {
    ":authority",
    ":method",
    ":path",
    ":scheme",
    ":version",
    "method",
    "scheme",
    "version",
};

const char* const QuicSimpleServerStream::kErrorResponseBody = "<h1> bad</h1>";
const char* const QuicSimpleServerStream::kNotFoundResponseBody = "lance found";

static bool ConvertSpdyHeaderToHttpRequest(const SpdyHeaderBlock& spdy_headers,
                                    HttpRequestHeaders* request_headers);
static void AddSpdyHeader(const std::string& name,
                   const std::string& value,
                   SpdyHeaderBlock* headers);
static void CreateSpdyHeadersFromHttpResponse(
    const HttpResponseHeaders& response_headers,
    SpdyHeaderBlock* headers);

QuicSimpleServerStream::QuicSimpleServerStream(
    QuicStreamId id,
    QuicSpdySession* session,
    QuicHttpResponseCache* response_cache, void *ngx_connection, void *ngx_addr_conf)
    : QuicSpdyServerStreamBase(id, session),
      content_length_(-1),
      response_cache_(response_cache),
	  ngx_connection_(ngx_connection),
	  ngx_addr_conf_(ngx_addr_conf) {
	  stream_ngx_connection_ = ngx_connection;
	  QUIC_DVLOG(1) << "QuicSimpleServerStream::QuicSimpleServerStream stream_ngx_connection: " << stream_ngx_connection_ << " ngx_addr_conf:" << ngx_addr_conf_;}

QuicSimpleServerStream::QuicSimpleServerStream(
    QuicStreamId id,
    QuicSpdySession* session,
    QuicHttpResponseCache* response_cache)
    : QuicSpdyServerStreamBase(id, session),
      content_length_(-1),
      response_cache_(response_cache){}

QuicSimpleServerStream::~QuicSimpleServerStream() {}

void QuicSimpleServerStream::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length_,
                                         &request_headers_)) {
    QUIC_DVLOG(1) << "Invalid headers";
    SendErrorResponse();
  }
  ConsumeHeaderList();
}

void QuicSimpleServerStream::OnTrailingHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QUIC_BUG << "Server does not support receiving Trailers.";
  SendErrorResponse();
}

void QuicSimpleServerStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    QUIC_DVLOG(1) << "Stream " << id() << " processed " << iov.iov_len
                  << " bytes.";
    body_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    if (content_length_ >= 0 &&
        body_.size() > static_cast<uint64_t>(content_length_)) {
      QUIC_DVLOG(1) << "Body size (" << body_.size() << ") > content length ("
                    << content_length_ << ").";
      SendErrorResponse();
      return;
    }
    MarkConsumed(iov.iov_len);
  }
  if (!sequencer()->IsClosed()) {
    sequencer()->SetUnblocked();
    return;
  }

  // If the sequencer is closed, then all the body, including the fin, has been
  // consumed.
  OnFinRead();

  if (write_side_closed() || fin_buffered()) {
    return;
  }

  SendToNginx();
}

void QuicSimpleServerStream::PushResponse(
    SpdyHeaderBlock push_request_headers) {
  if (id() % 2 != 0) {
    QUIC_BUG << "Client initiated stream shouldn't be used as promised stream.";
    return;
  }

  // Change the stream state to emulate a client request.
  request_headers_ = std::move(push_request_headers);
  content_length_ = 0;
  QUIC_DVLOG(1) << "Stream " << id()
                << " ready to receive server push response.";

  // Set as if stream decompresed the headers and received fin.
  QuicSpdyStream::OnInitialHeadersComplete(/*fin=*/true, 0, QuicHeaderList());
}

void QuicSimpleServerStream::SendResponse() {
  if (request_headers_.empty()) {
    QUIC_DVLOG(1) << "Request headers empty.";
    SendErrorResponse();
    return;
  }

  if (content_length_ > 0 &&
      static_cast<uint64_t>(content_length_) != body_.size()) {
    QUIC_DVLOG(1) << "Content length (" << content_length_ << ") != body size ("
                  << body_.size() << ").";
    SendErrorResponse();
    return;
  }

  if (!QuicContainsKey(request_headers_, ":authority") ||
      !QuicContainsKey(request_headers_, ":path")) {
    QUIC_DVLOG(1) << "Request headers do not contain :authority or :path.";
    SendErrorResponse();
    return;
  }

  // Find response in cache. If not found, send error response.
  const QuicHttpResponseCache::Response* response = nullptr;
  auto authority = request_headers_.find(":authority");
  auto path = request_headers_.find(":path");
  if (authority != request_headers_.end() && path != request_headers_.end()) {
    response = response_cache_->GetResponse(authority->second, path->second);
  }
  if (response == nullptr) {
    QUIC_DVLOG(1) << "Response not found in cache.";
    SendNotFoundResponse();
    return;
  }

  if (response->response_type() == QuicHttpResponseCache::CLOSE_CONNECTION) {
    QUIC_DVLOG(1) << "Special response: closing connection.";
    CloseConnectionWithDetails(QUIC_NO_ERROR, "Toy server forcing close");
    return;
  }

  if (response->response_type() == QuicHttpResponseCache::IGNORE_REQUEST) {
    QUIC_DVLOG(1) << "Special response: ignoring request.";
    return;
  }

  // Examing response status, if it was not pure integer as typical h2
  // response status, send error response. Notice that
  // QuicHttpResponseCache push urls are strictly authority + path only,
  // scheme is not included (see |QuicHttpResponseCache::GetKey()|).
  std::string request_url = request_headers_[":authority"].as_string() +
                       request_headers_[":path"].as_string();
  int response_code;
  const SpdyHeaderBlock& response_headers = response->headers();
  if (!ParseHeaderStatusCode(response_headers, &response_code)) {
    auto status = response_headers.find(":status");
    if (status == response_headers.end()) {
      QUIC_LOG(WARNING)
          << ":status not present in response from cache for request "
          << request_url;
    } else {
      QUIC_LOG(WARNING) << "Illegal (non-integer) response :status from cache: "
                        << status->second << " for request " << request_url;
    }
    SendErrorResponse();
    return;
  }

  if (id() % 2 == 0) {
    // A server initiated stream is only used for a server push response,
    // and only 200 and 30X response codes are supported for server push.
    // This behavior mirrors the HTTP/2 implementation.
    bool is_redirection = response_code / 100 == 3;
    if (response_code != 200 && !is_redirection) {
      QUIC_LOG(WARNING) << "Response to server push request " << request_url
                        << " result in response code " << response_code;
      Reset(QUIC_STREAM_CANCELLED);
      return;
    }
  }
  std::list<QuicHttpResponseCache::ServerPushInfo> resources =
      response_cache_->GetServerPushResources(request_url);
  QUIC_DVLOG(1) << "Stream " << id() << " found " << resources.size()
                << " push resources.";

  if (!resources.empty()) {
    QuicSimpleServerSession* session =
        static_cast<QuicSimpleServerSession*>(spdy_session());
    session->PromisePushResources(request_url, resources, id(),
                                  request_headers_);
  }

  QUIC_DVLOG(1) << "Stream " << id() << " sending response.";
  SendHeadersAndBodyAndTrailers(response->headers().Clone(), response->body(),
                                response->trailers().Clone());
}

void QuicSimpleServerStream::SendNotFoundResponse() {
  QUIC_DVLOG(1) << "Stream " << id() << " sending not found response.";
  SpdyHeaderBlock headers;
  headers[":status"] = "404";
  headers["content-length"] =
      QuicTextUtils::Uint64ToString(strlen(kNotFoundResponseBody));
  SendHeadersAndBody(std::move(headers), kNotFoundResponseBody);
}

void QuicSimpleServerStream::SendErrorResponse() {
  QUIC_DVLOG(1) << "Stream " << id() << " sending error response.";
  SpdyHeaderBlock headers;
  headers[":status"] = "500"; headers["content-length"] =
      QuicTextUtils::Uint64ToString(strlen(kErrorResponseBody));
  SendHeadersAndBody(std::move(headers), kErrorResponseBody);
}

void QuicSimpleServerStream::SendHeadersAndBody(
    SpdyHeaderBlock response_headers,
    QuicStringPiece body) {
  SendHeadersAndBodyAndTrailers(std::move(response_headers), body,
                                SpdyHeaderBlock());
}

void QuicSimpleServerStream::SendHeadersAndBodyAndTrailers(
    SpdyHeaderBlock response_headers,
    QuicStringPiece body,
    SpdyHeaderBlock response_trailers) {
  // Send the headers, with a FIN if there's nothing else to send.
  bool send_fin = (body.empty() && response_trailers.empty());
  QUIC_DLOG(INFO) << "Stream " << id() << " writing headers (fin = " << send_fin
                  << ") : " << response_headers.DebugString();
  WriteHeaders(std::move(response_headers), send_fin, nullptr);
  if (send_fin) {
    // Nothing else to send.
    return;
  }

  // Send the body, with a FIN if there's no trailers to send.
  send_fin = response_trailers.empty();
  QUIC_DLOG(INFO) << "Stream " << id() << " writing body (fin = " << send_fin
                  << ") with size: " << body.size();
  if (!body.empty() || send_fin) {
    WriteOrBufferData(body, send_fin, nullptr);
  }
  if (send_fin) {
    // Nothing else to send.
    return;
  }

  // Send the trailers. A FIN is always sent with trailers.
  QUIC_DLOG(INFO) << "Stream " << id() << " writing trailers (fin = true): "
                  << response_trailers.DebugString();
  WriteTrailers(std::move(response_trailers), nullptr);
}

void QuicSimpleServerStream::OnNginxDataAvailable() {
  SendResponse();
}

void QuicSimpleServerStream::OnNginxHeaderAvailable(const std::string &header, bool fin)
{
    //SendErrorResponse();
	//HeadersToRaw(const_cast<std::string *> (&header));
	scoped_refptr<HttpResponseHeaders> request_headers = new HttpResponseHeaders(header);	
	SpdyHeaderBlock spdy_headers;
	CreateSpdyHeadersFromHttpResponse(*request_headers, &spdy_headers);
	WriteHeaders(std::move(spdy_headers), fin, nullptr);
}

void QuicSimpleServerStream::OnNginxBodyAvailable(const std::string &body, bool fin)
{
    
	QUIC_DLOG(INFO) << "quic body available:" << body << "size:" << body.size() << "fin:" << fin;
	//HeadersToRaw(const_cast<std::string *> (&body));
	WriteOrBufferData(body, fin, nullptr);
}

void QuicSimpleServerStream::SendToNginx() {
	std::string request_line = request_headers_[":method"].as_string() + " " + request_headers_[":path"].as_string() + " HTTP/1.1";

	QUIC_DLOG(INFO) << "quic to http request line:" << request_line;
	std::string host = request_headers_[":authority"].as_string();
	std::string path = request_headers_[":path"].as_string();

	// copy test
	//SpdyHeaderBlock request_headers_ = request_headers_;
	HttpRequestHeaders http_request_headers;
	bool rt = ConvertSpdyHeaderToHttpRequest(request_headers_ ,&http_request_headers);
	if (!rt) {
		QUIC_DLOG(INFO) << "fail to convert spdy header to http request header";
		return;
	}

	http_request_headers.SetHeader("host", request_headers_[":authority"].as_string());
	http_request_headers.RemoveHeader("authority");
	http_request_headers.RemoveHeader("method");
	http_request_headers.RemoveHeader("path");
	http_request_headers.RemoveHeader("scheme");

	std::string request_headers = http_request_headers.ToString();
	QUIC_DLOG(INFO) << "quic headers as http string:" << request_headers;
	QUIC_DLOG(INFO) << "QuicSimpleServerStream::SendToNginx, stream_ngx_connection: " << stream_ngx_connection_;

	std::string http_request = request_line + "\r\n" + request_headers;
	ngx_http_quic_send_to_nginx(this , http_request.c_str(), http_request.size(), body_.c_str(), body_.size());
	//lance_debug for test
	//ngx_http_quic_send_to_nginx_test(this , host.c_str(), host.size(), path.c_str(), path.size(), body_.c_str(), body_.size());
}


void QuicSimpleServerStream::SetQuicNgxConnection(void *ngx_connection) {
	QUIC_DLOG(INFO) << "QuicSimpleServerStream::SetQuicNgxConnection " << ngx_connection;
	stream_ngx_connection_ = ngx_connection;
}

void* QuicSimpleServerStream::GetQuicNgxConnection() {
	QUIC_DLOG(INFO) << "QuicSimpleServerStream::GetQuicNgxConnection, stream_ngx_connection: " << stream_ngx_connection_;
	//return ngx_connection_;
	return stream_ngx_connection_;
}

void QuicSimpleServerStream::SetQuicNgxAddrConf(void *ngx_addr_conf) {
	QUIC_DLOG(INFO) << "QuicSimpleServerStream::SetQuicNgxAddrConf " << ngx_addr_conf;
	ngx_addr_conf_ = ngx_addr_conf;
}

void* QuicSimpleServerStream::GetQuicNgxAddrConf() {
	QUIC_DLOG(INFO) << "QuicSimpleServerStream::GetQuicNgxAddrConf " << ngx_addr_conf_;
	return ngx_addr_conf_;
}

void CreateSpdyHeadersFromHttpResponse(
    const HttpResponseHeaders& response_headers,
    SpdyHeaderBlock* headers) {
// debug
//  return;
  const std::string status_line = response_headers.GetStatusLine();
  std::string::const_iterator after_version =
      std::find(status_line.begin(), status_line.end(), ' ');
  // Get status code only.
  std::string::const_iterator after_status =
      std::find(after_version + 1, status_line.end(), ' ');
  (*headers)[":status"] = std::string(after_version + 1, after_status);
  QUIC_DVLOG(1) << "AddSpdyHeader name:";

  size_t iter = 0;
  std::string date_header;
  while (response_headers.EnumerateHeader(&iter, "Date", &date_header)) {
  	QUIC_DVLOG(1) << "AddSpdyHeader Got date header: " <<  date_header;
  }

  iter = 0;
  while (response_headers.EnumerateHeader(&iter, "Server", &date_header)) {
  	QUIC_DVLOG(1) << "AddSpdyHeader Got server header: " <<  date_header;
  }

  iter = 0;
  std::string raw_name, value;
  while (response_headers.EnumerateHeaderLines(&iter, &raw_name, &value)) {
    std::string name = base::ToLowerASCII(raw_name);
	QUIC_DVLOG(1) << "AddSpdyHeader name:" << name << "value:" << value;
    AddSpdyHeader(name, value, headers);
  }
}

void AddSpdyHeader(const std::string& name,
                   const std::string& value,
                   SpdyHeaderBlock* headers) {
  if (headers->find(name) == headers->end()) {
    (*headers)[name] = value;
  } else {
    std::string joint_value = (*headers)[name].as_string();
    joint_value.append(1, '\0');
    joint_value.append(value);
    (*headers)[name] = joint_value;
  }
}


bool ConvertSpdyHeaderToHttpRequest(const SpdyHeaderBlock& spdy_headers,
                                    HttpRequestHeaders* request_headers) {
  CHECK(request_headers);
  request_headers->Clear();

  SpdyHeaderBlock::const_iterator it = spdy_headers.begin();
  while (it != spdy_headers.end()) {
  bool valid_header = true;
	for (size_t i = 0; i < arraysize(kForbiddenHttpHeaderFields); ++i) {
      if (it->first == kForbiddenHttpHeaderFields[i]) {
        valid_header = false;
        break;
      }   
    }   
    if (!valid_header) {
      ++it;
      continue;
    }   

    base::StringPiece key(it->first);
    base::StringPiece value(it->second);

    if (key.size() && key[0] == ':') {
      key = key.substr(1);
    }   

    QUIC_DVLOG(1) << "ConvertSpdyHeaderToHttpRequest key:" << key << "value:" << value;

    request_headers->SetHeader(key, value);
    ++it;
  }

  return true;
}


}  // namespace net
