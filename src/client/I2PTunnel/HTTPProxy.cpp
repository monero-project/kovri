/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#include "HTTPProxy.h"

#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>

#include <atomic>
#include <cassert>
#include <cstring>
#include <string>

#include "I2PTunnel.h"
#include "Identity.h"
#include "Streaming.h"
#include "client/ClientContext.h"
#include "client/Destination.h"
#include "util/HTTP.h"
#include "util/I2PEndian.h"

namespace i2p {
namespace proxy {

static const size_t HTTP_BUFFER_SIZE = 8192;

class HTTPProxyHandler
    : public i2p::client::I2PServiceHandler,
      public std::enable_shared_from_this<HTTPProxyHandler> {
 private:
  enum state {
    GET_METHOD,
    GET_HOSTNAME,
    GET_HTTPV,
    GET_HTTPVNL,  // TODO(unassigned): fallback to finding Host header if needed
    DONE
  };

  void EnterState(
      state nstate);

  bool HandleData(
      uint8_t* http_buff,
      std::size_t len);

  void HandleSockRecv(
      const boost::system::error_code& ecode,
      std::size_t bytes_transfered);

  void Terminate();
  void AsyncSockRead();
  void HTTPRequestFailed(/*std::string message*/);
  void ExtractRequest();
  bool ValidateHTTPRequest();
  void HandleJumpServices();

  bool CreateHTTPRequest(
      uint8_t *http_buff,
      std::size_t len);

  void SentHTTPFailed(
      const boost::system::error_code& ecode);

  void HandleStreamRequestComplete(
      std::shared_ptr<i2p::stream::Stream> stream);

  uint8_t m_http_buff[HTTP_BUFFER_SIZE];
  std::shared_ptr<boost::asio::ip::tcp::socket> m_sock;
  std::string m_request,  // Data left to be sent
              m_url,      // URL
              m_method,   // Method
              m_version,  // HTTP version
              m_address,  // Address
              m_path;     // Path
  int m_port;             // Port
  state m_state;          // Parsing state

 public:
  HTTPProxyHandler(
      HTTPProxyServer* parent,
      std::shared_ptr<boost::asio::ip::tcp::socket> sock)
      : I2PServiceHandler(parent),
        m_sock(sock) {
          EnterState(GET_METHOD);
        }
  ~HTTPProxyHandler() { Terminate(); }

  void Handle() { AsyncSockRead(); }
};

void HTTPProxyHandler::AsyncSockRead() {
  LogPrint(eLogDebug, "HTTPProxyHandler: async sock read");
  if (m_sock) {
    m_sock->async_receive(
        boost::asio::buffer(
          m_http_buff,
          HTTP_BUFFER_SIZE),
        std::bind(
          &HTTPProxyHandler::HandleSockRecv,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
  } else {
    LogPrint(eLogError, "HTTPProxyHandler: no socket for read");
  }
}

void HTTPProxyHandler::Terminate() {
  if (Kill()) return;
  if (m_sock) {
    LogPrint(eLogDebug, "HTTPProxyHandler: terminating");
    m_sock->close();
    m_sock = nullptr;
  }
  Done(shared_from_this());
}

/* All hope is lost beyond this point */
// TODO(anonimal): handle this appropriately
void HTTPProxyHandler::HTTPRequestFailed(
    /*HTTPProxyHandler::errTypes error*/) {
  static std::string response =
    "HTTP/1.0 500 Internal Server Error\r\n"
    "Content-type: text/html\r\n"
    "Content-length: 0\r\n";
  boost::asio::async_write(
      *m_sock,
      boost::asio::buffer(
        response,
        response.size()),
      std::bind(
        &HTTPProxyHandler::SentHTTPFailed,
        shared_from_this(),
        std::placeholders::_1));
}

void HTTPProxyHandler::EnterState(
    HTTPProxyHandler::state nstate) {
  m_state = nstate;
}

void HTTPProxyHandler::ExtractRequest() {
  LogPrint(eLogDebug,
      "HTTPProxyHandler: method is: ", m_method,
      ", request is: ", m_url);
  std::string server = "";
  std::string port = "80";
  boost::regex rHTTP("http://(.*?)(:(\\d+))?(/.*)");
  boost::smatch m;
  std::string path;
  if (boost::regex_search(m_url, m, rHTTP, boost::match_extra)) {
    server = m[1].str();
    if (m[2].str() != "")
      port = m[3].str();
    path = m[4].str();
  }
  LogPrint(eLogDebug,
      "HTTPProxyHandler: server is: ", server,
      ", port is: ", port,
      ", path is: ", path);
  m_address = server;
  m_port = boost::lexical_cast<int>(port);
  m_path = path;
}

bool HTTPProxyHandler::ValidateHTTPRequest() {
  if (m_version != "HTTP/1.0" && m_version != "HTTP/1.1") {
    LogPrint(eLogError, "HTTPProxyHandler: unsupported version: ", m_version);
    HTTPRequestFailed();  // TODO(anonimal): send right stuff
    return false;
  }
  return true;
}

void HTTPProxyHandler::HandleJumpServices() {
  static const char* helpermark1 = "?i2paddresshelper=";
  static const char* helpermark2 = "&i2paddresshelper=";
  size_t addressHelperPos1 = m_path.rfind(helpermark1);
  size_t addressHelperPos2 = m_path.rfind(helpermark2);
  size_t addressHelperPos;
  if (addressHelperPos1 == std::string::npos) {
    if (addressHelperPos2 == std::string::npos)
      return;  // Not a jump service
    else
      addressHelperPos = addressHelperPos2;
  } else {
    if (addressHelperPos2 == std::string::npos)
      addressHelperPos = addressHelperPos1;
    else if (addressHelperPos1 > addressHelperPos2)
      addressHelperPos = addressHelperPos1;
    else
      addressHelperPos = addressHelperPos2;
  }
  auto base64 = m_path.substr(addressHelperPos + strlen(helpermark1));
  // Some of the symbols may be urlencoded
  i2p::util::http::URI uri;
  base64 = uri.Decode(base64);
  LogPrint(eLogDebug,
      "HTTPProxyHandler: jump service for ", m_address,
      " found at ", base64, ". Inserting to address book");
  // TODO(anonimal): this is very dangerous and broken.
  // We should ask the user before doing anything.
  // See http://pastethis.i2p/raw/pn5fL4YNJL7OSWj3Sc6N/
  // We could redirect the user again to avoid dirtiness in the browser
  i2p::client::context.GetAddressBook().InsertAddress(
      m_address,
      base64);
  m_path.erase(addressHelperPos);
}

bool HTTPProxyHandler::CreateHTTPRequest(
    uint8_t *http_buff,
    std::size_t len) {
  ExtractRequest();  // TODO(anonimal): parse earlier
  if (!ValidateHTTPRequest())
    return false;
  HandleJumpServices();
  m_request = m_method;
  m_request.push_back(' ');
  m_request += m_path;
  m_request.push_back(' ');
  m_request += m_version;
  m_request.push_back('\r');
  m_request.push_back('\n');
  m_request.append("Connection: close\r\n");
  m_request.append(reinterpret_cast<const char *>(http_buff), len);
  return true;
}

bool HTTPProxyHandler::HandleData(
    uint8_t *http_buff,
    std::size_t len) {
  // This should always be called with at least a byte left to parse
  assert(len);
  while (len > 0) {
    // TODO(anonimal): fallback to finding Host: header if needed
    switch (m_state) {
      case GET_METHOD:
        switch (*http_buff) {
          case ' ':
            EnterState(GET_HOSTNAME);
            break;
          default:
            m_method.push_back(*http_buff);
            break;
        }
      break;
      case GET_HOSTNAME:
        switch (*http_buff) {
          case ' ':
            EnterState(GET_HTTPV);
            break;
          default:
            m_url.push_back(*http_buff);
            break;
        }
      break;
      case GET_HTTPV:
        switch (*http_buff) {
          case '\r':
            EnterState(GET_HTTPVNL);
            break;
          default:
            m_version.push_back(*http_buff);
            break;
        }
      break;
      case GET_HTTPVNL:
        switch (*http_buff) {
          case '\n':
            EnterState(DONE);
            break;
          default:
            LogPrint(eLogError,
                "HTTPProxyHandler: rejected invalid request ending with: ",
                static_cast<int>(*http_buff));
            HTTPRequestFailed();  // TODO(anonimal): add correct code
            return false;
        }
      break;
      default:
        LogPrint(eLogError, "HTTPProxyHandler: invalid state: ", m_state);
        HTTPRequestFailed();  // TODO(anonimal): add correct code 500
        return false;
    }
    http_buff++;
    len--;
    if (m_state == DONE)
      return CreateHTTPRequest(http_buff, len);
  }
  return true;
}

void HTTPProxyHandler::HandleSockRecv(
    const boost::system::error_code& ecode,
    std::size_t len) {
  LogPrint(eLogDebug, "HTTPProxyHandler: sock recv: ", len);
  if (ecode) {
    LogPrint(eLogWarning, "HTTPProxyHandler: sock recv got error: ", ecode);
          Terminate();
    return;
  }
  if (HandleData(m_http_buff, len)) {
    if (m_state == DONE) {
      LogPrint(eLogInfo, "HTTPProxyHandler: proxy requested: ", m_url);
      GetOwner()->CreateStream(
          std::bind(
            &HTTPProxyHandler::HandleStreamRequestComplete,
            shared_from_this(),
            std::placeholders::_1),
          m_address,
          m_port);
    } else {
      AsyncSockRead();
    }
  }
}

void HTTPProxyHandler::SentHTTPFailed(
    const boost::system::error_code& ecode) {
  if (!ecode) {
    Terminate();
  } else {
    LogPrint(eLogError,
        "HTTPProxyHandler: closing socket after sending failure: ",
        ecode.message());
    Terminate();
  }
}

void HTTPProxyHandler::HandleStreamRequestComplete(
    std::shared_ptr<i2p::stream::Stream> stream) {
  if (stream) {
    if (Kill())
      return;
    LogPrint(eLogInfo, "HTTPProxyHandler: new I2PTunnel connection");
    auto connection =
      std::make_shared<i2p::client::I2PTunnelConnection>(
          GetOwner(),
          m_sock,
          stream);
    GetOwner()->AddHandler(connection);
    connection->I2PConnect(
        reinterpret_cast<const uint8_t*>(m_request.data()),
        m_request.size());
    Done(shared_from_this());
  } else {
    LogPrint(eLogError,
        "HTTPProxyHandler: issue when creating the stream,"
        "check the previous warnings for details");
    // TODO(anonimal): Send correct error message host unreachable
    HTTPRequestFailed();
  }
}

HTTPProxyServer::HTTPProxyServer(
    const std::string& name,
    const std::string& address,
    int port,
    std::shared_ptr<i2p::client::ClientDestination> localDestination)
    : TCPIPAcceptor(
          address,
          port,
          localDestination ? localDestination :
                             i2p::client::context.GetSharedLocalDestination()),
      m_Name(name) {}

std::shared_ptr<i2p::client::I2PServiceHandler> HTTPProxyServer::CreateHandler(
    std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
  return std::make_shared<HTTPProxyHandler> (this, socket);
}

}  // namespace proxy
}  // namespace i2p
