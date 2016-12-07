/**                                                                                           //
 * Copyright (c) 2013-2016, The Kovri I2P Router Project                                      //
 *                                                                                            //
 * All rights reserved.                                                                       //
 *                                                                                            //
 * Redistribution and use in source and binary forms, with or without modification, are       //
 * permitted provided that the following conditions are met:                                  //
 *                                                                                            //
 * 1. Redistributions of source code must retain the above copyright notice, this list of     //
 *    conditions and the following disclaimer.                                                //
 *                                                                                            //
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list     //
 *    of conditions and the following disclaimer in the documentation and/or other            //
 *    materials provided with the distribution.                                               //
 *                                                                                            //
 * 3. Neither the name of the copyright holder nor the names of its contributors may be       //
 *    used to endorse or promote products derived from this software without specific         //
 *    prior written permission.                                                               //
 *                                                                                            //
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY        //
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF    //
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL     //
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,       //
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,               //
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    //
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,          //
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF    //
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               //
 *                                                                                            //
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#include "client/proxy/http.h"

#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string/regex.hpp>
#include <atomic>
#include <utility>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <map>

#include "client/api/streaming.h"
#include "client/context.h"
#include <boost/foreach.hpp>
#include "core/router/identity.h"
#include "client/destination.h"
#include "client/tunnel.h"
#include "client/util/http.h"


#include "core/util/i2p_endian.h"
namespace kovri {
namespace client {

HTTPProxyServerService::HTTPProxyServerService(
    const std::string& name,
    const std::string& address,
    std::uint16_t port,
    std::shared_ptr<kovri::client::ClientDestination> local_destination)
    : TCPIPAcceptor(
          address,
          port,
          local_destination ?
            local_destination :
            kovri::client::context.GetSharedLocalDestination()),
      m_Name(name) {}

std::shared_ptr<kovri::client::I2PServiceHandler>
  HTTPProxyServerService::CreateHandler(
    std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
  return std::make_shared<HTTPProxyHandler>(this, socket);
}

void HTTPProxyHandler::AsyncSockRead() {
  boost::system::error_code error;
  LogPrint(eLogDebug, "HTTPProxyHandler: async sock read");
  //  but there's also use cases where you are providing an inproxy service for others
  //   00:27 < zzz2> for a full threat model including "slowloris" attacks, you need to 
  //   enforce max header lines, max header line length, and a total header timeout
  //  00:27 < zzz2> (in addition to the typical read timeout)
  if (m_Socket) {
    // Read the response headers, which are terminated by a blank line.
    boost::asio::read_until(m_Socket, m_Buffer, "\r\n\r\n",error);
    if (error == boost::asio::error::eof) {
      LogPrint(eLogError, "HTTPProxyHandler: error reading socket");
      Terminate();
      return;
    }
  } else {
    LogPrint(eLogError, "HTTPProxyHandler: no socket for read");
  }
  HandleSockRecv();
}
 
void HTTPProxyHandler::HandleSockRecv() {
  LogPrint(eLogDebug, "HTTPProxyHandler: sock recv: ", m_Buffer.size());
  boost::asio::streambuf::const_buffers_type bufs = m_Buffer.data();
  std::string headerData(boost::asio::buffers_begin(bufs), 
      boost::asio::buffers_begin(bufs) + m_Buffer.size());
  if (m_Protocol.HandleData(headerData )) {
      if (m_Protocol.CreateHTTPRequest()) {
      LogPrint(eLogInfo, "HTTPProxyHandler: proxy requested: ",
          m_Protocol.m_URL);
      GetOwner()->CreateStream(
          std::bind(
              &HTTPProxyHandler::HandleStreamRequestComplete,
              shared_from_this(),
              std::placeholders::_1),
          m_Protocol.m_Address,
          m_Protocol.m_Port);
      }
  } else {
    HTTPRequestFailed(HTTPResponse(HTTPProtocol::status_t::bad_request));
  }
}

bool HTTPProtocol::HandleData(
    std::string & bufString
    ) {
  std::vector<std::string> HeaderBody;
  std::vector<std::string> tokens;
  // get header info
  if (boost::algorithm::split_regex(HeaderBody, bufString,
        boost::regex("\r\n\r\n")).size() != HEADERBODY_LEN)
    return false;
  if (boost::algorithm::split_regex(tokens, HeaderBody[0],
        boost::regex("\r\n")).size() < REQUESTLINE_HEADERS_MIN)
    return false;
  m_RequestLine = tokens[0];
  // requestline
  std::vector<std::string> tokensRequest;
  boost::split(tokensRequest, m_RequestLine, boost::is_any_of(" \t"));
  if (tokensRequest.size() == 3) {
    m_Method = tokensRequest[0];
    m_URL = tokensRequest[1];
    m_Version = tokensRequest[2];
  } else {
    return false;
  }
  // headersline
  m_Headers = tokens;
  // remove start line
  m_Headers.erase(m_Headers.begin());
  // body line
  return true;
}

void HTTPProxyHandler::HandleStreamRequestComplete(
    std::shared_ptr<kovri::client::Stream> stream) {
  if (stream) {
    if (Kill())
      return;
    LogPrint(eLogInfo, "HTTPProxyHandler: new I2PTunnel connection");
    auto connection =
      std::make_shared<kovri::client::I2PTunnelConnection>(
          GetOwner(),
          m_Socket,
          stream);
    GetOwner()->AddHandler(connection);
    connection->I2PConnectUnbuffered(m_Protocol.m_Request, m_Socket);
    Done(shared_from_this());
  } else {
    LogPrint(eLogError,
        "HTTPProxyHandler: issue when creating the stream,"
        "check the previous warnings for details");
    HTTPRequestFailed(HTTPResponse(HTTPProtocol::status_t::not_found));
  }
}
/// @brief all this to change the useragent
/// Reset/scrub User-Agent
/// @param len length of string
bool HTTPProtocol::CreateHTTPRequest() {
  if (!ExtractIncomingRequest())
    return false;
  HandleJumpService();
  // Set method, path, and version
  m_Request = m_Method;
  m_Request.push_back(' ');
  m_Request += m_Path;
  m_Request.push_back(' ');
  m_Request += m_Version + "\r\n";
  std::pair<std::string, std::string> indexValue;
  std::vector<std::pair<std::string, std::string>> headerMap;
  for (auto it = m_Headers.begin(); it != m_Headers.end(); it++) {
    std::vector<std::string> keyElement;
    boost::split(keyElement, *it, boost::is_any_of(":"));
    std::string key = keyElement[0];
    keyElement.erase(keyElement.begin());
    std::string value = boost::algorithm::join(keyElement, ":");
    // concatenate remaining : values ie times
    headerMap.push_back(std::pair<std::string, std::string>(key,
          value));
  }
  // find and remove/adjust headers
  auto it = std::find_if(headerMap.begin(), headerMap.end(),
      [] (std::pair<std::string, std::string> arg) {
      boost::trim_left(arg.first);
      boost::trim_right(arg.first);
      return arg.first == "User-Agent"; });
  if (it != headerMap.end()) // found
    it->second = " MYOB/6.66 (AN/ON)";
  auto itRefer = std::find_if(headerMap.begin(), headerMap.end(),
      [] (std::pair<std::string, std::string> arg) {
      boost::trim_left(arg.first);
      boost::trim_right(arg.first);
      return arg.first == "Referer"; });
  if (itRefer != headerMap.end()) // found
    headerMap.erase(itRefer);
  for (std::vector<std::pair<std::string, std::string>>::iterator
      ii = headerMap.begin();
      ii != headerMap.end(); ++ii) {
    m_Request = m_Request + ii->first + ":" + ii->second+ "\r\n";
  }
  m_Request = m_Request + "\r\n";
  m_Request = m_Request + m_Body;
  return true;
}

bool HTTPProtocol::ExtractIncomingRequest() {
  LogPrint(eLogDebug,
      "HTTPProxyHandler: method is: ", m_Method,
      ", request is: ", m_URL);
  // Set defaults and regexp
  std::string server = "", port = "80";
  boost::regex regex("http://(.*?)(:(\\d+))?(/.*)");
  boost::smatch smatch;
  std::string path;
  // Ensure path is legitimate
  if (boost::regex_search(m_URL, smatch, regex, boost::match_extra)) {
    server = smatch[1].str();
    if (smatch[2].str() != "")
      port = smatch[3].str();
    path = smatch[4].str();
  }
  LogPrint(eLogDebug,
      "HTTPProxyHandler: server is: ", server,
      ", port is: ", port,
      ", path is: ", path);
  // Set member data
  m_Address = server;
  m_Port = boost::lexical_cast<std::uint16_t>(port);
  m_Path = path;
  // Check for HTTP version
  if (m_Version != "HTTP/1.0" && m_Version != "HTTP/1.1") {
    LogPrint(eLogError, "HTTPProxyHandler: unsupported version: ", m_Version);
    return false;
  }
  return true;
}

void HTTPProtocol::HandleJumpService() {
  // TODO(anonimal): add support for remaining services / rewrite this function
  std::size_t pos1 = m_Path.rfind(m_JumpService.at(0));
  std::size_t pos2 = m_Path.rfind(m_JumpService.at(1));
  std::size_t pos;
  if (pos1 == std::string::npos) {
    if (pos2 == std::string::npos)
      return;  // Not a jump service
    else
      pos = pos2;
  } else {
    if (pos2 == std::string::npos)
      pos = pos1;
    else if (pos1 > pos2)
      pos = pos1;
    else
      pos = pos2;
  }
  auto base64 = m_Path.substr(pos + m_JumpService.at(0).size());
  // We must decode
  HTTP uri;
  base64 = uri.HTTPProxyDecode(base64);
  // Insert into address book
  LogPrint(eLogDebug,
      "HTTPProxyHandler: jump service for ", m_Address,
      " found at ", base64, ". Inserting to address book");
  // TODO(unassigned): this is very dangerous and broken.
  // We should ask the user for confirmation before proceeding.
  // Previous reference: http://pastethis.i2p/raw/pn5fL4YNJL7OSWj3Sc6N/
  // We *could* redirect the user again to avoid dirtiness in the browser
  kovri::client::context.GetAddressBook().InsertAddressIntoStorage(m_Address,
      base64);
  m_Path.erase(pos);
}

/* All hope is lost beyond this point */
void HTTPProxyHandler::HTTPRequestFailed(
    HTTPResponse response) {
  boost::asio::async_write(
      *m_Socket,
      boost::asio::buffer(
          response.m_Response,
          response.m_Response.size()),
      std::bind(
          &HTTPProxyHandler::SentHTTPFailed,
          shared_from_this(),
          std::placeholders::_1));
}

void HTTPProxyHandler::SentHTTPFailed(
    const boost::system::error_code& ecode) {
  if (!ecode) {
    Terminate();
  } else {
    LogPrint(eLogError,
        "HTTPProxyHandler: closing socket after sending failure: '",
        ecode.message(), "'");
    Terminate();
  }
}

void HTTPProxyHandler::Terminate() {
  if (Kill())
    return;
  if (m_Socket) {
    LogPrint(eLogDebug, "HTTPProxyHandler: terminating");
    m_Socket->close();
    m_Socket = nullptr;
  }
  Done(shared_from_this());
}

}  // namespace client
}  // namespace kovri
