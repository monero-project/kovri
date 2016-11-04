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

#include "core/router/identity.h"

#include "core/util/i2p_endian.h"

namespace kovri {
namespace client {
HTTPProxyMessage::HTTPProxyMessage(int response_code,const std::string & response_string,const std::string & body, unsigned int body_length){
  m_Headers.m_Total=NUMBER_OF_HEADERS;
  SetResponse(response_code,response_string);
}
bool HTTPProxyMessage::IsValid(HTTPProxyMessage & msg){
        if (msg.m_Headers.m_Strings.size() == 0)
                return false;
        if (msg.m_Response.m_String == "")
                return false;
        if (msg.m_Response.m_Code < 1 || msg.m_Response.m_Code > 999)
                return false;

        return true;

}
bool HTTPProxyMessage::SetBody(const std::string & body, size_t len)
{
        /* Check for valid arguments */
        if (body.length() == 0)
                return false;
        if (len == 0)
                return false;

        m_Body.m_Text = body;
        m_Body.m_Length = len;

        return true;
}


void HTTPProxyMessage::SetResponse(int response_code, const std::string &response_string){
  m_Response.m_Code=response_code;  
  m_Response.m_String=response_string;
}
//
// @brief Server
//

HTTPProxyServer::HTTPProxyServer(
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

std::shared_ptr<kovri::client::I2PServiceHandler> HTTPProxyServer::CreateHandler(
    std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
  return std::make_shared<HTTPProxyHandler>(this, socket);
}

//
// Handler
//

void HTTPProxyHandler::AsyncSockRead() {
  LogPrint(eLogDebug, "HTTPProxyHandler: async sock read");
  if (m_Socket) {
    m_Socket->async_receive(
        boost::asio::buffer(
            m_Buffer.data(),
            m_Buffer.size()),
        std::bind(
            &HTTPProxyHandler::HandleSockRecv,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2));
  } else {
    LogPrint(eLogError, "HTTPProxyHandler: no socket for read");
  }
}

void HTTPProxyHandler::HandleSockRecv(
    const boost::system::error_code& ecode,
    std::size_t len) {
  LogPrint(eLogDebug, "HTTPProxyHandler: sock recv: ", len);
  if (ecode) {
    LogPrint(eLogWarn, "HTTPProxyHandler: sock recv got error: ", ecode);
          Terminate();
    return;
  }
  if (HandleData(m_Buffer.data(), len)) {
      LogPrint(eLogInfo, "HTTPProxyHandler: proxy requested: ", m_URL);
      GetOwner()->CreateStream(
          std::bind(
              &HTTPProxyHandler::HandleStreamRequestComplete,
              shared_from_this(),
              std::placeholders::_1),
          m_Address,
          m_Port);
  }
}

bool HTTPProxyHandler::HandleData(
    std::uint8_t* buf,
    std::size_t len) {
  assert(len);
  std::string bufString(buf,buf+len);
  std::vector<std::string> HeaderBody;
  std::vector<std::string> tokens;
  //get header info
  boost::algorithm::split_regex(HeaderBody,bufString,boost::regex("\r\n\r\n"));
  boost::algorithm::split_regex(tokens,HeaderBody[0],boost::regex("\r\n"));
  m_RequestLine=tokens[0];
  //requestline
  std::vector<std::string> tokensRequest;
  boost::split(tokensRequest,m_RequestLine,boost::is_any_of(" \t"));
  m_Method=tokensRequest[0];
  m_URL=tokensRequest[1];
  m_Version=tokensRequest[2];
  //headersline
  m_Headers=tokens;
  m_Headers.erase(m_Headers.begin()); //remove start line
  //send the headers into the map.
  //body line
  m_Body=HeaderBody[1];
  return CreateHTTPRequest(len);
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
    connection->I2PConnect(
        reinterpret_cast<const std::uint8_t*>(m_Request.data()),
        m_Request.size());
    Done(shared_from_this());
  } else {
    LogPrint(eLogError,
        "HTTPProxyHandler: issue when creating the stream,"
        "check the previous warnings for details");
    // TODO(unassigned): Send correct error message host unreachable
    HTTPRequestFailed();
  }
}
bool HTTPProxyHandler::CreateHTTPRequest(
    std::size_t len) {
  if (!ExtractIncomingRequest())
    return false;
  HandleJumpService();
  // Set method, path, and version
  m_Request = m_Method;
  m_Request.push_back(' ');
  m_Request += m_URL;
  m_Request.push_back(' ');
  m_Request += m_Version + "\r\n";
  // Reset/scrub User-Agent: ; 1. create map from list of headerssplit on :;2.  replace useragent
  std::multimap<std::string,std::string> headerMap;
  for(auto it = m_Headers.begin();it!=m_Headers.end();it++)
  {
    std::vector<std::string> keyElement;
     
    boost::split(keyElement,*it,boost::is_any_of(":"));
    headerMap.insert(std::pair<std::string,std::string>(keyElement[0],keyElement[1]));
  }
  //multimaps cannot directly access the key
  //
  std::pair <std::multimap<std::string,std::string>::iterator, std::multimap<std::string,std::string>::iterator> ret;
  ret = headerMap.equal_range("User-Agent");
  for( std::multimap<std::string,std::string>::iterator it = ret.first;it!=ret.second;it++){
    it->second= "MYOB/6.66 (AN/ON)";
  }

  for( std::map<std::string, std::string>::iterator ii=headerMap.begin(); ii!=headerMap.end(); ++ii){
    m_Request = m_Request + ii->first + ":" + ii->second+ "\r\n";
  }
  m_Request=m_Request + "\r\n";
  return true;
}

bool HTTPProxyHandler::ExtractIncomingRequest() {
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
    HTTPRequestFailed();  // TODO(unassigned): send correct responses
    return false;
  }
  return true;
}

void HTTPProxyHandler::HandleJumpService() {
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
  kovri::client::context.GetAddressBook().InsertAddressIntoStorage(m_Address, base64);
  m_Path.erase(pos);
}

/* All hope is lost beyond this point */
// TODO(unassigned): handle this appropriately
void HTTPProxyHandler::HTTPRequestFailed(
    /*Error error*/) {
  static std::string response =
    "HTTP/1.0 500 Internal Server Error\r\n"
    "Content-type: text/html\r\n"
    "Content-length: 0\r\n";
  boost::asio::async_write(
      *m_Socket,
      boost::asio::buffer(
          response,
          response.size()),
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
