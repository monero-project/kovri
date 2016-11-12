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

#ifndef SRC_CLIENT_PROXY_HTTP_H_
#define SRC_CLIENT_PROXY_HTTP_H_

#include <boost/asio.hpp>
#include <boost/network/protocol/http/server.hpp>
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "client/destination.h"
#include "client/service.h"

namespace kovri {
namespace client {

/// @class HTTPProxyServer
class HTTPProxyServer
    : public kovri::client::TCPIPAcceptor {
 public:
  /// @param name Proxy server service name
  /// @param address Proxy binding address
  /// @param port Proxy binding port
  /// @param local_destination Client destination
  //
  HTTPProxyServer(
      const std::string& name,
      const std::string& address,
      std::uint16_t port,
      std::shared_ptr<kovri::client::ClientDestination> local_destination = nullptr);

  ~HTTPProxyServer() {}

  /// @brief Implements TCPIPAcceptor
  std::shared_ptr<kovri::client::I2PServiceHandler> CreateHandler(
      std::shared_ptr<boost::asio::ip::tcp::socket> socket);

  /// @brief Gets name of proxy service
  /// @return Name of proxy service
  std::string GetName() const {
    return m_Name;
  }

 private:
  std::string m_Name;
};

typedef HTTPProxyServer HTTPProxy;

/// @class HTTPProxyHandler
class HTTPProxyHandler
    : public kovri::client::I2PServiceHandler,
      public std::enable_shared_from_this<HTTPProxyHandler> {
 public:
 enum status_t {
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    partial_content = 206,
    multiple_choices = 300,
    moved_permanently = 301,
    moved_temporarily = 302,
    not_modified = 304,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    not_supported = 405,
    not_acceptable = 406,
    request_timeout = 408,
    precondition_failed = 412,
    unsatisfiable_range = 416,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    space_unavailable = 507
  };

  static char const* status_message(status_t status) {
    static char const ok_[] = "OK", created_[] = "Created",
                      accepted_[] = "Accepted", no_content_[] = "No Content",
                      multiple_choices_[] = "Multiple Choices",
                      moved_permanently_[] = "Moved Permanently",
                      moved_temporarily_[] = "Moved Temporarily",
                      not_modified_[] = "Not Modified",
                      bad_request_[] = "Bad Request",
                      unauthorized_[] = "Unauthorized",
                      forbidden_[] = "Fobidden", not_found_[] = "Not Found",
                      not_supported_[] = "Not Supported",
                      not_acceptable_[] = "Not Acceptable",
                      internal_server_error_[] = "Internal Server Error",
                      not_implemented_[] = "Not Implemented",
                      bad_gateway_[] = "Bad Gateway",
                      service_unavailable_[] = "Service Unavailable",
                      unknown_[] = "Unknown",
                      partial_content_[] = "Partial Content",
                      request_timeout_[] = "Request Timeout",
                      precondition_failed_[] = "Precondition Failed",
                      unsatisfiable_range_[] =
                          "Requested Range Not Satisfiable",
                      space_unavailable_[] =
                          "Insufficient Space to Store Resource";
    switch (status) {
      case ok:
        return ok_;
      case created:
        return created_;
      case accepted:
        return accepted_;
      case no_content:
        return no_content_;
      case multiple_choices:
        return multiple_choices_;
      case moved_permanently:
        return moved_permanently_;
      case moved_temporarily:
        return moved_temporarily_;
      case not_modified:
        return not_modified_;
      case bad_request:
        return bad_request_;
      case unauthorized:
        return unauthorized_;
      case forbidden:
        return forbidden_;
      case not_found:
        return not_found_;
      case not_supported:
        return not_supported_;
      case not_acceptable:
        return not_acceptable_;
      case internal_server_error:
        return internal_server_error_;
      case not_implemented:
        return not_implemented_;
      case bad_gateway:
        return bad_gateway_;
      case service_unavailable:
        return service_unavailable_;
      case partial_content:
        return partial_content_;
      case request_timeout:
        return request_timeout_;
      case precondition_failed:
        return precondition_failed_;
      case unsatisfiable_range:
        return unsatisfiable_range_;
      case space_unavailable:
        return space_unavailable_;
      default:
        return unknown_;
    }
  }


  /// @param parent Pointer to parent server
  /// @param socket Shared pointer to bound socket
  HTTPProxyHandler(
      HTTPProxyServer* parent,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket)
      : I2PServiceHandler(parent),
        m_Socket(socket),
        m_Port(0) {

        }

  ~HTTPProxyHandler() {
    Terminate();
  }

  void Handle() {
    AsyncSockRead();
  }

 private:
  /// @brief Asynchronously reads data sent to proxy server
  void AsyncSockRead();

  /// @brief Handles buffer received from socket until read is finished
  void HandleSockRecv(
      const boost::system::error_code& ecode,
      std::size_t bytes_transfered);

  /// @brief Handles data received from socket
  bool HandleData(
      uint8_t* buf,
      std::size_t len);

  /// @brief Handles stream created by service through proxy handler
  void HandleStreamRequestComplete(
      std::shared_ptr<kovri::client::Stream> stream);

  /// @brief Processes original request: extracts, validates,
  ///   calls jump service, appends original request
  /// @return true on success
  bool CreateHTTPRequest(
      std::size_t len);

  /// @brief Performs regex, sets address/port/path, validates version
  ///   on request sent from user
  /// @return true on success
  bool ExtractIncomingRequest();

  /// @brief Parses path for base64 address, inserts into address book
  void HandleJumpService();

  /// @brief Generic request failure handler
  /// @param error User-defined enumerated error code
  void HTTPRequestFailed(HTTPProxyHandler::status_t);

  /// @brief Tests if our sent response to browser has failed
  /// @param ecode Boost error code
  void SentHTTPFailed(
      const boost::system::error_code& ecode);

  /// @brief Kills handler for Service, closes socket
  void Terminate();

 private:
  /// @enum Size::Size
  /// @brief Constant for size
  enum Size : const std::uint16_t {
    /// @var buffer
    /// @brief Buffer size for async sock read
    buffer = 8192
  };

  /// @var m_Buffer
  /// @brief Buffer for async socket read
  std::array<std::uint8_t, static_cast<std::size_t>(Size::buffer)> m_Buffer;
  std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;

  /// @brief Data for incoming request
  std::string m_RequestLine, m_HeaderLine,m_Request, m_Body,m_URL, m_Method, m_Version, m_Address, m_Path;
  std::vector<std::string> m_Headers;
  std::string m_Host, m_UserAgent;
  std::uint16_t m_Port;

  /// @var m_JumpService
  /// @brief Address helpers for base64 jump service
  const std::array<std::string, 4> m_JumpService {{
    "?i2paddresshelper=",
    "&i2paddresshelper=",
    "?kovrijumpservice=",
    "&kovrijumpservice=",
  }};
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_PROXY_HTTP_H_
