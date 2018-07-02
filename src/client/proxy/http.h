/**                                                                                           //
 * Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
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

#include <boost/bind.hpp>
#include <boost/optional.hpp>
#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <utility>

#include "client/destination.h"
#include "client/service.h"

namespace kovri {
namespace client {

/// @class HTTPResponse
/// @brief response for http error messages
class HTTPResponse{
 public:
  enum status_t
  {
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
    http_not_supported = 505,
    space_unavailable = 507
  };

  explicit HTTPResponse(const status_t status)
  {
    set_response(status);
  }

  /// @brief Get error message for a status code
  /// @return HTTP error message
  std::string status_message(const status_t status) const
  {
    switch (status)
      {
        case status_t::ok:
          return "OK";
        case status_t::created:
          return "Created";
        case status_t::accepted:
          return "Accepted";
        case status_t::no_content:
          return "No Content";
        case status_t::multiple_choices:
          return "Multiple Choices";
        case status_t::moved_permanently:
          return "Moved Permanently";
        case status_t::moved_temporarily:
          return "Moved Temporarily";
        case status_t::not_modified:
          return "Not Modified";
        case status_t::bad_request:
          return "Bad Request";
        case status_t::unauthorized:
          return "Unauthorized";
        case status_t::forbidden:
          return "Fobidden";
        case status_t::not_found:
          return "Not Found";
        case status_t::not_supported:
          return "Not Supported";
        case status_t::not_acceptable:
          return "Not Acceptable";
        case status_t::internal_server_error:
          return "Internal Server Error";
        case status_t::not_implemented:
          return "Not Implemented";
        case status_t::bad_gateway:
          return "Bad Gateway";
        case status_t::service_unavailable:
          return "Service Unavailable";
        case status_t::partial_content:
          return "Partial Content";
        case status_t::request_timeout:
          return "Request Timeout";
        case status_t::precondition_failed:
          return "Precondition Failed";
        case status_t::unsatisfiable_range:
          return "Requested Range Not Satisfiable";
        case status_t::http_not_supported:
          return "HTTP Version Not Supported";
        case status_t::space_unavailable:
          return "Insufficient Space to Store Resource";
        default:
          return "Unknown";
      }
  }

  /// @brief Set HTTP error response
  /// @param status HTTP status code for the error response
  void set_response(const status_t status)
  {
    std::string ext_msg{};
    if (status == status_t::service_unavailable)
      ext_msg =
          "<p>Service may be unavailable because it's offline, overloaded, or "
          "the router can't retrieve the service's destination information.<br>"
          "Please try again later.</p>";
    std::string const html_body(
        "<html><head><title>HTTP Error</title></head><body>HTTP Error "
        + std::to_string(status) + " " + status_message(status)
        + ext_msg + "</body></html>");
    m_Response = "HTTP/1.0 " + std::to_string(status) + " "
                 + status_message(status)
                 + "\r\nContent-type: text/html;charset=UTF-8\r\n"
                 + "Content-Encoding: UTF-8\r\nContent-length: "
                 + std::to_string(html_body.size()) + "\r\n\r\n" + html_body;
  }

  /// @brief Get the HTTP error response
  /// @return HTTP error response with HTML-formatted body
  const std::string& get_response() const
  {
    return m_Response;
  }

 private:
  std::string m_Response;
};

/// @class HTTPMessage
/// @brief defines protocol; and read from socket algorithm
class HTTPMessage : public std::enable_shared_from_this<HTTPMessage>{
 public:
  std::string m_RequestLine, m_HeaderLine, m_Request, m_Body,
    m_URL, m_Method, m_Version,  m_Path;
  std::vector<std::string> m_Headers;
  std::string m_Host, m_UserAgent;
  std::string m_Address, m_Base64Destination;

  boost::asio::streambuf m_Buffer;
  boost::asio::streambuf m_BodyBuffer;
  std::vector<std::pair<std::string, std::string>> m_HeaderMap;
  /// @brief Data for incoming request
  std::uint16_t m_Port;

  /// @var m_JumpService
  /// @brief Address helpers for base64 jump service
  const std::array<std::string, 4> m_JumpService {
  {
    "?i2paddresshelper=",
    "&i2paddresshelper=",
    "?kovrijumpservice=",
    "&kovrijumpservice=",
  }
  };
  HTTPResponse m_ErrorResponse;
  HTTPMessage() : m_Port(0), m_ErrorResponse(HTTPResponse::status_t::ok) {}
  enum msg_t {
    response,
    request
  };
  /// @brief loads variables in class;
  /// @param buf
  /// @param len
  /// return bool
  bool HandleData(const std::string  &buf);

  /// @brief Parses URI for base64 destination
  /// @return true on success
  bool HandleJumpService();

  /// @brief Performs regex, sets address/port/path, validates version
  ///   on request sent from user
  /// @return true on success
  bool ExtractIncomingRequest();

  /// @brief Processes original request: extracts, validates,
  ///   calls jump service, appends original request
  /// @param save_address Save address to disk
  /// @return true on success
  // TODO(unassigned): save address param is a hack until storage is separated from message
  bool CreateHTTPRequest(const bool save_address = true);

  /// @brief Sets HTTP error response
  /// @param status HTTP status code
  void set_error_response(const HTTPResponse::status_t status)
  {
    m_ErrorResponse.set_response(status);
  }

  /// @brief Get HTTP error response
  /// @return HTTP error response
  const std::string& get_error_response() const
  {
    return m_ErrorResponse.get_response();
  }

  const unsigned int HEADERBODY_LEN = 2;
  const unsigned int REQUESTLINE_HEADERS_MIN = 1;
 private:
  /// @brief Checks if request is a valid jump service request
  /// @return Index of jump service helper sub-string, 0 indicates failure
  std::size_t IsJumpServiceRequest() const;

  /// @brief Extracts & url-decodes base64 destination from URL
  /// @param pos Index of jump service helper sub-string in URL
  /// @return True on success
  bool ExtractBase64Destination(std::size_t const pos);

  /// @brief Saves found address in address book
  /// @return True on success
  bool SaveJumpServiceAddress();
};
/// @class HTTPProxyServer
/// setup asio service
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
      std::shared_ptr<kovri::client::ClientDestination> local_destination
              = nullptr);

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
/// @brief setup handler for asio service
/// each service needs a handler
class HTTPProxyHandler
    : public kovri::client::I2PServiceHandler,
      public std::enable_shared_from_this<HTTPProxyHandler> {
 public:
  HTTPMessage m_Protocol;
  /// @param parent Pointer to parent server
  /// @param socket Shared pointer to bound socket
  HTTPProxyHandler(
      HTTPProxyServer* parent,
      std::shared_ptr<boost::asio::ip::tcp::socket> socket)
      : I2PServiceHandler(parent),
        m_Socket(socket) {
        }

  ~HTTPProxyHandler() {
    Terminate();
  }
  void CreateStream();
  /// @brief reads data sent to proxy server
  /// virtual function;
  /// handle reading the protocol
  void Handle();

  /// @brief Handles buffer received from socket if Handle successful
  void HandleSockRecv(const boost::system::error_code & error,
    std::size_t bytes_transfered);

 private:
  /*! @brief read from a socket
   *
   *AsyncSockRead             - perform async read
   *  -AsyncHandleReadHeaders - handle read header info
   *    -HTTPMessage::HandleData   - handle header info
   *    -HandleSockRecv       - read body if needed
   *      -CreateStream
   *        -HTTPMessage::CreateHTTPStreamRequest -  create stream request
   *        -HandleStreamRequestComplete           -  connect to i2p tunnel
   */
  void AsyncSockRead(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
  // @brief handle read data
  void AsyncHandleReadHeaders(const boost::system::error_code & error,
    std::size_t bytes_transferred);


  /// @brief Handles stream created by service through proxy handler
  void HandleStreamRequestComplete(
      std::shared_ptr<kovri::client::Stream> stream);

  /// @brief Generic request failure handler
  void HTTPRequestFailed();

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
//  std::array<std::uint8_t, static_cast<std::size_t>(Size::buffer)> m_Buffer;
  std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_PROXY_HTTP_H_
