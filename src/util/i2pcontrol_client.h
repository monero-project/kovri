/**
 * Copyright (c) 2015-2017, The Kovri I2P Router Project
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
 */

#ifndef SRC_UTIL_I2PCONTROL_CLIENT_H_
#define SRC_UTIL_I2PCONTROL_CLIENT_H_

#include <boost/network/include/http/client.hpp>

#include <memory>
#include <string>

#include "client/api/i2p_control/data.h"

// Note: Credit goes to EinMByte.
// This is heavily inspired from i2pcontrol_client.h in qtoopie.

namespace kovri
{
namespace client
{
/**
 * @brief Provides functiality to communicate with an I2PControl server over HTTP.
 */
class I2PControlClient final
{
 public:
  // @brief I2PControlClient constructor
  // @param url the location of the HTTP document providing the JSONRPC API.
  explicit I2PControlClient(std::shared_ptr<boost::asio::io_service>);

  // @brief Starts the ::I2PControlClient.
  // @param callback the function to be called when the client is connected
  // @throw std::exception on error
  void AsyncConnect(
      std::function<void(std::unique_ptr<I2PControlResponse>)> callback);

  // @brief Sends a request to the I2PControl server.
  // @details automatically sets the token for non auth request
  // @details automatically reconnects if token expired
  // @param request the request to be sent
  // @param callback the function to be called when the request has finished
  // @throw std::exception on error
  void AsyncSendRequest(
      std::shared_ptr<I2PControlRequest> request,
      std::function<void(std::unique_ptr<I2PControlResponse>)> callback);

  // @brief Sets the host of the i2p router
  // @param host ip or hostname to connect to
  // @throw std::bad_alloc when not enough memory
  void SetHost(const std::string& host);

  // @brief Sets the port of the i2p router
  // @param port port to connect to
  // @throw std::bad_alloc when not enough memory
  void SetPort(std::uint16_t port);

  // @brief Sets the password of the i2p router
  // @param password password to use
  // @throw std::bad_alloc when not enough memory
  void SetPassword(const std::string& password);

 private:
  // For convenience
  typedef I2PControlResponse Response;
  typedef I2PControlRequest Request;
  typedef Response::ErrorCode ErrorCode;
  typedef Request::Method Method;

  // @brief Effectively sends request without any modification
  // @param request Original request
  // @param callback Callback to call
  // @throw std::exception on error
  void ProcessAsyncSendRequest(
      std::shared_ptr<Request> request,
      std::function<void(std::unique_ptr<Response>)> callback);

  // @brief Concatenate chunks as received and call callback when finished receiving
  // @param it iterator over chunk of data received
  // @param error Error as returned by underlying lib
  // @param request Original request
  // @param stream concatenation of chunks received so far
  // @param callback Callback to call when response is complete
  // @throw boost::system::error on error
  void HandleHTTPResponse(
      boost::network::http::client::char_const_range const& it,
      boost::system::error_code const& error,
      std::shared_ptr<Request> request,
      std::shared_ptr<std::stringstream> stream,
      std::function<void(std::unique_ptr<Response>)> callback);

  std::string m_Host{"127.0.0.1"};
  std::uint16_t m_Port{7650};
  std::string m_Password{"itoopie"};
  std::string m_Token{};
  std::shared_ptr<boost::asio::io_service> m_Service;
  std::unique_ptr<boost::network::http::client> m_Client;
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_UTIL_I2PCONTROL_CLIENT_H_
