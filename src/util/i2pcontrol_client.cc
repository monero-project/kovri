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

#include "util/i2pcontrol_client.h"

#include <boost/network/uri.hpp>

#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

#include "core/util/byte_stream.h"

namespace asio = boost::asio;
namespace core = kovri::core;
namespace http = boost::network::http;

namespace kovri
{
namespace client
{
I2PControlClient::I2PControlClient(std::shared_ptr<asio::io_service> service)
    : m_Service(service)
{
  http::client::options options;
  options.io_service(m_Service);
  m_Client = std::make_unique<http::client>(options);
}

void I2PControlClient::SetHost(const std::string& host)
{
  m_Host = host;
}

void I2PControlClient::SetPort(std::uint16_t port)
{
  m_Port = port;
}

void I2PControlClient::SetPassword(const std::string& password)
{
  m_Password = password;
}

void I2PControlClient::AsyncConnect(
    std::function<void(std::unique_ptr<Response>)> callback)
{
  auto request = std::make_shared<Request>();
  request->SetID(std::size_t(0));
  request->SetMethod(Method::Authenticate);
  request->SetParam(Request::MethodAuthenticate::API, std::size_t(1));
  request->SetParam(Request::MethodAuthenticate::Password, m_Password);

  ProcessAsyncSendRequest(
      request, [this, callback](std::unique_ptr<Response> response) {
        if (response->GetError() == Response::ErrorCode::None)  // Store token
          {
            LOG(debug) << "I2PControlClient: Authentication successful";
            m_Token = response->GetParam<std::string>(
                Request::MethodAuthenticate::Token);
          }
        else
          {
            LOG(debug) << "I2PControlClient: Authentication failed!";
          }
        callback(std::move(response));
      });
}

void I2PControlClient::AsyncSendRequest(
    std::shared_ptr<Request> request,
    std::function<void(std::unique_ptr<Response>)> callback)
{
  // First try
  ProcessAsyncSendRequest(
      request, [this, request, callback](std::unique_ptr<Response> response) {
        // Received response
        switch (response->GetError())
          {
            case ErrorCode::NonexistentToken:
            case ErrorCode::ExpiredToken:
              // Auto re-authenticate
              AsyncConnect(
                  [this, request, callback](std::unique_ptr<Response>) {
                    // Try one last time
                    ProcessAsyncSendRequest(request, callback);
                  });
              break;
            default:
              callback(std::move(response));
              break;
          }
      });
}

void I2PControlClient::ProcessAsyncSendRequest(
    std::shared_ptr<Request> request,
    std::function<void(std::unique_ptr<Response>)> callback)
{
  namespace uri = boost::network::uri;
  uri::uri url;
  url << uri::scheme("http") << uri::host(m_Host) << uri::port(m_Port);
  http::client::request http_request(url);

  if (request->GetMethod() != Method::Authenticate)
    request->SetToken(m_Token);

  auto stream = std::make_shared<std::stringstream>();
  m_Client->post(
      http_request,
      request->ToJsonString(),
      "application/json",
      std::bind(
          &I2PControlClient::HandleHTTPResponse,
          this,
          std::placeholders::_1,
          std::placeholders::_2,
          request,
          stream,
          callback));
}

void I2PControlClient::HandleHTTPResponse(
    boost::network::http::client::char_const_range const& range,
    boost::system::error_code const& error,
    std::shared_ptr<Request> request,
    std::shared_ptr<std::stringstream> stream,
    std::function<void(std::unique_ptr<Response>)> callback)
{
  if (error && error != asio::error::eof)  // Connection closed cleanly by peer.
    throw boost::system::system_error(error);  // Some other error.

  *stream << std::string(boost::begin(range), boost::end(range));
  if (error == asio::error::eof)
    {
      LOG(trace) << "I2PControlClient: received " << stream->str();
      auto response = std::make_unique<Response>();
      response->Parse(request->GetMethod(), *stream);
      callback(std::move(response));
    }
}

}  // namespace client
}  // namespace kovri
