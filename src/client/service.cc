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

#include "client/service.h"

#include <string>

#include "client/context.h"
#include "client/destination.h"

#include "core/router/identity.h"

namespace kovri {
namespace client {

I2PService::I2PService(
    std::shared_ptr<ClientDestination> local_destination)
    : m_LocalDestination(
        local_destination
        ? local_destination
        : kovri::client::context.CreateNewLocalDestination()) {}

I2PService::I2PService(
    kovri::core::SigningKeyType key_type)
    : m_LocalDestination(
        kovri::client::context.CreateNewLocalDestination(key_type)) {}

void I2PService::CreateStream(
    StreamRequestComplete stream_request_complete,
    const std::string& dest,
    std::uint16_t port) {
  assert(stream_request_complete);
  kovri::core::IdentHash ident_hash;
  if (kovri::client::context.GetAddressBook().CheckAddressIdentHashFound(dest, ident_hash)) {
    m_LocalDestination->CreateStream(
        stream_request_complete,
        ident_hash,
        port);
  } else {
    LogPrint(eLogWarn,
        "I2PService: remote destination ", dest, " not found");
    stream_request_complete(nullptr);
  }
}

void TCPIPAcceptor::Start() {
  m_Acceptor.listen();
  Accept();
}

void TCPIPAcceptor::Stop() {
  m_Acceptor.close();
  m_Timer.cancel();
  ClearHandlers();
}

void TCPIPAcceptor::Rebind(
    const std::string& addr,
    std::uint16_t port) {
  LogPrint(eLogInfo,
      "I2PService: re-bind ", GetName(), " to ", addr, ":", port);
  // stop everything with us
  m_Acceptor.cancel();
  Stop();
  // make new acceptor
  m_Acceptor =
    boost::asio::ip::tcp::acceptor(
        GetService(),
        boost::asio::ip::tcp::endpoint(
            boost::asio::ip::address::from_string(
              addr),
            port));
  // start everything again
  Start();
}

void TCPIPAcceptor::Accept() {
  auto new_socket =
    std::make_shared<boost::asio::ip::tcp::socket> (GetService());
  m_Acceptor.async_accept(
      *new_socket,
      std::bind(
        &TCPIPAcceptor::HandleAccept,
        this,
        std::placeholders::_1,
        new_socket));
}

void TCPIPAcceptor::HandleAccept(
    const boost::system::error_code& ecode,
    std::shared_ptr<boost::asio::ip::tcp::socket> socket) {
  if (!ecode) {
    LogPrint(eLogInfo, "I2PService: ", GetName(), " accepted");
    auto handler = CreateHandler(socket);
    if (handler) {
      AddHandler(handler);
      handler->Handle();
    } else {
      socket->close();
    }
    Accept();
  } else {
    if (ecode != boost::asio::error::operation_aborted)
      LogPrint(eLogError,
          "I2PService: ", GetName(),
          " closing socket on accept because: ", ecode.message());
  }
}

}  // namespace client
}  // namespace kovri
