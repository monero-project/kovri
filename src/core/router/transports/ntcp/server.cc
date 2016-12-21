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

#include "core/router/transports/ntcp/server.h"

#include <cstdint>
#include <memory>
#include <string>

#include "core/router/context.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/ntcp/session.h"
#include "core/router/transports/impl.h"

#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {

NTCPServer::NTCPServer(
    boost::asio::io_service& service,
    std::size_t port)
    : m_IsRunning(false),
      m_Service(service),
      m_NTCPEndpoint(boost::asio::ip::tcp::v4(), port),
      m_NTCPEndpointV6(boost::asio::ip::tcp::v6(), port),
      m_NTCPAcceptor(nullptr),
      m_NTCPV6Acceptor(nullptr) {}

NTCPServer::~NTCPServer() {}

void NTCPServer::Start() {
  if (!m_IsRunning) {
    LogPrint(eLogDebug, "NTCPServer: starting");
    m_IsRunning = true;
    // Create acceptors
    m_NTCPAcceptor =
      std::make_unique<boost::asio::ip::tcp::acceptor>(
          m_Service,
          m_NTCPEndpoint);
    auto conn = std::make_shared<NTCPSession>(*this);
    m_NTCPAcceptor->async_accept(
        conn->GetSocket(),
        std::bind(
            &NTCPServer::HandleAccept,
            this,
            conn,
            std::placeholders::_1));
    // If IPv6 is enabled, create IPv6 acceptor
    if (context.SupportsV6()) {
      m_NTCPV6Acceptor =
        std::make_unique<boost::asio::ip::tcp::acceptor>(m_Service);
      m_NTCPV6Acceptor->open(boost::asio::ip::tcp::v6());
      m_NTCPV6Acceptor->set_option(boost::asio::ip::v6_only(true));
      m_NTCPV6Acceptor->bind(m_NTCPEndpointV6);
      m_NTCPV6Acceptor->listen();
      auto conn = std::make_shared<NTCPSession>(*this);
      m_NTCPV6Acceptor->async_accept(
          conn->GetSocket(),
          std::bind(
              &NTCPServer::HandleAcceptV6,
              this,
              conn,
              std::placeholders::_1));
    }
  }
}

void NTCPServer::HandleAccept(
    std::shared_ptr<NTCPSession> conn,
    const boost::system::error_code& ecode) {
  if (!ecode) {
    LogPrint(eLogDebug, "NTCPServer: handling accepted connection");
    boost::system::error_code ec;
    auto ep = conn->GetSocket().remote_endpoint(ec);
    if (!ec) {
      LogPrint(eLogDebug, "NTCPServer: connected from ", ep);
      auto it = m_BanList.find(ep.address());
      if (it != m_BanList.end()) {
        std::uint32_t ts = kovri::core::GetSecondsSinceEpoch();
        if (ts < it->second) {
          LogPrint(eLogDebug,
              "NTCPServer: ", ep.address(), " is banned for ",
              it->second - ts, " more seconds");
          conn = nullptr;
        } else {
          m_BanList.erase(it);
        }
      }
      if (conn)
        conn->ServerLogin();
    } else {
      LogPrint(eLogError,
          "NTCPServer: HandleAccept() remote endpoint: ", ec.message());
    }
  } else {
    LogPrint(eLogError,
        "NTCPServer: HandleAccept(): '", ecode.message(), "'");
  }
  if (ecode != boost::asio::error::operation_aborted) {
    conn = std::make_shared<NTCPSession>(*this);
    m_NTCPAcceptor->async_accept(
        conn->GetSocket(),
        std::bind(
            &NTCPServer::HandleAccept,
            this,
            conn,
            std::placeholders::_1));
  }
}

void NTCPServer::HandleAcceptV6(
    std::shared_ptr<NTCPSession> conn,
    const boost::system::error_code& ecode) {
  if (!ecode) {
    LogPrint(eLogDebug, "NTCPServer: handling V6 accepted connection");
    boost::system::error_code ec;
    auto ep = conn->GetSocket().remote_endpoint(ec);
    if (!ec) {
      LogPrint(eLogDebug,
          "NTCPServer: V6 connected from ", ep);
      auto it = m_BanList.find(ep.address());
      if (it != m_BanList.end()) {
        std::uint32_t ts = kovri::core::GetSecondsSinceEpoch();
        if (ts < it->second) {
          LogPrint(eLogDebug,
              "NTCPServer: ", ep.address(), " is banned for ",
              it->second - ts, " more seconds");
          conn = nullptr;
        } else {
          m_BanList.erase(it);
        }
      }
      if (conn)
        conn->ServerLogin();
    } else {
      LogPrint(eLogError,
          "NTCPServer: HandleAcceptV6() remote endpoint: ", ec.message());
    }
  } else {
    LogPrint(eLogError,
        "NTCPServer: HandleAcceptV6(): '", ecode.message(), "'");
  }
  if (ecode != boost::asio::error::operation_aborted) {
    conn = std::make_shared<NTCPSession>(*this);
    m_NTCPV6Acceptor->async_accept(
        conn->GetSocket(),
        std::bind(
            &NTCPServer::HandleAcceptV6,
            this,
            conn,
            std::placeholders::_1));
  }
}

void NTCPServer::Connect(
    const boost::asio::ip::address& address,
    std::size_t port,
    std::shared_ptr<NTCPSession> conn) {
  LogPrint(eLogDebug,
      "NTCPServer: connecting to [",
      context.GetRouterInfo().GetIdentHashAbbreviation(), "] ",
      address , ":",  port);

  conn->GetSocket().async_connect(
      boost::asio::ip::tcp::endpoint(
          address,
          port),
      std::bind(
          &NTCPServer::HandleConnect,
          this,
          conn,
          std::placeholders::_1));
}

void NTCPServer::HandleConnect(
    std::shared_ptr<NTCPSession> conn,
    const boost::system::error_code& ecode) {
  if (ecode) {
    LogPrint(eLogError,
      "NTCPServer: connection handler error '", ecode.message(), "'");
    if (ecode != boost::asio::error::operation_aborted)
      kovri::core::netdb.SetUnreachable(
          conn->GetRemoteIdentity().GetIdentHash(),
          true);
    conn->Terminate();
  } else {
    LogPrint(eLogDebug,
        "NTCPServer: connected to ", conn->GetSocket().remote_endpoint());
    if (conn->GetSocket().local_endpoint().protocol() ==
        boost::asio::ip::tcp::v6())  // ipv6
      context.UpdateNTCPV6Address(
          conn->GetSocket().local_endpoint().address());
    conn->ClientLogin();

    m_Service.post([conn, this]() {
        this->AddNTCPSession(conn);
    });
  }
}

void NTCPServer::AddNTCPSession(
    std::shared_ptr<NTCPSession> session) {
  if (session) {
    LogPrint(eLogDebug,
        "NTCPServer: ", session->GetSocket().remote_endpoint(),
        " *** adding NTCP session");
    std::unique_lock<std::mutex> l(m_NTCPSessionsMutex);
    m_NTCPSessions[session->GetRemoteIdentity().GetIdentHash()] = session;
  }
}

void NTCPServer::RemoveNTCPSession(
    std::shared_ptr<NTCPSession> session) {
  if (session) {
    LogPrint(eLogDebug,
        "NTCPServer:", session->GetFormattedSessionInfo(),
        "*** removing NTCP session");
    std::unique_lock<std::mutex> l(m_NTCPSessionsMutex);
    m_NTCPSessions.erase(session->GetRemoteIdentity().GetIdentHash());
  }
}

std::shared_ptr<NTCPSession> NTCPServer::FindNTCPSession(
    const kovri::core::IdentHash& ident) {
  LogPrint(eLogDebug, "NTCPServer: finding NTCP session");
  std::unique_lock<std::mutex> l(m_NTCPSessionsMutex);
  auto it = m_NTCPSessions.find(ident);
  if (it != m_NTCPSessions.end())
    return it->second;
  return nullptr;
}

void NTCPServer::Ban(
    const std::shared_ptr<NTCPSession>& session) {
  std::uint32_t ts = kovri::core::GetSecondsSinceEpoch();
  m_BanList[session->GetRemoteEndpoint().address()] =
    ts + static_cast<std::size_t>(NTCPTimeoutLength::ban_expiration);
  LogPrint(eLogWarn,
      "NTCPServer:", session->GetFormattedSessionInfo(), "has been banned for ",
      static_cast<std::size_t>(NTCPTimeoutLength::ban_expiration), " seconds");
}

void NTCPServer::Stop() {
  LogPrint(eLogDebug, "NTCPServer: stopping");
  m_NTCPSessions.clear();
  if (m_IsRunning) {
    m_IsRunning = false;
    m_NTCPAcceptor.reset(nullptr);
    m_NTCPV6Acceptor.reset(nullptr);
  }
}

}  // namespace core
}  // namespace kovri

