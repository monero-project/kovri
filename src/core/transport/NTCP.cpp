/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
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

#include "NTCP.h"

#include "NTCPSession.h"
#include "NetworkDatabase.h"
#include "RouterContext.h"
#include "Transports.h"
#include "util/Timestamp.h"

namespace i2p {
namespace transport {

NTCPServer::NTCPServer(int)
    : m_IsRunning(false),
      m_Thread(nullptr),
      m_Work(m_Service),
      m_NTCPAcceptor(nullptr),
      m_NTCPV6Acceptor(nullptr) {}

NTCPServer::~NTCPServer() {
  Stop();
}

void NTCPServer::Start() {
  if (!m_IsRunning) {
    m_IsRunning = true;
    m_Thread = new std::thread(std::bind(&NTCPServer::Run, this));
    // create acceptors
    auto addresses = context.GetRouterInfo().GetAddresses();
    for (auto& address : addresses) {
      if (address.transportStyle ==
          i2p::data::RouterInfo::eTransportNTCP &&
          address.host.is_v4()) {
        m_NTCPAcceptor = new boost::asio::ip::tcp::acceptor(
            m_Service,
            boost::asio::ip::tcp::endpoint(
              boost::asio::ip::tcp::v4(),
              address.port));
        LogPrint(eLogInfo, "Start listening TCP port ", address.port);
        auto conn = std::make_shared<NTCPSession>(*this);
        m_NTCPAcceptor->async_accept(
            conn->GetSocket(),
            std::bind(
              &NTCPServer::HandleAccept,
              this,
              conn,
              std::placeholders::_1));
        if (context.SupportsV6()) {
          m_NTCPV6Acceptor = new boost::asio::ip::tcp::acceptor(m_Service);
          m_NTCPV6Acceptor->open(boost::asio::ip::tcp::v6());
          m_NTCPV6Acceptor->set_option(boost::asio::ip::v6_only(true));
          m_NTCPV6Acceptor->bind(boost::asio::ip::tcp::endpoint(
                boost::asio::ip::tcp::v6(),
                address.port));
          m_NTCPV6Acceptor->listen();
          LogPrint(eLogInfo, "Started listening V6 on TCP port ", address.port);
          auto conn = std::make_shared<NTCPSession> (*this);
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
  }
}

void NTCPServer::Stop() {
  m_NTCPSessions.clear();
  if (m_IsRunning) {
    m_IsRunning = false;
    delete m_NTCPAcceptor;
    m_NTCPAcceptor = nullptr;
    delete m_NTCPV6Acceptor;
    m_NTCPV6Acceptor = nullptr;
    m_Service.stop();
    if (m_Thread) {
      m_Thread->join();
      delete m_Thread;
      m_Thread = nullptr;
    }
  }
}

void NTCPServer::Run() {
  while (m_IsRunning) {
    try {
      m_Service.run();
    } catch (std::exception& ex) {
      LogPrint("NTCP server: ", ex.what());
    }
  }
}

void NTCPServer::AddNTCPSession(
    std::shared_ptr<NTCPSession> session) {
  if (session) {
    std::unique_lock<std::mutex> l(m_NTCPSessionsMutex);
    m_NTCPSessions[session->GetRemoteIdentity().GetIdentHash()] = session;
  }
}

void NTCPServer::RemoveNTCPSession(
    std::shared_ptr<NTCPSession> session) {
  if (session) {
    std::unique_lock<std::mutex> l(m_NTCPSessionsMutex);
    m_NTCPSessions.erase(session->GetRemoteIdentity().GetIdentHash());
  }
}

std::shared_ptr<NTCPSession> NTCPServer::FindNTCPSession(
    const i2p::data::IdentHash& ident) {
  std::unique_lock<std::mutex> l(m_NTCPSessionsMutex);
  auto it = m_NTCPSessions.find(ident);
  if (it != m_NTCPSessions.end())
    return it->second;
  return nullptr;
}

void NTCPServer::HandleAccept(
    std::shared_ptr<NTCPSession> conn,
    const boost::system::error_code& error) {
  if (!error) {
    boost::system::error_code ec;
    auto ep = conn->GetSocket().remote_endpoint(ec);
    if (!ec) {
      LogPrint(eLogInfo, "Connected from ", ep);
      auto it = m_BanList.find(ep.address());
      if (it != m_BanList.end()) {
        uint32_t ts = i2p::util::GetSecondsSinceEpoch();
        if (ts < it->second) {
          LogPrint(eLogInfo,
              ep.address(), " is banned for ", it->second - ts, " more seconds");
          conn = nullptr;
        } else {
          m_BanList.erase(it);
        }
      }
      if (conn)
        conn->ServerLogin();
    } else {
      LogPrint(eLogError, "Connected from error ", ec.message());
    }
  }
  if (error != boost::asio::error::operation_aborted) {
    conn = std::make_shared<NTCPSession> (*this);
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
    const boost::system::error_code& error) {
  if (!error) {
    boost::system::error_code ec;
    auto ep = conn->GetSocket().remote_endpoint(ec);
    if (!ec) {
      LogPrint(eLogInfo, "Connected from ", ep);
      auto it = m_BanList.find(ep.address());
      if (it != m_BanList.end()) {
        uint32_t ts = i2p::util::GetSecondsSinceEpoch();
        if (ts < it->second) {
          LogPrint(eLogInfo,
              ep.address(), " is banned for ", it->second - ts, " more seconds");
          conn = nullptr;
        } else {
          m_BanList.erase(it);
        }
      }
      if (conn)
        conn->ServerLogin();
    } else {
      LogPrint(eLogError, "Connected from error ", ec.message());
    }
  }
  if (error != boost::asio::error::operation_aborted) {
    conn = std::make_shared<NTCPSession> (*this);
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
    int port,
    std::shared_ptr<NTCPSession> conn) {
  LogPrint(eLogInfo, "Connecting to ", address , ":",  port);
  m_Service.post([conn, this]() {
      this->AddNTCPSession(conn);
    });
  conn->GetSocket().async_connect(
      boost::asio::ip::tcp::endpoint(
        address,
        port),
      std::bind(
        &NTCPServer::HandleConnect,
        this,
        std::placeholders::_1,
        conn));
}

void NTCPServer::HandleConnect(
    const boost::system::error_code& ecode,
    std::shared_ptr<NTCPSession> conn) {
  if (ecode) {
    LogPrint(eLogError, "Connect error: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      i2p::data::netdb.SetUnreachable(
          conn->GetRemoteIdentity().GetIdentHash(),
          true);
    conn->Terminate();
  } else {
    LogPrint(eLogInfo, "Connected to ",  conn->GetSocket().remote_endpoint());
    if (conn->GetSocket().local_endpoint().protocol () ==
        boost::asio::ip::tcp::v6())  // ipv6
      context.UpdateNTCPV6Address(
          conn->GetSocket().local_endpoint().address());
    conn->ClientLogin();
  }
}

void NTCPServer::Ban(
    const boost::asio::ip::address& addr) {
  uint32_t ts = i2p::util::GetSecondsSinceEpoch();
  m_BanList[addr] = ts + NTCP_BAN_EXPIRATION_TIMEOUT;
  LogPrint(eLogInfo,
      addr, " has been banned for ", NTCP_BAN_EXPIRATION_TIMEOUT, " seconds");
}

}  // namespace transport
}  // namespace i2p

