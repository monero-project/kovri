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

#include "core/router/transports/impl.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <ostream>

#include "core/crypto/diffie_hellman.h"
#include "core/crypto/rand.h"

#include "core/router/context.h"
#include "core/router/i2np.h"
#include "core/router/net_db/impl.h"

#include "core/util/log.h"

namespace kovri {
namespace core {

DHKeysPairSupplier::DHKeysPairSupplier(
    std::size_t size)
    : m_QueueSize(size),
      m_IsRunning(false),
      m_Thread(nullptr) {}

DHKeysPairSupplier::~DHKeysPairSupplier() {
  Stop();
}

void DHKeysPairSupplier::Start() {
  LogPrint(eLogDebug, "DHKeysPairSupplier: starting");
  m_IsRunning = true;
  m_Thread =
    std::make_unique<std::thread>(
        std::bind(
            &DHKeysPairSupplier::Run,
            this));
}

void DHKeysPairSupplier::Stop() {
  m_IsRunning = false;
  m_Acquired.notify_one();
  if (m_Thread) {
    m_Thread->join();
    m_Thread.reset(nullptr);
  }
}

void DHKeysPairSupplier::Run() {
  LogPrint(eLogDebug, "DHKeysPairSupplier: running");
  while (m_IsRunning) {
    if (m_QueueSize > m_Queue.size ())
      CreateDHKeysPairs(m_QueueSize - m_Queue.size());
    std::unique_lock<std::mutex> l(m_AcquiredMutex);
    m_Acquired.wait(l);  // wait for element gets acquired
  }
}

void DHKeysPairSupplier::CreateDHKeysPairs(
    std::size_t num) {
  LogPrint(eLogDebug, "DHKeysPairSupplier: creating");
  for (std::size_t i = 0; i < num; i++) {
    auto pair = std::make_unique<kovri::core::DHKeysPair>();
    kovri::core::DiffieHellman().GenerateKeyPair(
        pair->private_key.data(),
        pair->public_key.data());
    std::unique_lock<std::mutex>  l(m_AcquiredMutex);
    m_Queue.push(std::move(pair));
  }
}

std::unique_ptr<DHKeysPair> DHKeysPairSupplier::Acquire() {
  LogPrint(eLogDebug, "DHKeysPairSupplier: acquiring");
  std::unique_lock<std::mutex> l(m_AcquiredMutex);
  if (!m_Queue.empty()) {
    auto pair = std::move(m_Queue.front());
    m_Queue.pop();
    m_Acquired.notify_one();
    return pair;
  }
  l.unlock();
  // queue is empty, create new key pair
  auto pair = std::make_unique<DHKeysPair>();
  kovri::core::DiffieHellman().GenerateKeyPair(
      pair->private_key.data(),
      pair->public_key.data());
  return pair;
}

void DHKeysPairSupplier::Return(
    std::unique_ptr<DHKeysPair> pair) {
  LogPrint(eLogDebug, "DHKeysPairSupplier: returning");
  std::unique_lock<std::mutex> l(m_AcquiredMutex);
  m_Queue.push(std::move(pair));
}

void Peer::Done() {
  for (auto it : sessions)
    it->Done();
}

Transports transports;

Transports::Transports()
    : m_IsRunning(false),
      m_Thread(nullptr),
      m_Work(m_Service),
      m_PeerCleanupTimer(m_Service),
      m_NTCPServer(nullptr),
      m_SSUServer(nullptr),
      // TODO(unassigned): get rid of magic number
      m_DHKeysPairSupplier(5),  // 5 pre-generated keys
      m_TotalSentBytes(0),
      m_TotalReceivedBytes(0),
      m_InBandwidth(0),
      m_OutBandwidth(0),
      m_LastInBandwidthUpdateBytes(0),
      m_LastOutBandwidthUpdateBytes(0),
      m_LastBandwidthUpdateTime(0) {}

Transports::~Transports() {
  Stop();
}

void Transports::Start() {
  LogPrint(eLogDebug, "Transports: starting");
#ifdef USE_UPNP
  m_UPnP.Start();
  LogPrint(eLogInfo, "Transports: UPnP started");
#endif
  m_DHKeysPairSupplier.Start();
  m_IsRunning = true;
  m_Thread = std::make_unique<std::thread>(std::bind(&Transports::Run, this));
  // create acceptors
  const auto addresses = context.GetRouterInfo().GetAddresses();
  for (const auto& address : addresses) {
    LogPrint("Transports: creating servers for address ", address.host);
    if (address.transport_style ==
        kovri::core::RouterInfo::eTransportNTCP && address.host.is_v4()) {
      if (!m_NTCPServer) {
        LogPrint(eLogInfo, "Transports: TCP listening on port ", address.port);
        m_NTCPServer = std::make_unique<NTCPServer>(m_Service, address.port);
        m_NTCPServer->Start();
      } else {
        LogPrint(eLogError, "Transports: TCP server already exists");
      }
    }
    if (address.transport_style ==
        kovri::core::RouterInfo::eTransportSSU && address.host.is_v4()) {
      if (!m_SSUServer) {
        LogPrint(eLogInfo, "Transports: UDP listening on port ", address.port);
        m_SSUServer = std::make_unique<SSUServer>(m_Service, address.port);
        m_SSUServer->Start();
        DetectExternalIP();
      } else {
        LogPrint(eLogError, "Transports: SSU server already exists");
      }
    }
  }
  m_PeerCleanupTimer.expires_from_now(
      boost::posix_time::seconds(
          5 * SESSION_CREATION_TIMEOUT));   // TODO(unassigned): why 5 seconds
  m_PeerCleanupTimer.async_wait(
      std::bind(
          &Transports::HandlePeerCleanupTimer,
          this,
          std::placeholders::_1));
}

void Transports::Stop() {
#ifdef USE_UPNP
  m_UPnP.Stop();
#endif
  m_PeerCleanupTimer.cancel();
  m_Peers.clear();
  if (m_SSUServer) {
    m_SSUServer->Stop();
    m_SSUServer.reset(nullptr);
  }
  if (m_NTCPServer) {
    m_NTCPServer->Stop();
    m_NTCPServer.reset(nullptr);
  }
  m_DHKeysPairSupplier.Stop();
  m_IsRunning = false;
  m_Service.stop();
  if (m_Thread) {
    m_Thread->join();
    m_Thread.reset(nullptr);
  }
}

void Transports::Run() {
  LogPrint(eLogDebug, "Transports: running");
  while (m_IsRunning) {
    try {
      m_Service.run();
    } catch (std::exception& ex) {
      LogPrint("Transports: Run(): '", ex.what(), "'");
    }
  }
}

void Transports::UpdateBandwidth() {
  LogPrint(eLogDebug, "Transports: updating bandwidth");
  const std::uint64_t ts = kovri::core::GetMillisecondsSinceEpoch();
  if (m_LastBandwidthUpdateTime > 0) {
    auto delta = ts - m_LastBandwidthUpdateTime;
    if (delta > 0) {
      // Bandwidth in bytes per second
      m_InBandwidth =
        (m_TotalReceivedBytes - m_LastInBandwidthUpdateBytes) * 1000 / delta;
      m_OutBandwidth =
        (m_TotalSentBytes - m_LastOutBandwidthUpdateBytes) * 1000 / delta;
    }
  }
  m_LastBandwidthUpdateTime = ts;
  m_LastInBandwidthUpdateBytes = m_TotalReceivedBytes;
  m_LastOutBandwidthUpdateBytes = m_TotalSentBytes;
}

bool Transports::IsBandwidthExceeded() const {
  if (std::max(m_InBandwidth, m_OutBandwidth) > LOW_BANDWIDTH_LIMIT) {
    LogPrint(eLogDebug, "Transports: bandwidth has been exceeded");
    return true;
  }
  if (kovri::context.GetRouterInfo().IsHighBandwidth())
    LogPrint(eLogDebug, "Transports: bandwidth has not been exceeded");
  return false;
}

void Transports::SendMessage(
    const kovri::core::IdentHash& ident,
    std::shared_ptr<kovri::core::I2NPMessage> msg) {
  SendMessages(
      ident,
      std::vector<std::shared_ptr<kovri::core::I2NPMessage>> {msg});
}

void Transports::SendMessages(
    const kovri::core::IdentHash& ident,
    const std::vector<std::shared_ptr<kovri::core::I2NPMessage>>& msgs) {
  LogPrint(eLogDebug, "Transports: sending messages");
  m_Service.post(
      std::bind(
          &Transports::PostMessages,
          this,
          ident,
          msgs));
}

void Transports::PostMessages(
    kovri::core::IdentHash ident,
    std::vector<std::shared_ptr<kovri::core::I2NPMessage>> msgs) {
  LogPrint(eLogDebug, "Transports: posting messages");
  if (ident == kovri::context.GetRouterInfo().GetIdentHash()) {
    // we send it to ourself
    for (auto msg : msgs)
      kovri::core::HandleI2NPMessage(msg);
    return;
  }
  auto it = m_Peers.find(ident);
  if (it == m_Peers.end()) {
    bool connected = false;
    try {
      auto router = kovri::core::netdb.FindRouter(ident);
      it = m_Peers.insert(std::make_pair(
          ident,
          Peer{ 0, router, {}, kovri::core::GetSecondsSinceEpoch(), {} })).first;
      connected = ConnectToPeer(ident, it->second);
    } catch (std::exception& ex) {
      LogPrint(eLogError, "Transports: PostMessages(): '", ex.what(), "'");
    }
    if (!connected)
      return;
  }
  if (!it->second.sessions.empty()) {
    it->second.sessions.front()->SendI2NPMessages(msgs);
  } else {
    for (auto msg : msgs)
      it->second.delayed_messages.push_back(msg);
  }
}

bool Transports::ConnectToPeer(
    const kovri::core::IdentHash& ident,
    Peer& peer) {
  if (!peer.router) {  // We don't have the RI
    LogPrint(eLogDebug, "Transports: RI not found, requesting");
    kovri::core::netdb.RequestDestination(
        ident,
        std::bind(
            &Transports::RequestComplete,
            this,
            std::placeholders::_1,
            ident));
    return true;
  }

  // We have the RI, connect to it
  LogPrint(eLogDebug,
      "Transports: connecting to peer",
      GetFormattedSessionInfo(peer.router));

  // If only NTCP or SSU is supported, always try the supported transport
  // If both are supported, SSU is used for the second attempt
  // Peers that fail on all supported transports are removed
  bool result = false;
  if (!m_NTCPServer && m_SSUServer)
    result = ConnectToPeerSSU(peer);
  else if (m_NTCPServer && !m_SSUServer)
    result = ConnectToPeerNTCP(ident, peer);
  else if (peer.num_attempts == 0)
    result = ConnectToPeerNTCP(ident, peer);
  else if (peer.num_attempts == 1)
    result = ConnectToPeerSSU(peer);

  // Increase the number of attempts (even when no transports are available)
  ++peer.num_attempts;
  if (result)
    return true;

  // Couldn't connect, get rid of this peer
  LogPrint(eLogError,
      "Transports:", GetFormattedSessionInfo(peer.router),
      "no NTCP/SSU address available");
  peer.Done();
  m_Peers.erase(ident);
  return false;
}

bool Transports::ConnectToPeerNTCP(
    const kovri::core::IdentHash& ident,
    Peer& peer) {
  if (!m_NTCPServer)
    return false;  // NTCP not supported

  LogPrint(eLogDebug,
      "Transports: attempting NTCP for peer",
      GetFormattedSessionInfo(peer.router));

  const auto address = peer.router->GetNTCPAddress(!context.SupportsV6());

  // No NTCP address found
  if (!address)
    return false;

  if (!address->host.is_unspecified()) {
    if (!peer.router->UsesIntroducer() && !peer.router->IsUnreachable()) {
      auto s = std::make_shared<NTCPSession>(*m_NTCPServer, peer.router);
      m_NTCPServer->Connect(address->host, address->port, s);
      return true;
    }
  } else {  // we don't have address
    if (address->address_string.length() > 0) {  // trying to resolve
      LogPrint(eLogInfo,
          "Transports: NTCP resolving ", address->address_string);
          NTCPResolve(address->address_string, ident);
      return true;
    }
  }
  return false;
}

bool Transports::ConnectToPeerSSU(Peer& peer) {
  if (!m_SSUServer)
    return false;  // SSU not supported

  LogPrint(eLogDebug,
    "Transports: attempting SSU for peer",
    GetFormattedSessionInfo(peer.router));

  if (m_SSUServer->GetSession(peer.router))
    return true;

  return false;
}



void Transports::RequestComplete(
    std::shared_ptr<const kovri::core::RouterInfo> router,
    const kovri::core::IdentHash& ident) {
  m_Service.post(
      std::bind(
          &Transports::HandleRequestComplete,
          this,
          router,
          ident));
}

void Transports::HandleRequestComplete(
    std::shared_ptr<const kovri::core::RouterInfo> router,
    const kovri::core::IdentHash& ident) {
  auto it = m_Peers.find(ident);
  if (it != m_Peers.end()) {
    if (router) {
      LogPrint(eLogInfo,
          "Transports: router ", router->GetIdentHashAbbreviation(),
          " found, trying to connect");
      it->second.router = router;
      ConnectToPeer(ident, it->second);
    } else {
      LogPrint("Transports: router not found, failed to send messages");
      m_Peers.erase(it);
    }
  }
}

void Transports::NTCPResolve(
    const std::string& addr,
    const kovri::core::IdentHash& ident) {
  auto resolver =
    std::make_shared<boost::asio::ip::tcp::resolver>(m_Service);
  resolver->async_resolve(
      boost::asio::ip::tcp::resolver::query(
          addr,
          ""),
      std::bind(
          &Transports::HandleNTCPResolve,
          this,
          std::placeholders::_1,
          std::placeholders::_2,
          ident,
          resolver));
}

void Transports::HandleNTCPResolve(
    const boost::system::error_code& ecode,
    boost::asio::ip::tcp::resolver::iterator it,
    kovri::core::IdentHash ident,
    std::shared_ptr<boost::asio::ip::tcp::resolver>) {
  auto it1 = m_Peers.find(ident);
  if (it1 != m_Peers.end()) {
    auto& peer = it1->second;
    if (!ecode && peer.router) {
      auto address = (*it).endpoint().address();
      LogPrint(eLogInfo,
          "Transports: ", (*it).host_name(),
          " has been resolved to ", address);
      auto addr = peer.router->GetNTCPAddress();
      if (addr) {
        auto s = std::make_shared<NTCPSession>(*m_NTCPServer, peer.router);
        m_NTCPServer->Connect(address, addr->port, s);
        return;
      }
    }
    LogPrint(eLogError,
        "Transports: unable to resolve NTCP address: ", ecode.message());
    m_Peers.erase(it1);
  }
}

// TODO(unassigned): why is this never called anywhere?
void Transports::CloseSession(
    std::shared_ptr<const kovri::core::RouterInfo> router) {
  if (!router)
    return;

  LogPrint(eLogDebug,
      "Transports: closing session for [",
      router->GetIdentHashAbbreviation(), "]");
  m_Service.post(
      std::bind(
          &Transports::PostCloseSession,
          this,
          router));
}

void Transports::PostCloseSession(
    std::shared_ptr<const kovri::core::RouterInfo> router) {
  auto ssu_session =
    m_SSUServer ? m_SSUServer->FindSession(router) : nullptr;
  // try SSU first
  if (ssu_session) {
    m_SSUServer->DeleteSession(ssu_session);
    LogPrint(eLogInfo,
        "Transports: SSU session [",
        router->GetIdentHashAbbreviation(), "] closed");
  }
  auto ntcp_session = m_NTCPServer ?
      m_NTCPServer->FindNTCPSession(router->GetIdentHash()) : nullptr;
  if (ntcp_session) {
    m_NTCPServer->RemoveNTCPSession(ntcp_session);
    LogPrint(eLogInfo,
        "Transports: NTCP session [",
        router->GetIdentHashAbbreviation(), "] closed");
  }
}

void Transports::DetectExternalIP() {
  LogPrint(eLogDebug, "Transports: detecting external IP");

  if (!m_SSUServer) {  // SSU not supported
    LogPrint(eLogError,
        "Transports: can't detect external IP, SSU is not available");
    return;
  }

  kovri::context.SetStatus(eRouterStatusTesting);
  // TODO(unassigned): Why 5 times? (make constant)
  for (int i = 0; i < 5; i++) {
    auto router = kovri::core::netdb.GetRandomPeerTestRouter();
    if (router && router->IsSSU()) {
      m_SSUServer->GetSession(router, true);  // peer test
    } else {
      // if not peer test capable routers found pick any
      router = kovri::core::netdb.GetRandomRouter();
      if (router && router->IsSSU())
        m_SSUServer->GetSession(router);  // no peer test
    }
  }
}

std::unique_ptr<DHKeysPair> Transports::GetNextDHKeysPair() {
  LogPrint(eLogDebug, "Transports: getting next DH keys pair");
  return m_DHKeysPairSupplier.Acquire();
}

void Transports::ReuseDHKeysPair(
    std::unique_ptr<DHKeysPair> pair) {
  LogPrint(eLogDebug, "Transports: reusing DH keys pair");
  m_DHKeysPairSupplier.Return(std::move(pair));
}

void Transports::PeerConnected(
    std::shared_ptr<TransportSession> session) {
  auto router = session->GetRemoteRouter();
  LogPrint(eLogDebug,
      "Transports:", GetFormattedSessionInfo(router), "connecting");
  m_Service.post([session, this]() {
    auto ident = session->GetRemoteIdentity().GetIdentHash();
    auto it = m_Peers.find(ident);
    if (it != m_Peers.end()) {
      it->second.sessions.push_back(session);
      session->SendI2NPMessages(it->second.delayed_messages);
      it->second.delayed_messages.clear();
    } else {  // incoming connection
      m_Peers.insert(
          std::make_pair(
              ident,
              Peer{ 0, nullptr, { session },
              kovri::core::GetSecondsSinceEpoch(), {} }));
    }
  });
}

void Transports::PeerDisconnected(
    std::shared_ptr<TransportSession> session) {
  LogPrint(eLogDebug, "Transports: disconnecting peer");
  m_Service.post([session, this]() {
    auto ident = session->GetRemoteIdentity().GetIdentHash();
    auto it = m_Peers.find(ident);
    if (it != m_Peers.end()) {
      it->second.sessions.remove(session);
      if (it->second.sessions.empty()) {  // TODO(unassigned): why?
        if (it->second.delayed_messages.size() > 0)
          ConnectToPeer(ident, it->second);
        else
          m_Peers.erase(it);
      }
    }
  });
}

bool Transports::IsConnected(
    const kovri::core::IdentHash& ident) const {
  LogPrint(eLogDebug, "Transports: testing if connected");
  auto it = m_Peers.find(ident);
  if (it != m_Peers.end()) {
    LogPrint(eLogDebug, "Transports: we are connected");
    return true;
  }
  LogPrint(eLogDebug, "Transports: we are not connected");
  return false;
}

void Transports::HandlePeerCleanupTimer(
    const boost::system::error_code& ecode) {
  LogPrint(eLogDebug, "Transports: handling peer cleanup timer");
  if (ecode != boost::asio::error::operation_aborted) {
    auto ts = kovri::core::GetSecondsSinceEpoch();
    for (auto it = m_Peers.begin(); it != m_Peers.end();) {
      if (it->second.sessions.empty() &&
          ts > it->second.creation_time + SESSION_CREATION_TIMEOUT) {
        LogPrint(eLogError,
            "Transports: session to peer",
            GetFormattedSessionInfo(it->second.router),
            "has not been created in ", SESSION_CREATION_TIMEOUT, " seconds");
        it = m_Peers.erase(it);
      } else {
        it++;
      }
    }
    UpdateBandwidth();  // TODO(unassigned): use separate timer(s) for it
    // if still testing, repeat peer test
    if (kovri::context.GetStatus() == eRouterStatusTesting)
      DetectExternalIP();
    m_PeerCleanupTimer.expires_from_now(
        boost::posix_time::seconds(
            5 * SESSION_CREATION_TIMEOUT));
    m_PeerCleanupTimer.async_wait(
        std::bind(
            &Transports::HandlePeerCleanupTimer,
            this,
            std::placeholders::_1));
  }
}

std::shared_ptr<const kovri::core::RouterInfo> Transports::GetRandomPeer() const {
  LogPrint(eLogDebug, "Transports: getting random peer");
  if (m_Peers.empty())  // ensure m.Peers.size() >= 1
    return nullptr;
  std::size_t s = m_Peers.size();
  auto it = m_Peers.begin();
  std::advance(
      it,
      kovri::core::RandInRange<std::size_t>(0, s - 1));
  return it->second.router;
}

std::string Transports::GetFormattedSessionInfo(
    std::shared_ptr<const kovri::core::RouterInfo>& router) const {
  if (router) {
    std::ostringstream info;
    info << " [" << router->GetIdentHashAbbreviation() << "] ";
    return info.str();
  }
  return "[hash unavailable]";
}


}  // namespace core
}  // namespace kovri

