/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
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
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#include "Transports.h"

#include <algorithm>
#include <string>
#include <vector>

#include "I2NPProtocol.h"
#include "NetworkDatabase.h"
#include "RouterContext.h"
#include "crypto/DiffieHellman.h"
#include "crypto/Rand.h"
#include "util/Log.h"

namespace i2p {
namespace transport {

DHKeysPairSupplier::DHKeysPairSupplier(
    int size)
    : m_QueueSize(size),
      m_IsRunning(false),
      m_Thread(nullptr) {}

DHKeysPairSupplier::~DHKeysPairSupplier() {
  Stop();
}

void DHKeysPairSupplier::Start() {
  m_IsRunning = true;
  m_Thread =
    new std::thread(
        std::bind(
          &DHKeysPairSupplier::Run,
          this));
}

void DHKeysPairSupplier::Stop() {
  m_IsRunning = false;
  m_Acquired.notify_one();
  if (m_Thread) {
    m_Thread->join();
    delete m_Thread;
    m_Thread = 0;
  }
}

void DHKeysPairSupplier::Run() {
  while (m_IsRunning) {
    int num;
    while ((num = m_QueueSize - m_Queue.size ()) > 0)
      CreateDHKeysPairs(num);
    std::unique_lock<std::mutex> l(m_AcquiredMutex);
    m_Acquired.wait(l);  // wait for element gets acquired
  }
}

void DHKeysPairSupplier::CreateDHKeysPairs(
    int num) {
  if (num > 0) {
    for (int i = 0; i < num; i++) {
      i2p::transport::DHKeysPair* pair =
        new i2p::transport::DHKeysPair();
      i2p::crypto::DiffieHellman().GenerateKeyPair(
          pair->privateKey,
          pair->publicKey);
      std::unique_lock<std::mutex>  l(m_AcquiredMutex);
      m_Queue.push(pair);
    }
  }
}

DHKeysPair* DHKeysPairSupplier::Acquire() {
  std::unique_lock<std::mutex> l(m_AcquiredMutex);
  if (!m_Queue.empty()) {
    auto pair = m_Queue.front();
    m_Queue.pop();
    m_Acquired.notify_one();
    return pair;
  }
  l.unlock();

  // queue is empty, create new key pair
  DHKeysPair* pair = new DHKeysPair();
  i2p::crypto::DiffieHellman().GenerateKeyPair(
      pair->privateKey,
      pair->publicKey);
  return pair;
}

void DHKeysPairSupplier::Return(
    DHKeysPair* pair) {
  std::unique_lock<std::mutex>  l(m_AcquiredMutex);
  m_Queue.push(pair);
}

Transports transports;

Transports::Transports()
    : m_IsRunning(false),
      m_Thread(nullptr),
      m_Work(m_Service),
      m_PeerCleanupTimer(m_Service),
      m_NTCPServer(nullptr),
      m_SSUServer(nullptr),
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
#ifdef USE_UPNP
  m_UPnP.Start();
  LogPrint(eLogInfo, "Transports: UPnP started");
#endif
  m_DHKeysPairSupplier.Start();
  m_IsRunning = true;
  m_Thread =
    new std::thread(
      std::bind(
        &Transports::Run,
        this));
  // create acceptors
  auto addresses = context.GetRouterInfo().GetAddresses();
  for (auto& address : addresses) {
    if (!m_NTCPServer) {
      m_NTCPServer = new NTCPServer(address.port);
      m_NTCPServer->Start();
    }
    if (address.transportStyle ==
        i2p::data::RouterInfo::eTransportSSU &&
        address.host.is_v4()) {
      if (!m_SSUServer) {
        m_SSUServer = new SSUServer(address.port);
        LogPrint("Transports: UDP listening on port ", address.port);
        m_SSUServer->Start();
        DetectExternalIP();
      } else {
        LogPrint("Transports: SSU server already exists");
      }
    }
  }
  m_PeerCleanupTimer.expires_from_now(
      boost::posix_time::seconds(
        5 * SESSION_CREATION_TIMEOUT));
  m_PeerCleanupTimer.async_wait(
      std::bind(
        &Transports::HandlePeerCleanupTimer,
        this,
        std::placeholders::_1));
}

void Transports::Stop() {
#ifdef USE_UPNP
  m_UPnP.Stop();
  LogPrint(eLogInfo, "Transports: UPnP stopped");
#endif
  m_PeerCleanupTimer.cancel();
  m_Peers.clear();
  if (m_SSUServer) {
    m_SSUServer->Stop();
    delete m_SSUServer;
    m_SSUServer = nullptr;
  }
  if (m_NTCPServer) {
    m_NTCPServer->Stop();
    delete m_NTCPServer;
    m_NTCPServer = nullptr;
  }
  m_DHKeysPairSupplier.Stop();
  m_IsRunning = false;
  m_Service.stop();
  if (m_Thread) {
    m_Thread->join();
    delete m_Thread;
    m_Thread = nullptr;
  }
}

void Transports::Run() {
  while (m_IsRunning) {
    try {
      m_Service.run();
    } catch (std::exception& ex) {
      LogPrint("Transports::Run(): ", ex.what());
    }
  }
}

void Transports::UpdateBandwidth() {
  uint64_t ts = i2p::util::GetMillisecondsSinceEpoch();
  if (m_LastBandwidthUpdateTime > 0) {
    auto delta = ts - m_LastBandwidthUpdateTime;
    if (delta > 0) {
      m_InBandwidth =
        (m_TotalReceivedBytes - m_LastInBandwidthUpdateBytes) * 1000 / delta;  // per second
      m_OutBandwidth =
        (m_TotalSentBytes - m_LastOutBandwidthUpdateBytes) * 1000 / delta;  // per second
    }
  }
  m_LastBandwidthUpdateTime = ts;
  m_LastInBandwidthUpdateBytes = m_TotalReceivedBytes;
  m_LastOutBandwidthUpdateBytes = m_TotalSentBytes;
}

bool Transports::IsBandwidthExceeded() const {
  if (i2p::context.GetRouterInfo().IsHighBandwidth())
    return false;
  return std::max(m_InBandwidth, m_OutBandwidth) > LOW_BANDWIDTH_LIMIT;
}

void Transports::SendMessage(
    const i2p::data::IdentHash& ident,
    std::shared_ptr<i2p::I2NPMessage> msg) {
  SendMessages(ident, std::vector<std::shared_ptr<i2p::I2NPMessage> > {msg});
}

void Transports::SendMessages(
    const i2p::data::IdentHash& ident,
    const std::vector<std::shared_ptr<i2p::I2NPMessage> >& msgs) {
  m_Service.post(
      std::bind(
        &Transports::PostMessages,
        this,
        ident,
        msgs));
}

void Transports::PostMessages(
    i2p::data::IdentHash ident,
    std::vector<std::shared_ptr<i2p::I2NPMessage> > msgs) {
  if (ident == i2p::context.GetRouterInfo().GetIdentHash()) {
    // we send it to ourself
    for (auto it : msgs)
      i2p::HandleI2NPMessage(it);
    return;
  }
  auto it = m_Peers.find(ident);
  if (it == m_Peers.end()) {
    bool connected = false;
    try {
      auto r = i2p::data::netdb.FindRouter(ident);
      it = m_Peers.insert(
          std::make_pair(
            ident,
            Peer{ 0, r, {}, i2p::util::GetSecondsSinceEpoch(), {} })).first;
      connected = ConnectToPeer(ident, it->second);
    } catch (std::exception& ex) {
      LogPrint(eLogError, "Transports::PostMessages() ", ex.what());
    }
    if (!connected) return;
  }
  if (!it->second.sessions.empty()) {
    it->second.sessions.front()->SendI2NPMessages(msgs);
  } else {
    for (auto it1 : msgs)
      it->second.delayedMessages.push_back(it1);
  }
}

bool Transports::ConnectToPeer(
    const i2p::data::IdentHash& ident,
    Peer& peer) {
  // we have RI already
  if (peer.router) {
    // NTCP
    if (!peer.numAttempts) {
      peer.numAttempts++;
      auto address = peer.router->GetNTCPAddress(!context.SupportsV6());
      if (address) {
#if BOOST_VERSION >= 104900
        if (!address->host.is_unspecified())  // we have address now
#else
        boost::system::error_code ecode;
        address->host.to_string(ecode);
        if (!ecode)
#endif
        {
          if (!peer.router->UsesIntroducer() && !peer.router->IsUnreachable()) {
            auto s = std::make_shared<NTCPSession> (*m_NTCPServer, peer.router);
            m_NTCPServer->Connect(address->host, address->port, s);
            return true;
          }
        } else {  // we don't have address
          if (address->addressString.length() > 0) {  // trying to resolve
            LogPrint(eLogInfo, "Transports: resolving ", address->addressString);
            NTCPResolve(address->addressString, ident);
            return true;
          }
        }
      }
    } else if (peer.numAttempts == 1) {  // SSU
      peer.numAttempts++;
      if (m_SSUServer) {
        if (m_SSUServer->GetSession(peer.router))
          return true;
      }
    }
    LogPrint(eLogError, "Transports: no NTCP or SSU addresses available");
    peer.Done();
    m_Peers.erase(ident);
    return false;
  } else {  // otherwise request RI
    LogPrint("Transports: router not found, requesting");
    i2p::data::netdb.RequestDestination(
        ident,
        std::bind(
          &Transports::RequestComplete,
          this,
          std::placeholders::_1,
          ident));
  }
  return true;
}

void Transports::RequestComplete(
    std::shared_ptr<const i2p::data::RouterInfo> r,
    const i2p::data::IdentHash& ident) {
  m_Service.post(
      std::bind(
        &Transports::HandleRequestComplete,
        this,
        r,
        ident));
}

void Transports::HandleRequestComplete(
    std::shared_ptr<const i2p::data::RouterInfo> r,
    const i2p::data::IdentHash& ident) {
  auto it = m_Peers.find(ident);
  if (it != m_Peers.end()) {
    if (r) {
      LogPrint("Transports: router found, trying to connect");
      it->second.router = r;
      ConnectToPeer(ident, it->second);
    } else {
      LogPrint("Transports: router not found, failed to send messages");
      m_Peers.erase(it);
    }
  }
}

void Transports::NTCPResolve(
    const std::string& addr,
    const i2p::data::IdentHash& ident) {
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
    i2p::data::IdentHash ident,
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
        auto s = std::make_shared<NTCPSession> (*m_NTCPServer, peer.router);
        m_NTCPServer->Connect(address, addr->port, s);
        return;
      }
    }
    LogPrint(eLogError,
        "Transports: unable to resolve NTCP address: ", ecode.message());
    m_Peers.erase(it1);
  }
}

void Transports::CloseSession(
    std::shared_ptr<const i2p::data::RouterInfo> router) {
  if (!router)
    return;
  m_Service.post(
      std::bind(
        &Transports::PostCloseSession,
        this,
        router));
}

void Transports::PostCloseSession(
    std::shared_ptr<const i2p::data::RouterInfo> router) {
  auto ssuSession =
    m_SSUServer ? m_SSUServer->FindSession(router) : nullptr;
  // try SSU first
  if (ssuSession) {
    m_SSUServer->DeleteSession(ssuSession);
    LogPrint("Transports: SSU session closed");
  }
  // TODO(unassigned): delete NTCP
}

void Transports::DetectExternalIP() {
  if (m_SSUServer) {
    i2p::context.SetStatus(eRouterStatusTesting);
    for (int i = 0; i < 5; i++) {
      auto router = i2p::data::netdb.GetRandomPeerTestRouter();
      if (router  && router->IsSSU()) {
        m_SSUServer->GetSession(router, true);  // peer test
      } else {
        // if not peer test capable routers found pick any
        router = i2p::data::netdb.GetRandomRouter();
        if (router && router->IsSSU())
          m_SSUServer->GetSession(router);  // no peer test
      }
    }
  } else {
    LogPrint(eLogError,
        "Transports: can't detect external IP, SSU is not available");
  }
}

DHKeysPair* Transports::GetNextDHKeysPair() {
  return m_DHKeysPairSupplier.Acquire();
}

void Transports::ReuseDHKeysPair(DHKeysPair* pair) {
  m_DHKeysPairSupplier.Return(pair);
}

void Transports::PeerConnected(
    std::shared_ptr<TransportSession> session) {
  m_Service.post([session, this]() {
    auto ident = session->GetRemoteIdentity().GetIdentHash();
    auto it = m_Peers.find(ident);
    if (it != m_Peers.end()) {
      it->second.sessions.push_back(session);
      session->SendI2NPMessages(it->second.delayedMessages);
      it->second.delayedMessages.clear();
    } else {  // incoming connection
      m_Peers.insert(
          std::make_pair(
            ident,
            Peer{ 0, nullptr, { session },
            i2p::util::GetSecondsSinceEpoch(), {} }));
    }
  });
}

void Transports::PeerDisconnected(
    std::shared_ptr<TransportSession> session) {
  m_Service.post([session, this]() {
    auto ident = session->GetRemoteIdentity().GetIdentHash();
    auto it = m_Peers.find(ident);
    if (it != m_Peers.end()) {
      it->second.sessions.remove(session);
      if (it->second.sessions.empty()) {  // TODO(unassigned): why?
        if (it->second.delayedMessages.size() > 0)
          ConnectToPeer(ident, it->second);
        else
          m_Peers.erase(it);
      }
    }
  });
}

bool Transports::IsConnected(
    const i2p::data::IdentHash& ident) const {
  auto it = m_Peers.find(ident);
  return it != m_Peers.end();
}

void Transports::HandlePeerCleanupTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    auto ts = i2p::util::GetSecondsSinceEpoch();
    for (auto it = m_Peers.begin(); it != m_Peers.end();) {
      if (it->second.sessions.empty () &&
          ts > it->second.creationTime + SESSION_CREATION_TIMEOUT) {
        LogPrint(eLogError,
            "Transports: session to peer ", it->first.ToBase64(),
            " has not been created in ", SESSION_CREATION_TIMEOUT, " seconds");
        it = m_Peers.erase(it);
      } else {
        it++;
      }
    }
    UpdateBandwidth();  // TODO(unassigned): use separate timer(s) for it
    // if still testing,  repeat peer test
    if (i2p::context.GetStatus() == eRouterStatusTesting)
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

std::shared_ptr<const i2p::data::RouterInfo> Transports::GetRandomPeer() const {
  if (m_Peers.empty())  // ensure m.Peers.size() >= 1
    return nullptr;
  size_t s = m_Peers.size();
  auto it = m_Peers.begin();
  std::advance(
      it,
      i2p::crypto::RandInRange<size_t>(0, s - 1));

  return it->second.router;
}

}  // namespace transport
}  // namespace i2p

