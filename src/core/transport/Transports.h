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

#ifndef SRC_CORE_TRANSPORT_TRANSPORTS_H_
#define SRC_CORE_TRANSPORT_TRANSPORTS_H_

#include <boost/asio.hpp>

#include <cryptopp/osrng.h>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>
#include <list>

#include "I2NPProtocol.h"
#include "Identity.h"
#include "NTCP.h"
#include "NTCPSession.h"
#include "RouterInfo.h"
#include "SSU.h"
#include "TransportSession.h"

#ifdef USE_UPNP
#include "UPnP.h"
#endif

namespace i2p {
namespace transport {

class DHKeysPairSupplier {
 public:
  DHKeysPairSupplier(
      int size);
  ~DHKeysPairSupplier();

  void Start();

  void Stop();

  DHKeysPair* Acquire();

  void Return(
      DHKeysPair* pair);

 private:
  void Run();

  void CreateDHKeysPairs(
      int num);

 private:
  const int m_QueueSize;
  std::queue<DHKeysPair *> m_Queue;
  bool m_IsRunning;
  std::thread* m_Thread;
  std::condition_variable m_Acquired;
  std::mutex m_AcquiredMutex;
  CryptoPP::AutoSeededRandomPool m_Rnd;
};

struct Peer {
  int numAttempts;
  std::shared_ptr<const i2p::data::RouterInfo> router;
  std::list<std::shared_ptr<TransportSession> > sessions;
  uint64_t creationTime;
  std::vector<std::shared_ptr<i2p::I2NPMessage> > delayedMessages;
  void Done() {
    for (auto it : sessions)
      it->Done();
  }
};

const size_t SESSION_CREATION_TIMEOUT = 10;  // in seconds
const uint32_t LOW_BANDWIDTH_LIMIT = 32*1024;  // 32KBs

class Transports {
 public:
  Transports();
  ~Transports();

  void Start();

  void Stop();

  boost::asio::io_service& GetService() {
    return m_Service;
  }

  i2p::transport::DHKeysPair* GetNextDHKeysPair();

  void ReuseDHKeysPair(
      DHKeysPair* pair);

  void SendMessage(
      const i2p::data::IdentHash& ident,
      std::shared_ptr<i2p::I2NPMessage> msg);

  void SendMessages(
      const i2p::data::IdentHash& ident,
      const std::vector<std::shared_ptr<i2p::I2NPMessage> >& msgs);

  void CloseSession(
      std::shared_ptr<const i2p::data::RouterInfo> router);

  void PeerConnected(
      std::shared_ptr<TransportSession> session);

  void PeerDisconnected(
      std::shared_ptr<TransportSession> session);

  bool IsConnected(
      const i2p::data::IdentHash& ident) const;

  void UpdateSentBytes(
      uint64_t numBytes) {
    m_TotalSentBytes += numBytes;
  }

  void UpdateReceivedBytes(
      uint64_t numBytes) {
    m_TotalReceivedBytes += numBytes;
  }

  uint64_t GetTotalSentBytes() const {
    return m_TotalSentBytes;
  }

  uint64_t GetTotalReceivedBytes() const {
    return m_TotalReceivedBytes;
  }

  // bytes per second
  uint32_t GetInBandwidth() const {
    return m_InBandwidth;
  }

  // bytes per second
  uint32_t GetOutBandwidth() const {
    return m_OutBandwidth;
  }

  bool IsBandwidthExceeded() const;

  size_t GetNumPeers() const {
    return m_Peers.size();
  }

  std::shared_ptr<const i2p::data::RouterInfo> GetRandomPeer() const;

 private:
  void Run();

  void RequestComplete(
      std::shared_ptr<const i2p::data::RouterInfo> r,
      const i2p::data::IdentHash& ident);

  void HandleRequestComplete(
      std::shared_ptr<const i2p::data::RouterInfo> r,
      const i2p::data::IdentHash& ident);

  void PostMessages(
      i2p::data::IdentHash ident,
      std::vector<std::shared_ptr<i2p::I2NPMessage> > msgs);

  void PostCloseSession(
      std::shared_ptr<const i2p::data::RouterInfo> router);

  bool ConnectToPeer(
      const i2p::data::IdentHash& ident, Peer& peer);

  void HandlePeerCleanupTimer(
      const boost::system::error_code& ecode);

  void NTCPResolve(
      const std::string& addr,
      const i2p::data::IdentHash& ident);

  void HandleNTCPResolve(
      const boost::system::error_code& ecode,
      boost::asio::ip::tcp::resolver::iterator it,
      i2p::data::IdentHash ident,
      std::shared_ptr<boost::asio::ip::tcp::resolver> resolver);

  void UpdateBandwidth();

  void DetectExternalIP();

 private:
  bool m_IsRunning;
  std::thread * m_Thread;
  boost::asio::io_service m_Service;
  boost::asio::io_service::work m_Work;
  boost::asio::deadline_timer m_PeerCleanupTimer;

  NTCPServer* m_NTCPServer;
  SSUServer* m_SSUServer;
  std::map<i2p::data::IdentHash, Peer> m_Peers;

  DHKeysPairSupplier m_DHKeysPairSupplier;

  std::atomic<uint64_t> m_TotalSentBytes,
                        m_TotalReceivedBytes;
  uint32_t m_InBandwidth,
           m_OutBandwidth;

  uint64_t m_LastInBandwidthUpdateBytes,
           m_LastOutBandwidthUpdateBytes;

  uint64_t m_LastBandwidthUpdateTime;

#ifdef USE_UPNP
  UPnP m_UPnP;
#endif

 public:
  // for HTTP only
  const NTCPServer* GetNTCPServer() const {
    return m_NTCPServer;
  }
  const SSUServer* GetSSUServer() const {
    return m_SSUServer;
  }
  const decltype(m_Peers)& GetPeers() const {
    return m_Peers;
  }
};

extern Transports transports;

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_TRANSPORTS_H_

