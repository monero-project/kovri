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

#ifndef SRC_CORE_ROUTER_TRANSPORTS_IMPL_H_
#define SRC_CORE_ROUTER_TRANSPORTS_IMPL_H_

#include <boost/asio.hpp>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "core/router/i2np.h"
#include "core/router/identity.h"
#include "core/router/info.h"
#include "core/router/transports/ntcp/server.h"
#include "core/router/transports/ntcp/session.h"
#include "core/router/transports/session.h"
#include "core/router/transports/ssu/server.h"
#include "core/router/transports/upnp.h"

#include "core/util/exception.h"

namespace kovri {
namespace core {

/// @class DHKeysPairSupplier
/// @brief Pregenerates Diffie-Hellman key pairs for use in key exchange
/// TODO(unassigned): Does this really need to run on a separate thread?
class DHKeysPairSupplier {
 public:
  DHKeysPairSupplier(
      std::size_t size);

  ~DHKeysPairSupplier();

  void Start();

  void Stop();

  std::unique_ptr<DHKeysPair> Acquire();

  void Return(
      std::unique_ptr<DHKeysPair> pair);

 private:
  void Run();

  void CreateDHKeysPairs(
      std::size_t num);

 private:
  const std::size_t m_QueueSize;
  bool m_IsRunning;
  std::queue<std::unique_ptr<DHKeysPair>> m_Queue;
  std::unique_ptr<std::thread> m_Thread;
  std::condition_variable m_Acquired;
  std::mutex m_AcquiredMutex;
  core::Exception m_Exception;
};

/// @class Peer
/// @brief Stores information about transport peers.
struct Peer {
  std::size_t num_attempts{};
  std::shared_ptr<const kovri::core::RouterInfo> router;
  std::list<std::shared_ptr<TransportSession>> sessions;
  std::uint64_t creation_time{};  ///< Must be set as time since epoch, in implementation
  std::vector<std::shared_ptr<kovri::core::I2NPMessage>> delayed_messages;

  void Done();
};

const std::size_t SESSION_CREATION_TIMEOUT = 10;  // in seconds
const std::uint32_t LOW_BANDWIDTH_LIMIT = 32 * 1024;  // 32KBps

/// @class Transports
/// @brief Provides functions to pass messages to a given peer.
///        Manages the SSU and NTCP transports.
class Transports {
 public:
  Transports();

  ~Transports();

  /// @brief Starts SSU and NTCP server instances, as well as the cleanup timer.
  ///        If enabled, the UPnP service is also started.
  void Start();

  /// @brief Stops all services ran by this Transports object.
  void Stop();

  /// @return a reference to the boost::asio::io_serivce that is used by this
  ///         Transports object
  boost::asio::io_service& GetService() {
    return m_Service;
  }

  /// @return a pointer to a Diffie-Hellman pair
  std::unique_ptr<kovri::core::DHKeysPair> GetNextDHKeysPair();

  /// @brief Asynchronously sends a message to a peer.
  /// @param ident the router hash of the remote peer
  /// @param msg the I2NP message to deliver
  void SendMessage(
      const kovri::core::IdentHash& ident,
      std::shared_ptr<kovri::core::I2NPMessage> msg);

  /// @brief Asynchronously sends one or more messages to a peer.
  /// @param ident the router hash of the remote peer
  /// @param msgs the I2NP messages to deliver
  void SendMessages(
      const kovri::core::IdentHash& ident,
      const std::vector<std::shared_ptr<kovri::core::I2NPMessage>>& msgs);

  /// @brief Asynchronously close all transport sessions to the given router.
  /// @param router the kovri::core::RouterInfo of the router to disconnect from
  /// @note if router is nullptr, nothing happens
  void CloseSession(
      std::shared_ptr<const kovri::core::RouterInfo> router);

  /// @brief Informs this Transports object that a new peer has connected
  ///        to us
  /// @param session the new session
  void PeerConnected(
      std::shared_ptr<TransportSession> session);

  /// @brief Informs this Transports object that a peer has disconnected
  ///        from us
  /// @param session the session that has ended
  void PeerDisconnected(
      std::shared_ptr<TransportSession> session);

  bool IsConnected(
      const kovri::core::IdentHash& ident) const;

  void UpdateSentBytes(
      std::uint64_t num_bytes) {
    m_TotalSentBytes += num_bytes;
  }

  void UpdateReceivedBytes(
      std::uint64_t num_bytes) {
    m_TotalReceivedBytes += num_bytes;
  }

  std::uint64_t GetTotalSentBytes() const {
    return m_TotalSentBytes;
  }

  std::uint64_t GetTotalReceivedBytes() const {
    return m_TotalReceivedBytes;
  }

  // bytes per second
  std::uint32_t GetInBandwidth() const {
    return m_InBandwidth;
  }

  // bytes per second
  std::uint32_t GetOutBandwidth() const {
    return m_OutBandwidth;
  }

  bool IsBandwidthExceeded() const;

  std::size_t GetNumPeers() const {
    return m_Peers.size();
  }

  std::shared_ptr<const kovri::core::RouterInfo> GetRandomPeer() const;

  /// @return Log-formatted string of session info
  std::string GetFormattedSessionInfo(
      std::shared_ptr<const kovri::core::RouterInfo>& router) const;

 private:
  void Run();

  void RequestComplete(
      std::shared_ptr<const kovri::core::RouterInfo> router,
      const kovri::core::IdentHash& ident);

  void HandleRequestComplete(
      std::shared_ptr<const kovri::core::RouterInfo> router,
      const kovri::core::IdentHash& ident);

  void PostMessages(
      kovri::core::IdentHash ident,
      std::vector<std::shared_ptr<kovri::core::I2NPMessage>> msgs);

  void PostCloseSession(
      std::shared_ptr<const kovri::core::RouterInfo> router);

  bool ConnectToPeer(
      const kovri::core::IdentHash& ident, Peer& peer);

  bool ConnectToPeerNTCP(Peer& peer);
  bool ConnectToPeerSSU(Peer& peer);

  void HandlePeerCleanupTimer(
      const boost::system::error_code& ecode);

  void UpdateBandwidth();

  void DetectExternalIP();

 private:
  bool m_IsRunning;

  std::unique_ptr<std::thread> m_Thread;
  boost::asio::io_service m_Service;
  boost::asio::io_service::work m_Work;
  boost::asio::deadline_timer m_PeerCleanupTimer;

  std::unique_ptr<NTCPServer> m_NTCPServer;
  std::unique_ptr<SSUServer> m_SSUServer;

  std::map<kovri::core::IdentHash, Peer> m_Peers;

  DHKeysPairSupplier m_DHKeysPairSupplier;

  std::atomic<uint64_t> m_TotalSentBytes, m_TotalReceivedBytes;

  std::uint32_t m_InBandwidth, m_OutBandwidth;
  std::uint64_t m_LastInBandwidthUpdateBytes, m_LastOutBandwidthUpdateBytes;
  std::uint64_t m_LastBandwidthUpdateTime;

  UPnP m_UPnP;

 public:
  const decltype(m_Peers)& GetPeers() const {
    return m_Peers;
  }
};

extern Transports transports;

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_TRANSPORTS_IMPL_H_
