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

#ifndef SRC_CORE_ROUTER_TRANSPORTS_SSU_SERVER_H_
#define SRC_CORE_ROUTER_TRANSPORTS_SSU_SERVER_H_

#include <boost/asio.hpp>

#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "core/crypto/aes.h"

#include "core/router/i2np.h"
#include "core/router/identity.h"
#include "core/router/info.h"
#include "core/router/transports/ssu/packet.h"
#include "core/router/transports/ssu/session.h"


namespace kovri {
namespace core {

struct RawSSUPacket {
  kovri::core::AESAlignedBuffer<SSUSize::RawPacketBuffer> buf;
  boost::asio::ip::udp::endpoint from;
  std::size_t len{};
};

class SSUServer {
 public:
  SSUServer(boost::asio::io_service& service, const std::size_t port);

  ~SSUServer();

  void Start();

  void Stop();

  std::shared_ptr<SSUSession> GetSession(
      const std::shared_ptr<const kovri::core::RouterInfo>& router,
      const bool peer_test = false);

  std::shared_ptr<SSUSession> FindSession(
      const std::shared_ptr<const kovri::core::RouterInfo>& router) const;

  std::shared_ptr<SSUSession> FindSession(
      const boost::asio::ip::udp::endpoint& ep) const;

  std::shared_ptr<SSUSession> GetRandomEstablishedSession(
      const std::shared_ptr<const SSUSession>& excluded);

  void DeleteSession(const std::shared_ptr<SSUSession>& session);

  void DeleteAllSessions();

  // TODO(unassigned): const ref
  boost::asio::io_service& GetService()
  {
    return m_Service;
  }

  const auto& GetEndpoint() const noexcept
  {
    return m_Endpoint;
  }

  void Send(
      const uint8_t* buf,
      const std::size_t len,
      const boost::asio::ip::udp::endpoint& to);

  void AddRelay(
      const std::uint32_t tag,
      const boost::asio::ip::udp::endpoint& relay);

  std::shared_ptr<SSUSession> FindRelaySession(const std::uint32_t tag);

  void NewPeerTest(
      const std::uint32_t nonce,
      const PeerTestParticipant role,
      const std::shared_ptr<SSUSession>& session = nullptr);

  PeerTestParticipant GetPeerTestParticipant(const std::uint32_t nonce);

  std::shared_ptr<SSUSession> GetPeerTestSession(const std::uint32_t nonce);

  void UpdatePeerTest(
      const std::uint32_t nonce,
      const PeerTestParticipant role);

  void RemovePeerTest(const std::uint32_t nonce);

 private:
  void Receive();

  void ReceiveV6();

  void HandleReceivedFrom(
      const boost::system::error_code& ecode,
      const std::size_t bytes_transferred,
      RawSSUPacket* packet);

  void HandleReceivedFromV6(
      const boost::system::error_code& ecode,
      const std::size_t bytes_transferred,
      RawSSUPacket* packet);

  void HandleReceivedPackets(const std::vector<RawSSUPacket*>& packets);

  template <typename Filter>
  std::shared_ptr<SSUSession> GetRandomSession(const Filter filter);

  std::set<SSUSession*> FindIntroducers(const std::size_t max_num_introducers);

  void ScheduleIntroducersUpdateTimer();
  void HandleIntroducersUpdateTimer(const boost::system::error_code& ecode);

  void SchedulePeerTestsCleanupTimer();
  void HandlePeerTestsCleanupTimer(const boost::system::error_code& ecode);

 private:
  struct PeerTest {
    std::uint64_t creation_time{};  ///< Must be set as time since epoch, in implementation
    PeerTestParticipant role;
    std::shared_ptr<SSUSession> session;  // for Bob to Alice
  };

  boost::asio::io_service& m_Service;

  boost::asio::ip::udp::endpoint m_Endpoint, m_EndpointV6;
  boost::asio::ip::udp::socket m_Socket, m_SocketV6;

  boost::asio::deadline_timer m_IntroducersUpdateTimer, m_PeerTestsCleanupTimer;

  bool m_IsRunning;

  // introducers we are connected to
  std::list<boost::asio::ip::udp::endpoint> m_Introducers;

  mutable std::mutex m_SessionsMutex;

  std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<SSUSession>> m_Sessions;

  // we are introducer
  std::map<std::uint32_t, boost::asio::ip::udp::endpoint> m_Relays;

  // nonce -> creation time in milliseconds
  std::map<std::uint32_t, PeerTest> m_PeerTests;
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_TRANSPORTS_SSU_SERVER_H_
