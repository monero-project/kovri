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

#ifndef SRC_CORE_TRANSPORT_SSU_H_
#define SRC_CORE_TRANSPORT_SSU_H_

#include <boost/asio.hpp>

#include <inttypes.h>
#include <string.h>

#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

#include "i2np_protocol.h"
#include "identity.h"
#include "router_info.h"
#include "ssu_session.h"
#include "crypto/aes.h"
#include "util/i2p_endian.h"

namespace i2p {
namespace transport {

const int SSU_KEEP_ALIVE_INTERVAL = 30;  // 30 seconds
const int SSU_PEER_TEST_TIMEOUT = 60;  // 60 seconds
const int SSU_TO_INTRODUCER_SESSION_DURATION = 3600;  // 1 hour
const size_t SSU_MAX_NUM_INTRODUCERS = 3;

struct SSUPacket {
  i2p::crypto::AESAlignedBuffer<1500> buf;
  boost::asio::ip::udp::endpoint from;
  size_t len;
};

class SSUServer {
 public:
  SSUServer(
      boost::asio::io_service& service,
      std::size_t port);

  ~SSUServer();

  void Start();

  void Stop();

  std::shared_ptr<SSUSession> GetSession(
      std::shared_ptr<const i2p::data::RouterInfo> router,
      bool peerTest = false);

  std::shared_ptr<SSUSession> FindSession(
      std::shared_ptr<const i2p::data::RouterInfo> router) const;

  std::shared_ptr<SSUSession> FindSession(
      const boost::asio::ip::udp::endpoint& ep) const;

  std::shared_ptr<SSUSession> GetRandomEstablishedSession(
      std::shared_ptr<const SSUSession> excluded);

  void DeleteSession(
      std::shared_ptr<SSUSession> session);

  void DeleteAllSessions();

  boost::asio::io_service& GetService() {
    return m_Service;
  }

  const boost::asio::ip::udp::endpoint& GetEndpoint() const {
    return m_Endpoint;
  }

  void Send(
      const uint8_t* buf,
      size_t len,
      const boost::asio::ip::udp::endpoint& to);

  void AddRelay(
      uint32_t tag,
      const boost::asio::ip::udp::endpoint& relay);

  std::shared_ptr<SSUSession> FindRelaySession(
      uint32_t tag);

  void NewPeerTest(
      uint32_t nonce,
      PeerTestParticipant role,
      std::shared_ptr<SSUSession> session = nullptr);

  PeerTestParticipant GetPeerTestParticipant(
      uint32_t nonce);

  std::shared_ptr<SSUSession> GetPeerTestSession(
      uint32_t nonce);

  void UpdatePeerTest(
      uint32_t nonce,
      PeerTestParticipant role);

  void RemovePeerTest(
      uint32_t nonce);

 private:
  void Receive();

  void ReceiveV6();

  void HandleReceivedFrom(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      SSUPacket* packet);

  void HandleReceivedFromV6(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      SSUPacket* packet);

  void HandleReceivedPackets(
      std::vector<SSUPacket *> packets);

  template<typename Filter>
  std::shared_ptr<SSUSession> GetRandomSession(
      Filter filter);

  std::set<SSUSession *> FindIntroducers(
      int maxNumIntroducers);

  void ScheduleIntroducersUpdateTimer();

  void HandleIntroducersUpdateTimer(
      const boost::system::error_code& ecode);

  void SchedulePeerTestsCleanupTimer();

  void HandlePeerTestsCleanupTimer(
      const boost::system::error_code& ecode);

 private:
  struct PeerTest {
    uint64_t creationTime;
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
  std::map<uint32_t, boost::asio::ip::udp::endpoint> m_Relays;

  // nonce -> creation time in milliseconds
  std::map<uint32_t, PeerTest> m_PeerTests;

 public:
  // for HTTP only
  const decltype(m_Sessions)& GetSessions() const {
    return m_Sessions;
  }
};

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_SSU_H_
