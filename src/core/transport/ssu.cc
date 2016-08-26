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

#include "ssu.h"

#include <boost/bind.hpp>

#include <array>
#include <cstdint>
#include <list>
#include <memory>
#include <set>
#include <vector>

#include "ssu.h"
#include "crypto/rand.h"
#include "net_db.h"
#include "router_context.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace transport {

SSUServer::SSUServer(
    std::size_t port)
    : m_Thread(nullptr),
      m_ThreadV6(nullptr),
      m_ReceiversThread(nullptr),
      m_Work(m_Service),
      m_WorkV6(m_ServiceV6),
      m_ReceiversWork(m_ReceiversService),
      m_Endpoint(boost::asio::ip::udp::v4(), port),
      m_EndpointV6(boost::asio::ip::udp::v6(), port),
      m_Socket(m_ReceiversService, m_Endpoint),
      m_SocketV6(m_ReceiversService),
      m_IntroducersUpdateTimer(m_Service),
      m_PeerTestsCleanupTimer(m_Service) {
  m_Socket.set_option(boost::asio::socket_base::receive_buffer_size(65535));
  m_Socket.set_option(boost::asio::socket_base::send_buffer_size(65535));
  if (context.SupportsV6()) {
    m_SocketV6.open(boost::asio::ip::udp::v6());
    m_SocketV6.set_option(boost::asio::ip::v6_only(true));
    m_SocketV6.set_option(boost::asio::socket_base::receive_buffer_size(65535));
    m_SocketV6.set_option(boost::asio::socket_base::send_buffer_size(65535));
    m_SocketV6.bind(m_EndpointV6);
  }
}

SSUServer::~SSUServer() {}

void SSUServer::Start() {
  LogPrint(eLogDebug, "SSUServer: starting");
  m_IsRunning = true;
  m_ReceiversThread =
    std::make_unique<std::thread>(
        std::bind(
            &SSUServer::RunReceivers,
            this));
  m_Thread =
    std::make_unique<std::thread>(
        std::bind(
            &SSUServer::Run,
            this));
  m_ReceiversService.post(
      std::bind(
          &SSUServer::Receive,
          this));
  if (context.SupportsV6()) {
    m_ThreadV6 =
      std::make_unique<std::thread>(
          std::bind(
              &SSUServer::RunV6,
              this));
    m_ReceiversService.post(
        std::bind(
            &SSUServer::ReceiveV6,
            this));
  }
  SchedulePeerTestsCleanupTimer();
  // wait for 30 seconds and decide if we need introducers
  ScheduleIntroducersUpdateTimer();
}

void SSUServer::Stop() {
  LogPrint(eLogDebug, "SSUServer: stopping");
  DeleteAllSessions();
  m_IsRunning = false;
  m_Service.stop();
  m_Socket.close();
  m_ServiceV6.stop();
  m_SocketV6.close();
  m_ReceiversService.stop();
  if (m_ReceiversThread) {
    m_ReceiversThread->join();
    m_ReceiversThread.reset(nullptr);
  }
  if (m_Thread) {
    m_Thread->join();
    m_Thread.reset(nullptr);
  }
  if (m_ThreadV6) {
    m_ThreadV6->join();
    m_ThreadV6.reset(nullptr);
  }
}

void SSUServer::Run() {
  while (m_IsRunning) {
    try {
      LogPrint(eLogDebug, "SSUServer: running ioservice");
      m_Service.run();
    }
    catch (std::exception& ex) {
      LogPrint(eLogError,
          "SSUServer: Run() ioservice error: '", ex.what(), "'");
    }
  }
}

void SSUServer::RunV6() {
  while (m_IsRunning) {
    try {
      LogPrint(eLogDebug, "SSUServer: running V6 ioservice");
      m_ServiceV6.run();
    }
    catch (std::exception& ex) {
      LogPrint(eLogError,
          "SSUServer: RunV6() ioservice error: '", ex.what(), "'");
    }
  }
}

void SSUServer::RunReceivers() {
  while (m_IsRunning) {
    try {
      LogPrint(eLogDebug, "SSUServer: running receivers ioservice");
      m_ReceiversService.run();
    }
    catch (std::exception& ex) {
      LogPrint(eLogError,
          "SSUServer: RunReceivers() ioservice error: '", ex.what(), "'");
    }
  }
}

void SSUServer::AddRelay(
    std::uint32_t tag,
    const boost::asio::ip::udp::endpoint& relay) {
  LogPrint(eLogDebug, "SSUServer: adding relay");
  m_Relays[tag] = relay;
}

std::shared_ptr<SSUSession> SSUServer::FindRelaySession(
    std::uint32_t tag) {
  LogPrint(eLogDebug, "SSUServer: finding relay session");
  auto it = m_Relays.find(tag);
  if (it != m_Relays.end())
    return FindSession(it->second);
  return nullptr;
}

void SSUServer::Send(
    const std::uint8_t* buf,
    std::size_t len,
    const boost::asio::ip::udp::endpoint& to) {
  LogPrint(eLogDebug, "SSUServer: sending data");
  if (to.protocol() == boost::asio::ip::udp::v4()) {
    try {
      m_Socket.send_to(boost::asio::buffer(buf, len), to);
    } catch (const std::exception& ex) {
      LogPrint(eLogError, "SSUServer: send error: '", ex.what(), "'");
    }
  } else {
    try {
      m_SocketV6.send_to(boost::asio::buffer(buf, len), to);
    } catch (const std::exception& ex) {
      LogPrint(eLogError, "SSUServer: V6 send error: '", ex.what(), "'");
    }
  }
}

void SSUServer::Receive() {
  LogPrint(eLogDebug, "SSUServer: receiving data");
  RawSSUPacket* packet = new RawSSUPacket();
  m_Socket.async_receive_from(
      boost::asio::buffer(
          packet->buf,
          static_cast<std::size_t>(SSUSize::MTUv4)),
      packet->from,
      std::bind(
          &SSUServer::HandleReceivedFrom,
          this,
          std::placeholders::_1,
          std::placeholders::_2,
          packet));
}

void SSUServer::ReceiveV6() {
  LogPrint(eLogDebug, "SSUServer: V6: receiving data");
  RawSSUPacket* packet = new RawSSUPacket();
  m_SocketV6.async_receive_from(
      boost::asio::buffer(
          packet->buf,
          static_cast<std::size_t>(SSUSize::MTUv6)),
      packet->from,
      std::bind(
          &SSUServer::HandleReceivedFromV6,
          this,
          std::placeholders::_1,
          std::placeholders::_2,
          packet));
}

void SSUServer::HandleReceivedFrom(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    RawSSUPacket* packet) {
  LogPrint(eLogDebug, "SSUServer: handling received data");
  if (!ecode) {
    packet->len = bytes_transferred;
    std::vector<RawSSUPacket *> packets;
    packets.push_back(packet);
    boost::system::error_code ec;
    std::size_t more_bytes = m_Socket.available(ec);
    while (more_bytes && packets.size() < 25) {
      packet = new RawSSUPacket();
      packet->len = m_Socket.receive_from(
          boost::asio::buffer(
              packet->buf,
              static_cast<std::size_t>(SSUSize::MTUv4)),
          packet->from);
      packets.push_back(packet);
      more_bytes = m_Socket.available();
    }
    m_Service.post(
        std::bind(
            &SSUServer::HandleReceivedPackets,
            this,
            packets));
    Receive();
  } else {
    LogPrint("SSUServer: receive error: ", ecode.message());
    delete packet;
  }
}

void SSUServer::HandleReceivedFromV6(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    RawSSUPacket* packet) {
  LogPrint(eLogDebug, "SSUServer: V6: handling received data");
  if (!ecode) {
    packet->len = bytes_transferred;
    std::vector<RawSSUPacket *> packets;
    packets.push_back(packet);
    std::size_t more_bytes = m_SocketV6.available();
    while (more_bytes && packets.size() < 25) {
      packet = new RawSSUPacket();
      packet->len = m_SocketV6.receive_from(
          boost::asio::buffer(
              packet->buf,
              static_cast<std::size_t>(SSUSize::MTUv6)),
          packet->from);
      packets.push_back(packet);
      more_bytes = m_SocketV6.available();
    }
    m_ServiceV6.post(
        std::bind(
            &SSUServer::HandleReceivedPackets,
            this,
            packets));
    ReceiveV6();
  } else {
    LogPrint("SSUServer: V6 receive error: ", ecode.message());
    delete packet;
  }
}

void SSUServer::HandleReceivedPackets(
    std::vector<RawSSUPacket *> packets) {
  LogPrint(eLogDebug, "SSUServer: handling received packets");
  std::shared_ptr<SSUSession> session;
  for (auto packet : packets) {
    auto pkt = packet;
    try {
      // we received pkt for other session than previous
      if (!session || session->GetRemoteEndpoint() != pkt->from) {
        if (session)
          session->FlushData();
        auto session_it = m_Sessions.find(pkt->from);
        if (session_it != m_Sessions.end())
          session = session_it->second;
        if (!session) {
          session = std::make_shared<SSUSession>(*this, pkt->from);
          session->WaitForConnect(); {
            std::unique_lock<std::mutex> l(m_SessionsMutex);
            m_Sessions[pkt->from] = session;
          }
          LogPrint(eLogInfo,
              "SSUServer: created new SSU session from ",
              session->GetRemoteEndpoint());
        }
      }
      session->ProcessNextMessage(pkt->buf, pkt->len, pkt->from);
    } catch (std::exception& ex) {
      LogPrint(eLogError,
          "SSUServer: HandleReceivedPackets(): '", ex.what(), "'");
      if (session)
        session->FlushData();
      session = nullptr;
    }
    delete pkt;
  }
  if (session)
    session->FlushData();
}

std::shared_ptr<SSUSession> SSUServer::FindSession(
    std::shared_ptr<const i2p::data::RouterInfo> router) const {
  LogPrint(eLogDebug, "SSUServer: finding session from RI");
  if (!router)
    return nullptr;
  auto address = router->GetSSUAddress(true);  // v4 only
  if (!address)
    return nullptr;
  auto session =
    FindSession(boost::asio::ip::udp::endpoint(address->host, address->port));
  if (session || !context.SupportsV6())
    return session;
  // try v6
  address = router->GetSSUV6Address();
  if (!address)
    return nullptr;
  return FindSession(boost::asio::ip::udp::endpoint(address->host, address->port));
}

std::shared_ptr<SSUSession> SSUServer::FindSession(
    const boost::asio::ip::udp::endpoint& ep) const {
  LogPrint(eLogDebug, "SSUServer: finding session from endpoint");
  auto it = m_Sessions.find(ep);
  if (it != m_Sessions.end())
    return it->second;
  else
    return nullptr;
}

std::shared_ptr<SSUSession> SSUServer::GetSession(
    std::shared_ptr<const i2p::data::RouterInfo> router,
    bool peer_test) {
  LogPrint(eLogDebug, "SSUServer: getting session");
  std::shared_ptr<SSUSession> session;
  if (router) {
    auto address = router->GetSSUAddress(!context.SupportsV6());
    if (address) {
      boost::asio::ip::udp::endpoint remote_endpoint(
          address->host,
          address->port);
      auto it = m_Sessions.find(remote_endpoint);
      if (it != m_Sessions.end()) {
        session = it->second;
      } else {
        // otherwise create new session
        session = std::make_shared<SSUSession>(
            *this,
            remote_endpoint,
            router,
            peer_test); {
          std::unique_lock<std::mutex> l(m_SessionsMutex);
          m_Sessions[remote_endpoint] = session;
        }
        session->SetRemoteIdentHashAbbreviation();
        if (!router->UsesIntroducer()) {
          // connect directly
          LogPrint(eLogInfo,
              "SSUServer: creating new session to",
              session->GetFormattedSessionInfo());
          session->Connect();
        } else {
          // connect through introducer
          auto num_introducers = address->introducers.size();
          if (num_introducers > 0) {
            std::shared_ptr<SSUSession> introducer_session;
            const i2p::data::RouterInfo::Introducer* introducer = nullptr;
            // we might have a session to introducer already
            for (std::size_t i = 0; i < num_introducers; i++) {
              introducer = &(address->introducers[i]);
              it = m_Sessions.find(
                       boost::asio::ip::udp::endpoint(
                           introducer->host,
                           introducer->port));
              if (it != m_Sessions.end()) {
                introducer_session = it->second;
                break;
              }
            }
            if (introducer_session) {  // session found
              LogPrint(eLogInfo,
                  "SSUServer: ", introducer->host, ":", introducer->port,
                  "session to introducer already exists");
            } else {  // create new
              LogPrint(eLogInfo,
                  "SSUServer: creating new session to introducer");
              introducer = &(address->introducers[0]);  // TODO(unassigned): ???
              boost::asio::ip::udp::endpoint introducerEndpoint(
                  introducer->host,
                  introducer->port);
              introducer_session = std::make_shared<SSUSession>(
                  *this,
                  introducerEndpoint,
                  router);
              std::unique_lock<std::mutex> l(m_SessionsMutex);
              m_Sessions[introducerEndpoint] = introducer_session;
            }
            // introduce
            LogPrint("SSUServer: introducing new SSU session to [",
                router->GetIdentHashAbbreviation(), "] through introducer [",
                introducer_session->GetRemoteIdentHashAbbreviation(), "] ",
                introducer->host, ":",
                introducer->port);
            session->WaitForIntroduction();
            // if we are unreachable
            if (i2p::context.GetRouterInfo().UsesIntroducer()) {
              std::array<std::uint8_t, 1> buf {};
              Send(buf.data(), 0, remote_endpoint);  // send HolePunch
            }
            introducer_session->Introduce(introducer->tag, introducer->key);
          } else {
            LogPrint(eLogWarn,
                "SSUServer: can't connect to unreachable router."
                "No introducers presented");
            std::unique_lock<std::mutex> l(m_SessionsMutex);
            m_Sessions.erase(remote_endpoint);
            session.reset();
          }
        }
      }
    } else {
      LogPrint(eLogWarn,
          "SSUServer: router ", router->GetIdentHashAbbreviation(),
          " doesn't have SSU address");
    }
  }
  return session;
}

void SSUServer::DeleteSession(
    std::shared_ptr<SSUSession> session) {
  LogPrint(eLogDebug, "SSUServer: deleting session");
  if (session) {
    session->Close();
    std::unique_lock<std::mutex> l(m_SessionsMutex);
    m_Sessions.erase(session->GetRemoteEndpoint());
  }
}

void SSUServer::DeleteAllSessions() {
  LogPrint(eLogDebug, "SSUServer: deleting all sessions");
  std::unique_lock<std::mutex> l(m_SessionsMutex);
  for (auto it : m_Sessions)
    it.second->Close();
  m_Sessions.clear();
}

template<typename Filter>
std::shared_ptr<SSUSession> SSUServer::GetRandomSession(
    Filter filter) {
  LogPrint(eLogDebug, "SSUServer: getting random session");
  std::vector<std::shared_ptr<SSUSession>> filtered_sessions;
  for (auto session : m_Sessions)
    if (filter (session.second))
      filtered_sessions.push_back(session.second);
  if (filtered_sessions.size() > 0) {
    std::size_t s = filtered_sessions.size();
    std::size_t ind = i2p::crypto::RandInRange<std::size_t>(0, s - 1);
    return filtered_sessions[ind];
  }
  return nullptr;
}

std::shared_ptr<SSUSession> SSUServer::GetRandomEstablishedSession(
    std::shared_ptr<const SSUSession> excluded) {
  LogPrint(eLogDebug, "SSUServer: getting random established session");
  return GetRandomSession(
      [excluded](std::shared_ptr<SSUSession> session)->bool {
      return session->GetState() == SessionStateEstablished &&
      !session->IsV6() &&
      session != excluded; });
}

std::set<SSUSession *> SSUServer::FindIntroducers(
    std::size_t max_num_introducers) {
  LogPrint(eLogDebug, "SSUServer: finding introducers");
  std::uint32_t ts = i2p::util::GetSecondsSinceEpoch();
  std::set<SSUSession *> ret;
  for (std::size_t i = 0; i < max_num_introducers; i++) {
    auto session =
      GetRandomSession(
          [&ret, ts](std::shared_ptr<SSUSession> session)->bool {
          return session->GetRelayTag() &&
          !ret.count(session.get()) &&
          session->GetState() == SessionStateEstablished &&
          ts < session->GetCreationTime()
               + static_cast<std::size_t>(SSUDuration::ToIntroducerSessionDuration); });
    if (session) {
      ret.insert(session.get());
      break;
    }
  }
  return ret;
}

void SSUServer::ScheduleIntroducersUpdateTimer() {
  LogPrint(eLogDebug, "SSUServer: scheduling introducers update timer");
  m_IntroducersUpdateTimer.expires_from_now(
      boost::posix_time::seconds(
          static_cast<std::size_t>(SSUDuration::KeepAliveInterval)));
  m_IntroducersUpdateTimer.async_wait(
      std::bind(
          &SSUServer::HandleIntroducersUpdateTimer,
          this,
          std::placeholders::_1));
}

void SSUServer::HandleIntroducersUpdateTimer(
    const boost::system::error_code& ecode) {
  LogPrint(eLogDebug,
      "SSUServer: handling introducers update timer");
  if (ecode != boost::asio::error::operation_aborted) {
    // timeout expired
    if (i2p::context.GetStatus() == eRouterStatusTesting) {
      // we still don't know if we need introducers
      ScheduleIntroducersUpdateTimer();
      return;
    }
    if (i2p::context.GetStatus () == eRouterStatusOK)
      return;  // we don't need introducers anymore
    // we are firewalled
    if (!i2p::context.IsUnreachable()) i2p::context.SetUnreachable();
    std::list<boost::asio::ip::udp::endpoint> new_list;
    std::size_t num_introducers = 0;
    std::uint32_t ts = i2p::util::GetSecondsSinceEpoch();  // Timestamp
    for (auto introducer : m_Introducers) {
      auto session = FindSession(introducer);
      if (session &&
          ts < session->GetCreationTime()
               + static_cast<std::size_t>(SSUDuration::ToIntroducerSessionDuration)) {
        session->SendKeepAlive();
        new_list.push_back(introducer);
        num_introducers++;
      } else {
        i2p::context.RemoveIntroducer(introducer);
      }
    }
    if (num_introducers < static_cast<std::size_t>(SSUSize::MaxIntroducers)) {
      // create new
      auto introducers =
        FindIntroducers(static_cast<std::size_t>(SSUSize::MaxIntroducers));
      if (introducers.size() > 0) {
        for (auto it : introducers) {
          auto router = it->GetRemoteRouter();
          if (router &&
              i2p::context.AddIntroducer(*router, it->GetRelayTag())) {
            new_list.push_back(it->GetRemoteEndpoint());
            if (new_list.size() >= static_cast<std::size_t>(SSUSize::MaxIntroducers))
              break;
          }
        }
      }
    }
    m_Introducers = new_list;
    if (m_Introducers.empty()) {
      auto introducer = i2p::data::netdb.GetRandomIntroducer();
      if (introducer)
        GetSession(introducer);
    }
    ScheduleIntroducersUpdateTimer();
  }
}

void SSUServer::NewPeerTest(
    std::uint32_t nonce,
    PeerTestParticipant role,
    std::shared_ptr<SSUSession> session) {
  LogPrint(eLogDebug, "SSUServer: new peer test");
  m_PeerTests[nonce] = {
    i2p::util::GetMillisecondsSinceEpoch(),
    role,
    session
  };
}

PeerTestParticipant SSUServer::GetPeerTestParticipant(
    std::uint32_t nonce) {
  LogPrint(eLogDebug, "SSUServer: getting PeerTest participant");
  auto it = m_PeerTests.find(nonce);
  if (it != m_PeerTests.end())
    return it->second.role;
  else
    return PeerTestParticipantUnknown;
}

std::shared_ptr<SSUSession> SSUServer::GetPeerTestSession(
    std::uint32_t nonce) {
  LogPrint(eLogDebug, "SSUServer: getting PeerTest session");
  auto it = m_PeerTests.find(nonce);
  if (it != m_PeerTests.end())
    return it->second.session;
  else
    return nullptr;
}

void SSUServer::UpdatePeerTest(
    std::uint32_t nonce,
    PeerTestParticipant role) {
  LogPrint(eLogDebug, "SSUServer: updating PeerTest");
  auto it = m_PeerTests.find(nonce);
  if (it != m_PeerTests.end())
    it->second.role = role;
}

void SSUServer::RemovePeerTest(
    std::uint32_t nonce) {
  LogPrint(eLogDebug, "SSUServer: removing PeerTest");
  m_PeerTests.erase(nonce);
}

void SSUServer::SchedulePeerTestsCleanupTimer() {
  LogPrint(eLogDebug, "SSUServer: scheduling PeerTests cleanup timer");
  m_PeerTestsCleanupTimer.expires_from_now(
      boost::posix_time::seconds(
          static_cast<std::size_t>(SSUDuration::PeerTestTimeout)));
  m_PeerTestsCleanupTimer.async_wait(
      std::bind(
          &SSUServer::HandlePeerTestsCleanupTimer,
          this,
          std::placeholders::_1));
}

void SSUServer::HandlePeerTestsCleanupTimer(
    const boost::system::error_code& ecode) {
  LogPrint(eLogDebug, "SSUServer: handling PeerTests cleanup timer");
  if (ecode != boost::asio::error::operation_aborted) {
    std::size_t num_deleted = 0;
    std::uint64_t ts = i2p::util::GetMillisecondsSinceEpoch();
    for (auto it = m_PeerTests.begin(); it != m_PeerTests.end();) {
      if (ts > it->second.creationTime
               + static_cast<std::size_t>(SSUDuration::PeerTestTimeout)
               * 1000LL) {
        num_deleted++;
        it = m_PeerTests.erase(it);
      } else {
        it++;
      }
    }
    if (num_deleted > 0)
      LogPrint(eLogInfo,
          "SSUServer: ", num_deleted, " peer tests have been expired");
    SchedulePeerTestsCleanupTimer();
  }
}

}  // namespace transport
}  // namespace i2p

