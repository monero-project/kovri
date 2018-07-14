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

#include "core/router/transports/ssu/server.h"

#include <boost/bind.hpp>

#include <array>

#include "core/crypto/rand.h"

#include "core/router/context.h"
#include "core/router/net_db/impl.h"

#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {
SSUServer::SSUServer(boost::asio::io_service& service, const std::size_t port)
    : m_Exception(__func__),
      m_Service(service),
      m_Endpoint(boost::asio::ip::udp::v4(), port),
      m_EndpointV6(boost::asio::ip::udp::v6(), port),
      m_Socket(m_Service, m_Endpoint),
      m_SocketV6(m_Service),
      m_IntroducersUpdateTimer(m_Service),
      m_PeerTestsCleanupTimer(m_Service),
      m_IsRunning(false)
{
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
  LOG(debug) << "SSUServer: starting";
  m_IsRunning = true;
  m_Service.post(
      std::bind(
          &SSUServer::Receive,
          this));
  if (context.SupportsV6()) {
    m_Service.post(
        std::bind(
            &SSUServer::ReceiveV6,
            this));
  }
  SchedulePeerTestsCleanupTimer();
  // wait for 30 seconds and decide if we need introducers
  ScheduleIntroducersUpdateTimer();
}

void SSUServer::Stop() {
  LOG(debug) << "SSUServer: stopping";
  DeleteAllSessions();
  m_IsRunning = false;
  m_Socket.close();
  m_SocketV6.close();
}

void SSUServer::AddRelay(
    const std::uint32_t tag,
    const boost::asio::ip::udp::endpoint& relay)
{
  LOG(debug) << "SSUServer: adding relay";
  m_Relays[tag] = relay;
}

std::shared_ptr<SSUSession> SSUServer::FindRelaySession(const std::uint32_t tag)
{
  LOG(debug) << "SSUServer: finding relay session";
  auto it = m_Relays.find(tag);
  if (it != m_Relays.end())
    return FindSession(it->second);
  return nullptr;
}

void SSUServer::Send(
    const std::uint8_t* buf,
    const std::size_t len,
    const boost::asio::ip::udp::endpoint& to)
{
  LOG(debug) << "SSUServer: sending data";
  try
    {
      if (to.protocol() == boost::asio::ip::udp::v4())
        {
          m_Socket.send_to(boost::asio::buffer(buf, len), to);
          return;
        }

      m_SocketV6.send_to(boost::asio::buffer(buf, len), to);
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
    }
}

void SSUServer::Receive()
{
  LOG(debug) << "SSUServer: receiving data";
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
  auto packet = std::make_unique<RawSSUPacket>();
#else
  RawSSUPacket* packet =
      new RawSSUPacket();  // always freed in ensuing handlers
#endif
  m_Socket.async_receive_from(
      boost::asio::buffer(packet->buf, SSUSize::MTUv4),
      packet->from,
      std::bind(
          &SSUServer::HandleReceivedFrom,
          this,
          std::placeholders::_1,
          std::placeholders::_2,
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
          std::move(packet)
#else
          packet  // will not work with unique_ptr .get()
#endif
              ));
}

void SSUServer::ReceiveV6()
{
  LOG(debug) << "SSUServer: V6: receiving data";
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
  auto packet = std::make_unique<RawSSUPacket>();
#else
  RawSSUPacket* packet =
      new RawSSUPacket();  // always freed in ensuing handlers
#endif
  m_SocketV6.async_receive_from(
      boost::asio::buffer(packet->buf, SSUSize::MTUv6),
      packet->from,
      std::bind(
          &SSUServer::HandleReceivedFromV6,
          this,
          std::placeholders::_1,
          std::placeholders::_2,
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
          std::move(packet)
#else
          packet  // will not work with unique_ptr .get()
#endif
              ));
}

// coverity[+free : arg-2]
void SSUServer::HandleReceivedFrom(
    const boost::system::error_code& ecode,
    const std::size_t bytes_transferred,
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
    std::unique_ptr<RawSSUPacket>& packet
#else
    RawSSUPacket* packet
#endif
)
{
  LOG(debug) << "SSUServer: handling received data";
  if (!ecode)
    {
      packet->len = bytes_transferred;
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
      std::vector<std::unique_ptr<RawSSUPacket>> packets;
      packets.push_back(std::move(packet));
#else
      std::vector<RawSSUPacket*> packets;
      packets.push_back(packet);
#endif
      boost::system::error_code ec;
      std::size_t more_bytes = m_Socket.available(ec);
      // TODO(anonimal): but what about 0 length HolePunch?
      //   Current handler's null length check done in vain?
      while (more_bytes && packets.size() < 25)
        {
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
          auto pkt = std::make_unique<RawSSUPacket>();
#else
          RawSSUPacket* pkt = new RawSSUPacket();
#endif
          pkt->len = m_Socket.receive_from(
              boost::asio::buffer(pkt->buf, SSUSize::MTUv4), pkt->from);
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
          packets.push_back(std::move(pkt));
#else
          packets.push_back(pkt);
#endif
          more_bytes = m_Socket.available();
        }
      m_Service.post(std::bind(
          &SSUServer::HandleReceivedPackets,
          this,
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
          std::move(packets)
#else
          packets
#endif
              ));
      Receive();
    }
  else
    {
      LOG(error) << "SSUServer: receive error: " << ecode.message();
#if (BOOST_VERSION < 106600)
      delete packet;  // free packet, now
#endif
    }
}

// coverity[+free : arg-2]
void SSUServer::HandleReceivedFromV6(
    const boost::system::error_code& ecode,
    const std::size_t bytes_transferred,
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
    std::unique_ptr<RawSSUPacket>& packet
#else
    RawSSUPacket* packet
#endif
)
{
  LOG(debug) << "SSUServer: V6: handling received data";
  if (!ecode)
    {
      packet->len = bytes_transferred;
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
      std::vector<std::unique_ptr<RawSSUPacket>> packets;
      packets.push_back(std::move(packet));
#else
      std::vector<RawSSUPacket*> packets;
      packets.push_back(packet);
#endif
      std::size_t more_bytes = m_SocketV6.available();
      while (more_bytes && packets.size() < 25)
        {
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
          auto pkt = std::make_unique<RawSSUPacket>();
#else
          RawSSUPacket* pkt = new RawSSUPacket();
#endif
          pkt->len = m_SocketV6.receive_from(
              boost::asio::buffer(pkt->buf, SSUSize::MTUv6), pkt->from);
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
          packets.push_back(std::move(pkt));
#else
          packets.push_back(pkt);
#endif
          more_bytes = m_SocketV6.available();
        }
      m_Service.post(std::bind(
          &SSUServer::HandleReceivedPackets,
          this,
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
          std::move(packets)
#else
          packets
#endif
              ));
      ReceiveV6();
    }
  else
    {
      LOG(error) << "SSUServer: V6 receive error: " << ecode.message();
#if (BOOST_VERSION < 106600)
      delete packet;  // free packet, now
#endif
    }
}

void SSUServer::HandleReceivedPackets(
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
    const std::vector<std::unique_ptr<RawSSUPacket>>& packets
#else
    const std::vector<RawSSUPacket*>& packets
#endif
)
{
  LOG(debug) << "SSUServer: handling received packets";
  std::shared_ptr<SSUSession> session;
// BOOST_ASIO_MOVE_ACCEPT_HANDLER_CHECK enabled in 1.66
#if (BOOST_VERSION >= 106600)
  for (const auto& packet : packets)
    {
#else
  for (auto* packet : packets)
    {
#endif
      try
        {
          // Packet received for a session other than the previous one
          if (!session || session->GetRemoteEndpoint() != packet->from)
            {
              if (session)
                session->FlushData();
              auto session_it = m_Sessions.find(packet->from);
              if (session_it != m_Sessions.end())
                {
                  session = session_it->second;
                }
              else
                {
                  session = std::make_shared<SSUSession>(*this, packet->from);
                  session->WaitForConnect();
                  {
                    std::unique_lock<std::mutex> l(m_SessionsMutex);
                    // TODO(anonimal): assuming we get this far with 0 length HolePunch,
                    //   why would we add a session with Charlie *before* sending a SessionRequest?
                    m_Sessions[packet->from] = session;
                  }
                  LOG(debug) << "SSUServer: created new SSU session from "
                             << session->GetRemoteEndpoint();
                }
            }
          session->ProcessNextMessage(packet->buf, packet->len, packet->from);
        }
      catch (...)
        {
          m_Exception.Dispatch(__func__);
          if (session)
            session->FlushData();
          session = nullptr;
        }
#if (BOOST_VERSION < 106600)
      delete packet;  // free received packet
#endif
    }
  if (session)
    session->FlushData();
}

std::shared_ptr<SSUSession> SSUServer::FindSession(
    const std::shared_ptr<const kovri::core::RouterInfo>& router) const
{
  LOG(debug) << "SSUServer: finding session from RI";
  if (!router)
    return nullptr;
  auto address = router->GetSSUAddress();  // v4 only
  if (!address)
    return nullptr;
  auto session =
    FindSession(boost::asio::ip::udp::endpoint(address->host, address->port));
  if (session || !context.SupportsV6())
    return session;
  // try v6
  address = router->GetSSUAddress(true);
  if (!address)
    return nullptr;
  return FindSession(boost::asio::ip::udp::endpoint(address->host, address->port));
}

std::shared_ptr<SSUSession> SSUServer::FindSession(
    const boost::asio::ip::udp::endpoint& ep) const {
  LOG(debug) << "SSUServer: finding session from endpoint";
  auto it = m_Sessions.find(ep);
  if (it != m_Sessions.end())
    return it->second;
  else
    return nullptr;
}

std::shared_ptr<SSUSession> SSUServer::GetSession(
    const std::shared_ptr<const kovri::core::RouterInfo>& router,
    const bool peer_test)
{
  LOG(debug) << "SSUServer: getting session";
  std::shared_ptr<SSUSession> session;
  if (router) {
    auto address = router->GetSSUAddress(context.SupportsV6());
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
          LOG(debug)
            << "SSUServer: creating new session to"
            << session->GetFormattedSessionInfo();
          session->Connect();
        } else {
          // connect through introducer
          auto num_introducers = address->introducers.size();
          if (num_introducers > 0) {
            std::shared_ptr<SSUSession> introducer_session;
            const kovri::core::RouterInfo::Introducer* introducer = nullptr;
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
              LOG(debug)
                << "SSUServer: " << introducer->host << ":" << introducer->port
                << "session to introducer already exists";
            } else {  // create new
              LOG(debug) << "SSUServer: creating new session to introducer";
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
            LOG(debug)
              << "SSUServer: introducing new SSU session to "
              << "[" << router->GetIdentHashAbbreviation() << "] through introducer "
              << "[" << introducer_session->GetRemoteIdentHashAbbreviation() << "] "
              << introducer->host << ":" << introducer->port;
            session->WaitForIntroduction();
            // if we are unreachable
            if (context.GetRouterInfo().UsesIntroducer()) {
              std::array<std::uint8_t, 1> buf {{}};
              Send(buf.data(), 0, remote_endpoint);  // send HolePunch
            }
            introducer_session->Introduce(introducer->tag, introducer->key);
          } else {
            LOG(warning)
              << "SSUServer: can't connect to unreachable router."
              << "No introducers presented";
            std::unique_lock<std::mutex> l(m_SessionsMutex);
            m_Sessions.erase(remote_endpoint);
            session.reset();
          }
        }
      }
    } else {
      LOG(warning)
        << "SSUServer: router "
        << "[" << router->GetIdentHashAbbreviation() << "] "
        << "doesn't have SSU address";
    }
  }
  return session;
}

void SSUServer::DeleteSession(const std::shared_ptr<SSUSession>& session)
{
  LOG(debug) << "SSUServer: deleting session";
  if (session) {
    session->Close();
    std::unique_lock<std::mutex> l(m_SessionsMutex);
    m_Sessions.erase(session->GetRemoteEndpoint());
  }
}

void SSUServer::DeleteAllSessions() {
  LOG(debug) << "SSUServer: deleting all sessions";
  std::unique_lock<std::mutex> l(m_SessionsMutex);
  for (auto it : m_Sessions)
    it.second->Close();
  m_Sessions.clear();
}

template <typename Filter>
std::shared_ptr<SSUSession> SSUServer::GetRandomSession(const Filter filter)
{
  LOG(debug) << "SSUServer: getting random session";
  std::vector<std::shared_ptr<SSUSession>> filtered_sessions;
  for (auto session : m_Sessions)
    if (filter (session.second))
      filtered_sessions.push_back(session.second);
  if (filtered_sessions.size() > 0) {
    std::size_t s = filtered_sessions.size();
    std::size_t ind = kovri::core::RandInRange32(0, s - 1);
    return filtered_sessions[ind];
  }
  return nullptr;
}

std::shared_ptr<SSUSession> SSUServer::GetRandomEstablishedSession(
    const std::shared_ptr<const SSUSession>& excluded)
{
  LOG(debug) << "SSUServer: getting random established session";
  return GetRandomSession(
      [excluded](std::shared_ptr<SSUSession> session)->bool {
      return session->GetState() == SessionState::Established &&
      !session->IsV6() &&
      session != excluded; });
}

std::set<SSUSession*> SSUServer::FindIntroducers(
    const std::size_t max_num_introducers)
{
  LOG(debug) << "SSUServer: finding introducers";
  std::uint32_t ts = kovri::core::GetSecondsSinceEpoch();
  std::set<SSUSession *> ret;
  for (std::size_t i = 0; i < max_num_introducers; i++) {
    auto session =
      GetRandomSession(
          [&ret, ts](std::shared_ptr<SSUSession> session)->bool {
          return session->GetRelayTag() &&
          !ret.count(session.get()) &&
          session->GetState() == SessionState::Established &&
          ts < session->GetCreationTime()
               + SSUDuration::ToIntroducerSessionDuration; });
    if (session) {
      ret.insert(session.get());
      break;
    }
  }
  return ret;
}

void SSUServer::ScheduleIntroducersUpdateTimer() {
  LOG(debug) << "SSUServer: scheduling introducers update timer";
  m_IntroducersUpdateTimer.expires_from_now(
      boost::posix_time::seconds{
          static_cast<long>(SSUDuration::KeepAliveInterval)});
  m_IntroducersUpdateTimer.async_wait(
      std::bind(
          &SSUServer::HandleIntroducersUpdateTimer,
          this,
          std::placeholders::_1));
}

void SSUServer::HandleIntroducersUpdateTimer(
    const boost::system::error_code& ecode) {
  LOG(debug) << "SSUServer: handling introducers update timer";
  if (ecode != boost::asio::error::operation_aborted) {
    // timeout expired
    if (context.GetState() == RouterState::Testing) {
      // we still don't know if we need introducers
      ScheduleIntroducersUpdateTimer();
      return;
    }
    if (context.GetState () == RouterState::OK)
      return;  // we don't need introducers anymore
    // we are firewalled
    if (!context.IsUnreachable()) context.SetUnreachable();
    std::list<boost::asio::ip::udp::endpoint> new_list;
    std::size_t num_introducers = 0;
    std::uint32_t ts = kovri::core::GetSecondsSinceEpoch();  // Timestamp
    for (auto introducer : m_Introducers) {
      auto session = FindSession(introducer);
      if (session &&
          ts < session->GetCreationTime()
             + SSUDuration::ToIntroducerSessionDuration) {
        session->SendKeepAlive();
        new_list.push_back(introducer);
        num_introducers++;
      } else {
        context.RemoveIntroducer(introducer);
      }
    }
    auto max_introducers = SSUSize::MaxIntroducers;
    if (num_introducers < max_introducers) {
      // create new
      auto introducers = FindIntroducers(max_introducers);
      if (introducers.size() > 0) {
        for (auto it : introducers) {
          auto router = it->GetRemoteRouter();
          if (router &&
              context.AddIntroducer(*router, it->GetRelayTag())) {
            new_list.push_back(it->GetRemoteEndpoint());
            if (new_list.size() >= max_introducers)
              break;
          }
        }
      }
    }
    m_Introducers = new_list;
    if (m_Introducers.empty()) {
      auto introducer = kovri::core::netdb.GetRandomIntroducer();
      if (introducer)
        GetSession(introducer);
    }
    ScheduleIntroducersUpdateTimer();
  }
}

void SSUServer::NewPeerTest(
    const std::uint32_t nonce,
    const PeerTestParticipant role,
    const std::shared_ptr<SSUSession>& session)
{
  LOG(debug) << "SSUServer: new peer test";
  m_PeerTests[nonce] = {
    kovri::core::GetMillisecondsSinceEpoch(),
    role,
    session
  };
}

PeerTestParticipant SSUServer::GetPeerTestParticipant(const std::uint32_t nonce)
{
  LOG(debug) << "SSUServer: getting PeerTest participant";
  auto it = m_PeerTests.find(nonce);
  if (it != m_PeerTests.end())
    return it->second.role;
  else
    return PeerTestParticipant::Unknown;
}

std::shared_ptr<SSUSession> SSUServer::GetPeerTestSession(
    const std::uint32_t nonce)
{
  LOG(debug) << "SSUServer: getting PeerTest session";
  auto it = m_PeerTests.find(nonce);
  if (it != m_PeerTests.end())
    return it->second.session;
  else
    return nullptr;
}

void SSUServer::UpdatePeerTest(
    const std::uint32_t nonce,
    const PeerTestParticipant role)
{
  LOG(debug) << "SSUServer: updating PeerTest";
  auto it = m_PeerTests.find(nonce);
  if (it != m_PeerTests.end())
    it->second.role = role;
}

void SSUServer::RemovePeerTest(const std::uint32_t nonce)
{
  LOG(debug) << "SSUServer: removing PeerTest";
  m_PeerTests.erase(nonce);
}

void SSUServer::SchedulePeerTestsCleanupTimer() {
  LOG(debug) << "SSUServer: scheduling PeerTests cleanup timer";
  m_PeerTestsCleanupTimer.expires_from_now(
      boost::posix_time::seconds{
          static_cast<long>(SSUDuration::PeerTestTimeout)});
  m_PeerTestsCleanupTimer.async_wait(
      std::bind(
          &SSUServer::HandlePeerTestsCleanupTimer,
          this,
          std::placeholders::_1));
}

void SSUServer::HandlePeerTestsCleanupTimer(
    const boost::system::error_code& ecode) {
  LOG(debug) << "SSUServer: handling PeerTests cleanup timer";
  if (ecode != boost::asio::error::operation_aborted) {
    std::size_t num_deleted = 0;
    std::uint64_t ts = kovri::core::GetMillisecondsSinceEpoch();
    for (auto it = m_PeerTests.begin(); it != m_PeerTests.end();) {
      if (ts > it->second.creation_time
               + SSUDuration::PeerTestTimeout
               * 1000LL) {
        num_deleted++;
        it = m_PeerTests.erase(it);
      } else {
        it++;
      }
    }
    if (num_deleted > 0)
      LOG(debug)
        << "SSUServer: " << num_deleted << " peer tests have been expired";
    SchedulePeerTestsCleanupTimer();
  }
}

}  // namespace core
}  // namespace kovri

