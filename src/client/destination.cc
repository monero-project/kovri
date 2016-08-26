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

#include "destination.h"

#include <boost/lexical_cast.hpp>

#include <algorithm>
#include <cassert>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "address_book.h"
#include "net_db.h"
#include "crypto/elgamal.h"
#include "crypto/rand.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace client {

ClientDestination::ClientDestination(
    const i2p::data::PrivateKeys& keys,
    bool is_public,
    const std::map<std::string, std::string> * params)
    : m_IsRunning(false),
      m_Thread(nullptr),
      m_Work(m_Service),
      m_Keys(keys),
      m_IsPublic(is_public),
      m_PublishReplyToken(0),
      m_DatagramDestination(nullptr),
      m_PublishConfirmationTimer(m_Service),
      m_CleanupTimer(m_Service) {
  i2p::crypto::GenerateElGamalKeyPair(
      m_EncryptionPrivateKey,
      m_EncryptionPublicKey);
  int inbound_tunnel_len = DEFAULT_INBOUND_TUNNEL_LENGTH,
      outbound_tunnel_len = DEFAULT_OUTBOUND_TUNNEL_LENGTH,
      inbound_tunnels_quantity = DEFAULT_INBOUND_TUNNELS_QUANTITY,
      outbound_tunnels_quantity = DEFAULT_OUTBOUND_TUNNELS_QUANTITY;
  std::shared_ptr<std::vector<i2p::data::IdentHash> > explicit_peers;
  if (params) {
    auto it = params->find(I2CP_PARAM_INBOUND_TUNNEL_LENGTH);
    if (it != params->end()) {
      int len = boost::lexical_cast<int>(it->second);
      if (len > 0) {
        inbound_tunnel_len = len;
        LogPrint(eLogInfo, "ClientDestination: inbound tunnel length set to ", len);
      }
    }
    it = params->find(I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH);
    if (it != params->end()) {
      int len = boost::lexical_cast<int>(it->second);
      if (len > 0) {
        outbound_tunnel_len = len;
        LogPrint(eLogInfo,
            "ClientDestination: outbound tunnel length set to ", len);
      }
    }
    it = params->find(I2CP_PARAM_INBOUND_TUNNELS_QUANTITY);
    if (it != params->end()) {
      int quantity = boost::lexical_cast<int>(it->second);
      if (quantity > 0) {
        inbound_tunnels_quantity = quantity;
        LogPrint(eLogInfo,
            "ClientDestination: inbound tunnels quantity set to ", quantity);
      }
    }
    it = params->find(I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY);
    if (it != params->end()) {
      int quantity = boost::lexical_cast<int>(it->second);
      if (quantity > 0) {
        outbound_tunnels_quantity = quantity;
        LogPrint(eLogInfo,
            "ClientDestination: outbound tunnels quantity set to ", quantity);
      }
    }
    it = params->find(I2CP_PARAM_EXPLICIT_PEERS);
    if (it != params->end()) {
      explicit_peers = std::make_shared<std::vector<i2p::data::IdentHash> >();
      std::stringstream ss(it->second);
      std::string b64;
      while (std::getline(ss, b64, ',')) {
        i2p::data::IdentHash ident;
        ident.FromBase64(b64);
        explicit_peers->push_back(ident);
      }
      LogPrint(eLogInfo,
          "ClientDestination: explicit peers set to ", it->second);
    }
  }
  m_Pool =
    i2p::tunnel::tunnels.CreateTunnelPool(
        this,
        inbound_tunnel_len,
        outbound_tunnel_len,
        inbound_tunnels_quantity,
        outbound_tunnels_quantity);
  if (explicit_peers)
    m_Pool->SetExplicitPeers(explicit_peers);
  if (m_IsPublic)
    LogPrint(eLogInfo,
        "ClientDestination: created local address ",
        i2p::client::GetB32Address(GetIdentHash()));
  // TODO(unassigned): ???
  m_StreamingDestination =
    std::make_shared<i2p::stream::StreamingDestination> (*this);
}

ClientDestination::~ClientDestination() {
  if (m_IsRunning)
    Stop();
  for (auto it : m_LeaseSetRequests)
    delete it.second;
  if (m_Pool)
    i2p::tunnel::tunnels.DeleteTunnelPool(m_Pool);
  if (m_DatagramDestination)
    delete m_DatagramDestination;
}

void ClientDestination::Run() {
  while (m_IsRunning) {
    try {
      m_Service.run();
    } catch (std::exception& ex) {
      LogPrint(eLogError,
          "ClientDestination::Run() exception: ", ex.what());
    }
  }
}

void ClientDestination::Start() {
  if (!m_IsRunning) {
    m_IsRunning = true;
    m_Pool->SetLocalDestination(this);
    m_Pool->SetActive(true);
    m_Thread =
      std::make_unique<std::thread>(
          std::bind(
              &ClientDestination::Run,
              this));
    m_StreamingDestination->Start();
    for (auto it : m_StreamingDestinationsByPorts)
      it.second->Start();
    m_CleanupTimer.expires_from_now(
        boost::posix_time::minutes(
            DESTINATION_CLEANUP_TIMEOUT));
    m_CleanupTimer.async_wait(
        std::bind(
            &ClientDestination::HandleCleanupTimer,
            this,
            std::placeholders::_1));
  }
}

void ClientDestination::Stop() {
  if (m_IsRunning) {
    m_CleanupTimer.cancel();
    m_IsRunning = false;
    m_StreamingDestination->Stop();
    for (auto it : m_StreamingDestinationsByPorts)
      it.second->Stop();
    if (m_DatagramDestination) {
      auto d = m_DatagramDestination;
      m_DatagramDestination = nullptr;
      delete d;
    }
    if (m_Pool) {
      m_Pool->SetLocalDestination(nullptr);
      i2p::tunnel::tunnels.StopTunnelPool(m_Pool);
    }
    m_Service.stop();
    if (m_Thread) {
      m_Thread->join();
      m_Thread.reset(0);
    }
  }
}

std::shared_ptr<const i2p::data::LeaseSet> ClientDestination::FindLeaseSet(
    const i2p::data::IdentHash& ident) {
  auto it = m_RemoteLeaseSets.find(ident);
  if (it != m_RemoteLeaseSets.end()) {
    if (it->second->HasNonExpiredLeases())
      return it->second;
    else
      LogPrint(eLogInfo,
          "ClientDestination: all leases of remote LeaseSet expired");
  } else {
    auto ls = i2p::data::netdb.FindLeaseSet(ident);
    if (ls) {
      m_RemoteLeaseSets[ident] = ls;
      return ls;
    }
  }
  return nullptr;
}

std::shared_ptr<const i2p::data::LeaseSet> ClientDestination::GetLeaseSet() {
  if (!m_Pool)
    return nullptr;
  if (!m_LeaseSet)
    UpdateLeaseSet();
  return m_LeaseSet;
}

void ClientDestination::UpdateLeaseSet() {
  m_LeaseSet.reset(new i2p::data::LeaseSet(*m_Pool));
}

bool ClientDestination::SubmitSessionKey(
    const uint8_t* key,
    const uint8_t* tag) {
  struct {
    uint8_t k[32], t[32];
  } data;
  memcpy(data.k, key, 32);
  memcpy(data.t, tag, 32);
  m_Service.post([this, data](void) {
      this->AddSessionKey(data.k, data.t);
    });
  return true;
}

void ClientDestination::ProcessGarlicMessage(
    std::shared_ptr<I2NPMessage> msg) {
  m_Service.post(
      std::bind(
          &ClientDestination::HandleGarlicMessage,
          this,
          msg));
}

void ClientDestination::ProcessDeliveryStatusMessage(
    std::shared_ptr<I2NPMessage> msg) {
  m_Service.post(
      std::bind(
          &ClientDestination::HandleDeliveryStatusMessage,
          this,
          msg));
}

void ClientDestination::HandleI2NPMessage(
    const uint8_t* buf,
    size_t,
    std::shared_ptr<i2p::tunnel::InboundTunnel> from) {
  uint8_t typeID = buf[I2NP_HEADER_TYPEID_OFFSET];
  switch (typeID) {
    case e_I2NPData:
      HandleDataMessage(
          buf + I2NP_HEADER_SIZE,
          bufbe16toh(
              buf + I2NP_HEADER_SIZE_OFFSET));
    break;
    case e_I2NPDeliveryStatus:
      // we assume tunnel tests non-encrypted
      HandleDeliveryStatusMessage(
          CreateI2NPMessage(
              buf,
              GetI2NPMessageLength(buf),
              from));
    break;
    case e_I2NPDatabaseStore:
      HandleDatabaseStoreMessage(
          buf + I2NP_HEADER_SIZE,
          bufbe16toh(
              buf + I2NP_HEADER_SIZE_OFFSET));
    break;
    case e_I2NPDatabaseSearchReply:
      HandleDatabaseSearchReplyMessage(
          buf + I2NP_HEADER_SIZE,
          bufbe16toh(
              buf + I2NP_HEADER_SIZE_OFFSET));
    break;
    default:
      i2p::HandleI2NPMessage(
          CreateI2NPMessage(
              buf,
              GetI2NPMessageLength(buf),
              from));
  }
}

void ClientDestination::HandleDatabaseStoreMessage(
    const uint8_t* buf,
    size_t len) {
  uint32_t replyToken = bufbe32toh(buf + DATABASE_STORE_REPLY_TOKEN_OFFSET);
  size_t offset = DATABASE_STORE_HEADER_SIZE;
  if (replyToken) {
    LogPrint(eLogInfo,
        "ClientDestination: reply token is ignored for DatabaseStore");
    offset += 36;
  }
  // LeaseSet
  std::shared_ptr<i2p::data::LeaseSet> lease_set;
  if (buf[DATABASE_STORE_TYPE_OFFSET] == 1) {
    LogPrint(eLogDebug, "ClientDestination: remote LeaseSet");
    auto it = m_RemoteLeaseSets.find(buf + DATABASE_STORE_KEY_OFFSET);
    if (it != m_RemoteLeaseSets.end()) {
      lease_set = it->second;
      lease_set->Update(buf + offset, len - offset);
      if (lease_set->IsValid()) {
        LogPrint(eLogDebug, "ClientDestination: remote LeaseSet updated");
      } else {
        LogPrint(eLogError, "ClientDestination: remote LeaseSet update failed");
        m_RemoteLeaseSets.erase(it);
        lease_set = nullptr;
      }
    } else {
      lease_set =
        std::make_shared<i2p::data::LeaseSet> (buf + offset, len - offset);
      if (lease_set->IsValid()) {
        LogPrint(eLogDebug, "ClientDestination: new remote LeaseSet added");
        m_RemoteLeaseSets[buf + DATABASE_STORE_KEY_OFFSET] = lease_set;
      } else {
        LogPrint(eLogError,
            "ClientDestination: new remote LeaseSet verification failed");
        lease_set = nullptr;
      }
    }
  } else {
    LogPrint(eLogError,
        "ClientDestination: unexpected client's DatabaseStore type ",
        buf[DATABASE_STORE_TYPE_OFFSET], ". Dropped");
  }
  auto it1 = m_LeaseSetRequests.find(buf + DATABASE_STORE_KEY_OFFSET);
  if (it1 != m_LeaseSetRequests.end()) {
    it1->second->request_timeout_timer.cancel();
    if (it1->second->request_complete)
      it1->second->request_complete(lease_set);
    delete it1->second;
    m_LeaseSetRequests.erase(it1);
  }
}

void ClientDestination::HandleDatabaseSearchReplyMessage(
    const uint8_t* buf,
    size_t) {
  i2p::data::IdentHash key(buf);
  int num = buf[32];  // num
  LogPrint(eLogInfo,
      "ClientDestination: DatabaseSearchReply for ",
      key.ToBase64(), " num=", num);
  auto it = m_LeaseSetRequests.find(key);
  if (it != m_LeaseSetRequests.end()) {
    LeaseSetRequest* request = it->second;
    bool found = false;
    if (request->excluded.size() < MAX_NUM_FLOODFILLS_PER_REQUEST) {
      for (int i = 0; i < num; i++) {
        i2p::data::IdentHash peerHash(buf + 33 + i * 32);
        auto floodfill = i2p::data::netdb.FindRouter(peerHash);
        if (floodfill) {
          LogPrint(eLogInfo,
              "ClientDestination: requesting ",
              key.ToBase64(), " at ", peerHash.ToBase64());
          if (SendLeaseSetRequest(key, floodfill, request))
            found = true;
        } else {
          LogPrint(eLogInfo,
              "ClientDestination: found new floodfill, requesting it");
          i2p::data::netdb.RequestDestination(peerHash);
        }
      }
      if (!found)
        LogPrint(eLogError,
            "ClientDestination: suggested floodfills are not presented in NetDb");
    } else {
      LogPrint(eLogInfo,
          "ClientDestination: ", key.ToBase64(), " was not found on ",
          MAX_NUM_FLOODFILLS_PER_REQUEST, " floodfills");
    }
    if (!found) {
      if (request->request_complete)
        request->request_complete(nullptr);
      delete request;
      m_LeaseSetRequests.erase(key);
    }
  } else {
    LogPrint(eLogWarn,
        "ClientDestination: request for ", key.ToBase64(), " not found");
  }
}

void ClientDestination::HandleDeliveryStatusMessage(
    std::shared_ptr<I2NPMessage> msg) {
  uint32_t msg_ID =
    bufbe32toh(msg->GetPayload() + DELIVERY_STATUS_MSGID_OFFSET);
  if (msg_ID == m_PublishReplyToken) {
    LogPrint(eLogDebug, "ClientDestination: publishing confirmed");
    m_ExcludedFloodfills.clear();
    m_PublishReplyToken = 0;
  } else {
    i2p::garlic::GarlicDestination::HandleDeliveryStatusMessage(msg);
  }
}

void ClientDestination::SetLeaseSetUpdated() {
  i2p::garlic::GarlicDestination::SetLeaseSetUpdated();
  UpdateLeaseSet();
  if (m_IsPublic)
    Publish();
}

void ClientDestination::Publish() {
  if (!m_LeaseSet || !m_Pool) {
    LogPrint(eLogError,
        "ClientDestination: can't publish non-existing LeaseSet");
    return;
  }
  if (m_PublishReplyToken) {
    LogPrint(eLogInfo, "Publishing is pending");
    return;
  }
  auto outbound = m_Pool->GetNextOutboundTunnel();
  if (!outbound) {
    LogPrint(eLogError,
        "ClientDestination: can't publish LeaseSet, no outbound tunnels");
    return;
  }
  std::set<i2p::data::IdentHash> excluded;
  auto floodfill =
    i2p::data::netdb.GetClosestFloodfill(
        m_LeaseSet->GetIdentHash(),
        m_ExcludedFloodfills);
  if (!floodfill) {
    LogPrint(eLogError,
        "ClientDestination: can't publish LeaseSet, no more floodfills found");
    m_ExcludedFloodfills.clear();
    return;
  }
  m_ExcludedFloodfills.insert(floodfill->GetIdentHash());
  LogPrint(eLogDebug,
      "ClientDestination: publish LeaseSet of ", GetIdentHash().ToBase32());
  m_PublishReplyToken = i2p::crypto::Rand<uint32_t>();
  auto msg =
    WrapMessage(
        floodfill,
        i2p::CreateDatabaseStoreMsg(
            m_LeaseSet,
            m_PublishReplyToken));
  m_PublishConfirmationTimer.expires_from_now(
      boost::posix_time::seconds(
          PUBLISH_CONFIRMATION_TIMEOUT));
  m_PublishConfirmationTimer.async_wait(
      std::bind(
          &ClientDestination::HandlePublishConfirmationTimer,
          this,
          std::placeholders::_1));
  outbound->SendTunnelDataMsg(floodfill->GetIdentHash(), 0, msg);
}

void ClientDestination::HandlePublishConfirmationTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    if (m_PublishReplyToken) {
      LogPrint(eLogWarn,
          "ClientDestination: publish confirmation was not received in ",
          PUBLISH_CONFIRMATION_TIMEOUT,  "seconds. Try again");
      m_PublishReplyToken = 0;
      Publish();
    }
  }
}

void ClientDestination::HandleDataMessage(
    const uint8_t* buf,
    size_t) {
  uint32_t length = bufbe32toh(buf);
  buf += 4;
  // we assume I2CP payload
  uint16_t from_port = bufbe16toh(buf + 4),  // source
    to_port = bufbe16toh(buf + 6);  // destination
  switch (buf[9]) {
    case PROTOCOL_TYPE_STREAMING: {
      // streaming protocol
      auto dest = GetStreamingDestination(to_port);
      if (dest)
        dest->HandleDataMessagePayload(buf, length);
      else
        LogPrint(eLogWarn,
            "ClientDestination: missing streaming destination");
    }
    break;
    case PROTOCOL_TYPE_DATAGRAM:
      // datagram protocol
      if (m_DatagramDestination)
        m_DatagramDestination->HandleDataMessagePayload(
            from_port,
            to_port,
            buf,
            length);
      else
        LogPrint(eLogWarn,
            "ClientDestination: missing streaming destination");
    break;
    default:
      LogPrint(eLogWarn,
          "ClientDestination: HandleDataMessage(): unexpected protocol ", buf[9]);
  }
}

void ClientDestination::CreateStream(
    StreamRequestComplete stream_request_complete,
    const i2p::data::IdentHash& dest,
    int port) {
  assert(stream_request_complete);
  auto lease_set = FindLeaseSet(dest);
  if (lease_set) {
    stream_request_complete(
        CreateStream(
            lease_set,
            port));
  } else {
    RequestDestination(
        dest,
        [this, stream_request_complete, port](
          std::shared_ptr<i2p::data::LeaseSet> ls) {
        if (ls)
          stream_request_complete(
              CreateStream(
                  ls,
                  port));
        else
          stream_request_complete(nullptr);
      });
  }
}

std::shared_ptr<i2p::stream::Stream> ClientDestination::CreateStream(
    std::shared_ptr<const i2p::data::LeaseSet> remote,
    int port) {
  if (m_StreamingDestination)
    return m_StreamingDestination->CreateNewOutgoingStream(remote, port);
  else
    return nullptr;
}

std::shared_ptr<i2p::stream::StreamingDestination> ClientDestination::GetStreamingDestination(
    int port) const {
  if (port) {
    auto it = m_StreamingDestinationsByPorts.find(port);
    if (it != m_StreamingDestinationsByPorts.end())
      return it->second;
  }
  // if port is zero or not found, use default destination
  return m_StreamingDestination;
}

void ClientDestination::AcceptStreams(
    const i2p::stream::StreamingDestination::Acceptor& acceptor) {
  if (m_StreamingDestination)
    m_StreamingDestination->SetAcceptor(acceptor);
}

void ClientDestination::StopAcceptingStreams() {
  if (m_StreamingDestination)
    m_StreamingDestination->ResetAcceptor();
}

bool ClientDestination::IsAcceptingStreams() const {
  if (m_StreamingDestination)
    return m_StreamingDestination->IsAcceptorSet();
  return false;
}

std::shared_ptr<i2p::stream::StreamingDestination> ClientDestination::CreateStreamingDestination(
    int port) {
  auto dest =
    std::make_shared<i2p::stream::StreamingDestination> (
        *this,
        port);
  if (port)
    m_StreamingDestinationsByPorts[port] = dest;
  else  // update default
    m_StreamingDestination = dest;
  return dest;
}

i2p::datagram::DatagramDestination* ClientDestination::CreateDatagramDestination() {
  if (!m_DatagramDestination)
    m_DatagramDestination = new i2p::datagram::DatagramDestination(*this);
  return m_DatagramDestination;
}

bool ClientDestination::RequestDestination(
    const i2p::data::IdentHash& dest,
    RequestComplete request_complete) {
  if (!m_Pool || !IsReady()) {
    if (request_complete)
      request_complete(nullptr);
    return false;
  }
  m_Service.post(
      std::bind(
          &ClientDestination::RequestLeaseSet,
          this,
          dest,
          request_complete));
  return true;
}

void ClientDestination::RequestLeaseSet(
    const i2p::data::IdentHash& dest,
    RequestComplete request_complete) {
  std::set<i2p::data::IdentHash> excluded;
  auto floodfill =
    i2p::data::netdb.GetClosestFloodfill(
        dest,
        excluded);
  if (floodfill) {
    LeaseSetRequest* request = new LeaseSetRequest(m_Service);
    request->request_complete = request_complete;
    auto ret =
      m_LeaseSetRequests.insert(
          std::pair<i2p::data::IdentHash, LeaseSetRequest *>(
            dest,
            request));
    if (ret.second) {  // inserted
      if (!SendLeaseSetRequest(dest, floodfill, request)) {
        // request failed
        if (request->request_complete)
          request->request_complete(nullptr);
        delete request;
        m_LeaseSetRequests.erase(dest);
      }
    } else {  // duplicate
      LogPrint(eLogError,
          "ClientDestination: request of ", dest.ToBase64(), " is pending already");
      // TODO(unassigned): queue up requests
      if (request->request_complete)
        request->request_complete(nullptr);
      delete request;
    }
  } else {
    LogPrint(eLogError, "ClientDestination: no floodfills found");
  }
}

bool ClientDestination::SendLeaseSetRequest(
    const i2p::data::IdentHash& dest,
    std::shared_ptr<const i2p::data::RouterInfo> next_floodfill,
    LeaseSetRequest* request) {
  auto reply_tunnel = m_Pool->GetNextInboundTunnel();
  if (!reply_tunnel)
    LogPrint(eLogError, "ClientDestination: no inbound tunnels found");
  auto outboundTunnel = m_Pool->GetNextOutboundTunnel();
  if (!outboundTunnel)
    LogPrint(eLogError, "ClientDestination: no outbound tunnels found");
  if (reply_tunnel && outboundTunnel) {
    request->excluded.insert(next_floodfill->GetIdentHash());
    request->request_time = i2p::util::GetSecondsSinceEpoch();
    request->request_timeout_timer.cancel();
    uint8_t reply_key[32], reply_tag[32];
    i2p::crypto::RandBytes(reply_key, 32);  // random session key
    i2p::crypto::RandBytes(reply_tag, 32);  // random session tag
    AddSessionKey(reply_key, reply_tag);
    auto msg =
      WrapMessage(
          next_floodfill,
          CreateLeaseSetDatabaseLookupMsg(
            dest,
            request->excluded,
            reply_tunnel.get(),
            reply_key,
            reply_tag));
    outboundTunnel->SendTunnelDataMsg({
        i2p::tunnel::TunnelMessageBlock {
            i2p::tunnel::e_DeliveryTypeRouter,
            next_floodfill->GetIdentHash(),
            0,
            msg
        }
    });
    request->request_timeout_timer.expires_from_now(
        boost::posix_time::seconds(
            LEASESET_REQUEST_TIMEOUT));
    request->request_timeout_timer.async_wait(
        std::bind(
            &ClientDestination::HandleRequestTimoutTimer,
            this,
            std::placeholders::_1,
            dest));
  } else {
    return false;
  }
  return true;
}

void ClientDestination::HandleRequestTimoutTimer(
    const boost::system::error_code& ecode,
    const i2p::data::IdentHash& dest) {
  if (ecode != boost::asio::error::operation_aborted) {
    auto it = m_LeaseSetRequests.find(dest);
    if (it != m_LeaseSetRequests.end()) {
      bool done = false;
      uint64_t ts = i2p::util::GetSecondsSinceEpoch();
      if (ts < it->second->request_time + MAX_LEASESET_REQUEST_TIMEOUT) {
        auto floodfill =
          i2p::data::netdb.GetClosestFloodfill(
              dest,
              it->second->excluded);
        if (floodfill)
           done = !SendLeaseSetRequest(dest, floodfill, it->second);
        else
          done = true;
      } else {
        LogPrint(eLogInfo,
            "ClientDestination: ",
            dest.ToBase64(), " was not found within ",
            MAX_LEASESET_REQUEST_TIMEOUT, " seconds");
        done = true;
      }
      if (done) {
        if (it->second->request_complete)
          it->second->request_complete(nullptr);
        delete it->second;
        m_LeaseSetRequests.erase(it);
      }
    }
  }
}

void ClientDestination::HandleCleanupTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    CleanupRoutingSessions();
    CleanupRemoteLeaseSets();
    m_CleanupTimer.expires_from_now(
        boost::posix_time::minutes(
            DESTINATION_CLEANUP_TIMEOUT));
    m_CleanupTimer.async_wait(
        std::bind(
            &ClientDestination::HandleCleanupTimer,
            this,
            std::placeholders::_1));
  }
}

void ClientDestination::CleanupRemoteLeaseSets() {
  for (auto it = m_RemoteLeaseSets.begin(); it != m_RemoteLeaseSets.end();) {
    if (!it->second->HasNonExpiredLeases()) {  // all leases expired
      LogPrint(eLogInfo,
          "ClientDestination: remote LeaseSet ",
          it->second->GetIdentHash().ToBase64(), " expired");
      it = m_RemoteLeaseSets.erase(it);
    } else {
      it++;
    }
  }
}

}  // namespace client
}  // namespace i2p
