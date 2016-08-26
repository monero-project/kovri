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

#include <cryptopp/sha.h>

#include <string.h>

#include <algorithm>
#include <map>
#include <memory>
#include <thread>
#include <vector>

#include "crypto/rand.h"
#include "i2np_protocol.h"
#include "net_db.h"
#include "router_context.h"
#include "tunnel.h"
#include "transport/transports.h"
#include "util/i2p_endian.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace tunnel {

Tunnel::Tunnel(
    std::shared_ptr<const TunnelConfig> config)
    : m_Config(config),
      m_Pool(nullptr),
      m_State(e_TunnelStatePending),
      m_IsRecreated(false) {}

Tunnel::~Tunnel() {}

void Tunnel::Build(
    uint32_t replyMsgID,
    std::shared_ptr<OutboundTunnel> outboundTunnel) {
  auto numHops = m_Config->GetNumHops();
  int numRecords = numHops <= STANDARD_NUM_RECORDS ?
    STANDARD_NUM_RECORDS :
    numHops;
  auto msg = NewI2NPShortMessage();
  *msg->GetPayload() = numRecords;
  msg->len += numRecords * TUNNEL_BUILD_RECORD_SIZE + 1;
  // shuffle records
  std::vector<int> recordIndicies;
  for (int i = 0; i < numRecords; i++)
    recordIndicies.push_back(i);
  std::random_shuffle(recordIndicies.begin(), recordIndicies.end());
  // create real records
  uint8_t* records = msg->GetPayload() + 1;
  TunnelHopConfig* hop = m_Config->GetFirstHop();
  int i = 0;
  while (hop) {
    int idx = recordIndicies[i];
    hop->CreateBuildRequestRecord(
        records + idx * TUNNEL_BUILD_RECORD_SIZE,
        // we set replyMsgID for last hop only
        hop->next ? i2p::crypto::Rand<uint32_t>() : replyMsgID);
    hop->recordIndex = idx;
    i++;
    hop = hop->next;
  }
  // fill up fake records with random data
  for (int i = numHops; i < numRecords; i++) {
    int idx = recordIndicies[i];
    i2p::crypto::RandBytes(
        records + idx * TUNNEL_BUILD_RECORD_SIZE,
        TUNNEL_BUILD_RECORD_SIZE);
  }
  // decrypt real records
  i2p::crypto::CBCDecryption decryption;
  hop = m_Config->GetLastHop()->prev;
  while (hop) {
    decryption.SetKey(hop->replyKey);
    // decrypt records after current hop
    TunnelHopConfig* hop1 = hop->next;
    while (hop1) {
      decryption.SetIV(hop->replyIV);
      uint8_t* record =
        records + hop1->recordIndex*TUNNEL_BUILD_RECORD_SIZE;
      decryption.Decrypt(record, TUNNEL_BUILD_RECORD_SIZE, record);
      hop1 = hop1->next;
    }
    hop = hop->prev;
  }
  msg->FillI2NPMessageHeader(e_I2NPVariableTunnelBuild);
  // send message
  if (outboundTunnel)
    outboundTunnel->SendTunnelDataMsg(
        GetNextIdentHash(),
        0,
        ToSharedI2NPMessage(msg));
  else
    i2p::transport::transports.SendMessage(
        GetNextIdentHash(),
        ToSharedI2NPMessage(msg));
}

bool Tunnel::HandleTunnelBuildResponse(
    uint8_t* msg,
    size_t) {
  LogPrint(eLogDebug,
      "Tunnel: TunnelBuildResponse ",
      static_cast<int>(msg[0]), " records.");
  i2p::crypto::CBCDecryption decryption;
  TunnelHopConfig* hop = m_Config->GetLastHop();
  while (hop) {
    decryption.SetKey(hop->replyKey);
    // decrypt records before and including current hop
    TunnelHopConfig* hop1 = hop;
    while (hop1) {
      auto idx = hop1->recordIndex;
      if (idx >= 0 && idx < msg[0]) {
        uint8_t* record = msg + 1 + idx * TUNNEL_BUILD_RECORD_SIZE;
        decryption.SetIV(hop->replyIV);
        decryption.Decrypt(record, TUNNEL_BUILD_RECORD_SIZE, record);
      } else {
        LogPrint(eLogWarn,
            "Tunnel: hop index ", idx, " is out of range");
      }
      hop1 = hop1->prev;
    }
    hop = hop->prev;
  }
  bool established = true;
  hop = m_Config->GetFirstHop();
  while (hop) {
    const uint8_t* record =
      msg + 1 + hop->recordIndex * TUNNEL_BUILD_RECORD_SIZE;
    uint8_t ret = record[BUILD_RESPONSE_RECORD_RET_OFFSET];
    LogPrint("Tunnel: ret code=", static_cast<int>(ret));
    hop->router->GetProfile()->TunnelBuildResponse(ret);
    if (ret)
      // if any of participants declined the tunnel is not established
      established = false;
    hop = hop->next;
  }
  if (established) {
    // change reply keys to layer keys
    hop = m_Config->GetFirstHop();
    while (hop) {
      hop->decryption.SetKeys(hop->layerKey, hop->ivKey);
      hop = hop->next;
    }
  }
  if (established)
    m_State = e_TunnelStateEstablished;
  return established;
}

void Tunnel::EncryptTunnelMsg(
    std::shared_ptr<const I2NPMessage> in,
    std::shared_ptr<I2NPMessage> out) {
  const uint8_t* inPayload = in->GetPayload() + 4;
  uint8_t* outPayload = out->GetPayload() + 4;
  TunnelHopConfig* hop = m_Config->GetLastHop();
  while (hop) {
    hop->decryption.Decrypt(inPayload, outPayload);
    hop = hop->prev;
    inPayload = outPayload;
  }
}

void Tunnel::SendTunnelDataMsg(
    std::shared_ptr<i2p::I2NPMessage>) {
  // TODO(unassigned): review for missing code
  LogPrint(eLogInfo,
      "Tunnel: can't send I2NP messages without delivery instructions");
}

void InboundTunnel::HandleTunnelDataMsg(
    std::shared_ptr<const I2NPMessage> msg) {
  // incoming messages means a tunnel is alive
  if (IsFailed())
    SetState(e_TunnelStateEstablished);
  auto newMsg = CreateEmptyTunnelDataMsg();
  EncryptTunnelMsg(msg, newMsg);
  newMsg->from = shared_from_this();
  m_Endpoint.HandleDecryptedTunnelDataMsg(newMsg);
}

void OutboundTunnel::SendTunnelDataMsg(
    const uint8_t* gwHash,
    uint32_t gwTunnel,
    std::shared_ptr<i2p::I2NPMessage> msg) {
  TunnelMessageBlock block;
  if (gwHash) {
    block.hash = gwHash;
    if (gwTunnel) {
      block.deliveryType = e_DeliveryTypeTunnel;
      block.tunnelID = gwTunnel;
    } else {
      block.deliveryType = e_DeliveryTypeRouter;
    }
  } else {
    block.deliveryType = e_DeliveryTypeLocal;
  }
  block.data = msg;
  std::unique_lock<std::mutex> l(m_SendMutex);
  m_Gateway.SendTunnelDataMsg(block);
}

void OutboundTunnel::SendTunnelDataMsg(
    const std::vector<TunnelMessageBlock>& msgs) {
  std::unique_lock<std::mutex> l(m_SendMutex);
  for (auto& it : msgs)
    m_Gateway.PutTunnelDataMsg(it);
  m_Gateway.SendBuffer();
}

void OutboundTunnel::HandleTunnelDataMsg(
    std::shared_ptr<const i2p::I2NPMessage>) {
  LogPrint(eLogError,
      "OutboundTunnel: incoming message for outbound tunnel ",
      GetTunnelID());
}

Tunnels tunnels;

Tunnels::Tunnels()
    : m_IsRunning(false),
      m_Thread(nullptr),
      m_NumSuccesiveTunnelCreations(0),
      m_NumFailedTunnelCreations(0) {}

Tunnels::~Tunnels() {
  for (auto& it : m_TransitTunnels)
    delete it.second;
  m_TransitTunnels.clear();
}

std::shared_ptr<InboundTunnel> Tunnels::GetInboundTunnel(
    uint32_t tunnelID) {
  auto it = m_InboundTunnels.find(tunnelID);
  if (it != m_InboundTunnels.end())
    return it->second;
  return nullptr;
}

TransitTunnel* Tunnels::GetTransitTunnel(
    uint32_t tunnelID) {
  auto it = m_TransitTunnels.find(tunnelID);
  if (it != m_TransitTunnels.end())
    return it->second;
  return nullptr;
}

std::shared_ptr<InboundTunnel> Tunnels::GetPendingInboundTunnel(
    uint32_t replyMsgID) {
  return GetPendingTunnel(
      replyMsgID,
      m_PendingInboundTunnels);
}

std::shared_ptr<OutboundTunnel> Tunnels::GetPendingOutboundTunnel(
    uint32_t replyMsgID) {
  return GetPendingTunnel(
      replyMsgID,
      m_PendingOutboundTunnels);
}

template<class TTunnel>
std::shared_ptr<TTunnel> Tunnels::GetPendingTunnel(
    uint32_t replyMsgID,
    const std::map<uint32_t,
    std::shared_ptr<TTunnel> >& pendingTunnels) {
  auto it = pendingTunnels.find(replyMsgID);
  if (it != pendingTunnels.end() &&
      it->second->GetState() == e_TunnelStatePending) {
    it->second->SetState(e_TunnelStateBuildReplyReceived);
    return it->second;
  }
  return nullptr;
}

std::shared_ptr<InboundTunnel> Tunnels::GetNextInboundTunnel() {
  std::shared_ptr<InboundTunnel> tunnel;
  size_t minReceived = 0;
  for (auto it : m_InboundTunnels) {
    if (!it.second->IsEstablished ())
      continue;
    if (!tunnel || it.second->GetNumReceivedBytes() < minReceived) {
      tunnel = it.second;
      minReceived = it.second->GetNumReceivedBytes();
    }
  }
  return tunnel;
}

std::shared_ptr<OutboundTunnel> Tunnels::GetNextOutboundTunnel() {
  // TODO(unassigned): integer size
  uint32_t s = m_OutboundTunnels.size();
  uint32_t ind = i2p::crypto::RandInRange<uint32_t>(uint32_t{0}, s - 1);
  uint32_t i = 0;
  std::shared_ptr<OutboundTunnel> tunnel;
  for (auto it : m_OutboundTunnels) {
    if (it->IsEstablished()) {
      tunnel = it;
      i++;
    }
    if (i > ind && tunnel)
      break;
  }
  return tunnel;
}

std::shared_ptr<TunnelPool> Tunnels::CreateTunnelPool(
    i2p::garlic::GarlicDestination* localDestination,
    int numInboundHops,
    int numOutboundHops,
    int numInboundTunnels,
    int numOutboundTunnels) {
  auto pool =
    std::make_shared<TunnelPool> (
      localDestination,
      numInboundHops,
      numOutboundHops,
      numInboundTunnels,
      numOutboundTunnels);
  std::unique_lock<std::mutex> l(m_PoolsMutex);
  m_Pools.push_back(pool);
  return pool;
}

void Tunnels::DeleteTunnelPool(
    std::shared_ptr<TunnelPool> pool) {
  if (pool) {
    StopTunnelPool(pool); {
      std::unique_lock<std::mutex> l(m_PoolsMutex);
      m_Pools.remove(pool);
    }
  }
}

void Tunnels::StopTunnelPool(
    std::shared_ptr<TunnelPool> pool) {
  if (pool) {
    pool->SetActive(false);
    pool->DetachTunnels();
  }
}

void Tunnels::AddTransitTunnel(
    TransitTunnel* tunnel) {
  std::unique_lock<std::mutex> l(m_TransitTunnelsMutex);
  if (!m_TransitTunnels.insert(
        std::make_pair(
          tunnel->GetTunnelID(),
          tunnel)).second) {
    LogPrint(eLogError,
        "Tunnels: transit tunnel ", tunnel->GetTunnelID(), " already exists");
    delete tunnel;
  }
}

void Tunnels::Start() {
  m_IsRunning = true;
  m_Thread =
    std::make_unique<std::thread>(
        std::bind(
          &Tunnels::Run,
          this));
}

void Tunnels::Stop() {
  m_IsRunning = false;
  m_Queue.WakeUp();
  if (m_Thread) {
    m_Thread->join();
    m_Thread.reset(nullptr);
  }
}

void Tunnels::Run() {
  // wait for other parts are ready
  std::this_thread::sleep_for(std::chrono::seconds(1));
  uint64_t lastTs = 0;
  while (m_IsRunning) {
    try {
      auto msg = m_Queue.GetNextWithTimeout(1000);  // 1 sec
      if (msg) {
        uint32_t prevTunnelID = 0,
                 tunnelID = 0;
        TunnelBase* prevTunnel = nullptr;
        do {
          TunnelBase* tunnel = nullptr;
          uint8_t typeID = msg->GetTypeID();
          switch (typeID) {
            case e_I2NPTunnelData:
            case e_I2NPTunnelGateway: {
              tunnelID = bufbe32toh(msg->GetPayload());
              if (tunnelID == prevTunnelID)
                tunnel = prevTunnel;
              else if (prevTunnel)
                prevTunnel->FlushTunnelDataMsgs();
              if (!tunnel && typeID == e_I2NPTunnelData)
                tunnel = GetInboundTunnel(tunnelID).get();
              if (!tunnel)
                tunnel = GetTransitTunnel(tunnelID);
              if (tunnel) {
                if (typeID == e_I2NPTunnelData)
                  tunnel->HandleTunnelDataMsg(msg);
                else  // tunnel gateway assumed
                  HandleTunnelGatewayMsg(tunnel, msg);
              } else {
                LogPrint(eLogWarn,
                    "Tunnels: tunnel ", tunnelID, " not found");
              }
              break;
            }
            case e_I2NPVariableTunnelBuild:
            case e_I2NPVariableTunnelBuildReply:
            case e_I2NPTunnelBuild:
            case e_I2NPTunnelBuildReply:
              HandleI2NPMessage(msg->GetBuffer(), msg->GetLength());
            break;
            default:
              LogPrint(eLogError,
                  "Tunnels: unexpected messsage type ",
                  static_cast<int>(typeID));
          }
          msg = m_Queue.Get();
          if (msg) {
            prevTunnelID = tunnelID;
            prevTunnel = tunnel;
          } else if (tunnel) {
            tunnel->FlushTunnelDataMsgs();
          }
        }
        while (msg);
      }
      uint64_t ts = i2p::util::GetSecondsSinceEpoch();
      if (ts - lastTs >= 15) {  // manage tunnels every 15 seconds
        ManageTunnels();
        lastTs = ts;
      }
    } catch (std::exception& ex) {
      LogPrint("Tunnels::Run() exception: ", ex.what());
    }
  }
}

void Tunnels::HandleTunnelGatewayMsg(
    TunnelBase* tunnel,
    std::shared_ptr<I2NPMessage> msg) {
  if (!tunnel) {
    LogPrint(eLogError, "Tunnels: missing tunnel for TunnelGateway");
    return;
  }
  const uint8_t* payload = msg->GetPayload();
  uint16_t len = bufbe16toh(payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET);
  // we make payload as new I2NP message to send
  msg->offset += I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE;
  msg->len = msg->offset + len;
  auto typeID = msg->GetTypeID();
  LogPrint(eLogDebug,
      "Tunnels: TunnelGateway of ", static_cast<int>(len),
      " bytes for tunnel ", tunnel->GetTunnelID(),
      ". Msg type ", static_cast<int>(typeID));
  if (typeID == e_I2NPDatabaseStore || typeID == e_I2NPDatabaseSearchReply)
    // transit DatabaseStore my contain new/updated RI
    // or DatabaseSearchReply with new routers
    i2p::data::netdb.PostI2NPMsg(msg);
  tunnel->SendTunnelDataMsg(msg);
}

void Tunnels::ManageTunnels() {
  ManagePendingTunnels();
  ManageInboundTunnels();
  ManageOutboundTunnels();
  ManageTransitTunnels();
  ManageTunnelPools();
}

void Tunnels::ManagePendingTunnels() {
  ManagePendingTunnels(m_PendingInboundTunnels);
  ManagePendingTunnels(m_PendingOutboundTunnels);
}

template<class PendingTunnels>
void Tunnels::ManagePendingTunnels(
    PendingTunnels& pendingTunnels) {
  // check pending tunnel. delete failed or timeout
  uint64_t ts = i2p::util::GetSecondsSinceEpoch();
  for (auto it = pendingTunnels.begin(); it != pendingTunnels.end();) {
    auto tunnel = it->second;
    switch (tunnel->GetState()) {
      case e_TunnelStatePending:
        if (ts > tunnel->GetCreationTime() + TUNNEL_CREATION_TIMEOUT) {
          LogPrint(eLogInfo,
              "Tunnels: pending tunnel build request ",
              it->first, " timeout. Deleted");
          // update stats
          auto config = tunnel->GetTunnelConfig();
          if (config) {
            auto hop = config->GetFirstHop();
            while (hop) {
              if (hop->router)
                hop->router->GetProfile()->TunnelNonReplied();
              hop = hop->next;
            }
          }
          // delete
          it = pendingTunnels.erase(it);
          m_NumFailedTunnelCreations++;
        } else {
          it++;
        }
      break;
      case e_TunnelStateBuildFailed:
        LogPrint(eLogInfo,
            "Tunnels: pending tunnel build request ",
            it->first, " failed. Deleted");
        it = pendingTunnels.erase(it);
        m_NumFailedTunnelCreations++;
      break;
      case e_TunnelStateBuildReplyReceived:
        // intermediate state, will be either established of build failed
        it++;
      break;
      default:
        // success
        it = pendingTunnels.erase(it);
        m_NumSuccesiveTunnelCreations++;
    }
  }
}

void Tunnels::ManageOutboundTunnels() {
  uint64_t ts = i2p::util::GetSecondsSinceEpoch(); {
    for (auto it = m_OutboundTunnels.begin(); it != m_OutboundTunnels.end();) {
      auto tunnel = *it;
      if (ts > tunnel->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT) {
        LogPrint(eLogInfo,
            "Tunnels: tunnel ", tunnel->GetTunnelID(), " expired");
        auto pool = tunnel->GetTunnelPool();
        if (pool)
          pool->TunnelExpired(tunnel);
        it = m_OutboundTunnels.erase(it);
      } else {
        if (tunnel->IsEstablished()) {
          if (!tunnel->IsRecreated () &&
              ts + TUNNEL_RECREATION_THRESHOLD >
              tunnel->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT) {
            tunnel->SetIsRecreated();
            auto pool = tunnel->GetTunnelPool();
            if (pool)
              pool->RecreateOutboundTunnel(tunnel);
          }
          if (ts + TUNNEL_EXPIRATION_THRESHOLD >
              tunnel->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT)
            tunnel->SetState(e_TunnelStateExpiring);
        }
        it++;
      }
    }
  }
  if (m_OutboundTunnels.size() < 5) {
    // trying to create one more outbound tunnel
    auto inboundTunnel = GetNextInboundTunnel();
    auto router = i2p::data::netdb.GetRandomRouter();
    if (!inboundTunnel || !router)
      return;
    LogPrint(eLogInfo, "Tunnels: creating one hop outbound tunnel");
    CreateTunnel<OutboundTunnel> (
        std::make_shared<TunnelConfig> (
          std::vector<std::shared_ptr<const i2p::data::RouterInfo> > { router },
          inboundTunnel->GetTunnelConfig()));
  }
}

void Tunnels::ManageInboundTunnels() {
  uint64_t ts = i2p::util::GetSecondsSinceEpoch(); {
    for (auto it = m_InboundTunnels.begin(); it != m_InboundTunnels.end();) {
      auto tunnel = it->second;
      if (ts > tunnel->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT) {
        LogPrint(eLogInfo,
            "Tunnels: tunnel ", tunnel->GetTunnelID(), " expired");
        auto pool = tunnel->GetTunnelPool();
        if (pool)
          pool->TunnelExpired(tunnel);
        it = m_InboundTunnels.erase(it);
      } else {
        if (tunnel->IsEstablished()) {
          if (!tunnel->IsRecreated() &&
              ts + TUNNEL_RECREATION_THRESHOLD >
              tunnel->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT) {
            tunnel->SetIsRecreated();
            auto pool = tunnel->GetTunnelPool();
            if (pool)
              pool->RecreateInboundTunnel(tunnel);
          }
          if (ts + TUNNEL_EXPIRATION_THRESHOLD >
              tunnel->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT)
            tunnel->SetState(e_TunnelStateExpiring);
        }
        it++;
      }
    }
  }
  if (m_InboundTunnels.empty()) {
    LogPrint(eLogInfo,
        "Tunnels: creating zero hops inbound tunnel");
    CreateZeroHopsInboundTunnel();
    if (!m_ExploratoryPool)
      m_ExploratoryPool =
        // 2-hop exploratory, 5 tunnels
        CreateTunnelPool(&i2p::context, 2, 2, 5, 5);
    return;
  }
  if (m_OutboundTunnels.empty() || m_InboundTunnels.size() < 5) {
    // trying to create one more inbound tunnel
    auto router = i2p::data::netdb.GetRandomRouter();
    LogPrint(eLogInfo, "Tunnels: creating one hop inbound tunnel");
    CreateTunnel<InboundTunnel> (
        std::make_shared<TunnelConfig> (
          std::vector<std::shared_ptr<const i2p::data::RouterInfo> > {router}));
  }
}

void Tunnels::ManageTransitTunnels() {
  uint32_t ts = i2p::util::GetSecondsSinceEpoch();
  for (auto it = m_TransitTunnels.begin(); it != m_TransitTunnels.end();) {
    if (ts > it->second->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT) {
      auto tmp = it->second;
      LogPrint(eLogInfo,
          "Tunnels: transit tunnel ", tmp->GetTunnelID(), " expired"); {
        std::unique_lock<std::mutex> l(m_TransitTunnelsMutex);
        it = m_TransitTunnels.erase(it);
      }
      delete tmp;
    } else {
      it++;
    }
  }
}

void Tunnels::ManageTunnelPools() {
  std::unique_lock<std::mutex> l(m_PoolsMutex);
  for (auto it : m_Pools) {
    auto pool = it;
    if (pool && pool->IsActive()) {
      pool->CreateTunnels();
      pool->TestTunnels();
    }
  }
}

void Tunnels::PostTunnelData(
    std::shared_ptr<I2NPMessage> msg) {
  if (msg)
    m_Queue.Put(msg);
}

void Tunnels::PostTunnelData(
    const std::vector<std::shared_ptr<I2NPMessage> >& msgs) {
  m_Queue.Put(msgs);
}

template<class TTunnel>
std::shared_ptr<TTunnel> Tunnels::CreateTunnel(
    std::shared_ptr<TunnelConfig> config,
    std::shared_ptr<OutboundTunnel> outboundTunnel) {
  auto newTunnel = std::make_shared<TTunnel> (config);
  uint32_t replyMsgID = i2p::crypto::Rand<uint32_t>();
  AddPendingTunnel(replyMsgID, newTunnel);
  newTunnel->Build(replyMsgID, outboundTunnel);
  return newTunnel;
}

void Tunnels::AddPendingTunnel(
    uint32_t replyMsgID,
    std::shared_ptr<InboundTunnel> tunnel) {
  m_PendingInboundTunnels[replyMsgID] = tunnel;
}

void Tunnels::AddPendingTunnel(
    uint32_t replyMsgID,
    std::shared_ptr<OutboundTunnel> tunnel) {
  m_PendingOutboundTunnels[replyMsgID] = tunnel;
}

void Tunnels::AddOutboundTunnel(
    std::shared_ptr<OutboundTunnel> newTunnel) {
  m_OutboundTunnels.push_back(newTunnel);
  auto pool = newTunnel->GetTunnelPool();
  if (pool && pool->IsActive())
    pool->TunnelCreated(newTunnel);
  else
    newTunnel->SetTunnelPool(nullptr);
}

void Tunnels::AddInboundTunnel(
    std::shared_ptr<InboundTunnel> newTunnel) {
  m_InboundTunnels[newTunnel->GetTunnelID()] = newTunnel;
  auto pool = newTunnel->GetTunnelPool();
  if (!pool) {
    // build symmetric outbound tunnel
    CreateTunnel<OutboundTunnel> (
        newTunnel->GetTunnelConfig()->Invert(),
        GetNextOutboundTunnel());
  } else {
    if (pool->IsActive())
      pool->TunnelCreated(newTunnel);
    else
      newTunnel->SetTunnelPool(nullptr);
  }
}

void Tunnels::CreateZeroHopsInboundTunnel() {
  CreateTunnel<InboundTunnel> (
      std::make_shared<TunnelConfig> (
        std::vector<std::shared_ptr<const i2p::data::RouterInfo> > {
        i2p::context.GetSharedRouterInfo()
      }));
}

int Tunnels::GetTransitTunnelsExpirationTimeout() {
  int timeout = 0;
  uint32_t ts = i2p::util::GetSecondsSinceEpoch();
  std::unique_lock<std::mutex> l(m_TransitTunnelsMutex);
  for (auto it : m_TransitTunnels) {
    int t = it.second->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT - ts;
    if (t > timeout)
      timeout = t;
  }
  return timeout;
}

}  // namespace tunnel
}  // namespace i2p
