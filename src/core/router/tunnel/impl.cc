/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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

#include <string.h>

#include <map>
#include <memory>
#include <thread>
#include <vector>

#include "core/crypto/rand.h"

#include "core/router/context.h"
#include "core/router/i2np.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/impl.h"
#include "core/router/tunnel/impl.h"

#include "core/util/i2p_endian.h"
#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {

Tunnel::Tunnel(
    std::shared_ptr<const TunnelConfig> config)
    : m_Config(config),
      m_Pool(nullptr),
      m_State(e_TunnelStatePending),
      m_IsRecreated(false),
      m_Exception(__func__) {}

Tunnel::~Tunnel() {}

void Tunnel::Build(
    std::uint32_t reply_msg_ID,
    std::shared_ptr<OutboundTunnel> outbound_tunnel) {
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    auto num_hops = m_Config->GetNumHops();
    int num_records = num_hops <= STANDARD_NUM_RECORDS ?
      STANDARD_NUM_RECORDS :
      num_hops;
    auto msg = NewI2NPShortMessage();
    *msg->GetPayload() = num_records;
    msg->len += num_records * TUNNEL_BUILD_RECORD_SIZE + 1;
    // shuffle records
    std::vector<int> record_indicies;
    for (int i = 0; i < num_records; i++)
      record_indicies.push_back(i);
    kovri::core::Shuffle(record_indicies.begin(), record_indicies.end());
    // create real records
    std::uint8_t* records = msg->GetPayload() + 1;
    TunnelHopConfig* hop = m_Config->GetFirstHop();
    int i = 0;
    while (hop) {
      int idx = record_indicies[i];
      hop->CreateBuildRequestRecord(
          records + idx * TUNNEL_BUILD_RECORD_SIZE,
          // we set reply_msg_ID for last hop only
          hop->GetNextHop() ? Rand<std::uint32_t>() : reply_msg_ID);
      hop->SetRecordIndex(idx);
      i++;
      hop = hop->GetNextHop();
    }
    // fill up fake records with random data
    for (int i = num_hops; i < num_records; i++) {
      int idx = record_indicies[i];
      kovri::core::RandBytes(
          records + idx * TUNNEL_BUILD_RECORD_SIZE,
          TUNNEL_BUILD_RECORD_SIZE);
    }
    // decrypt real records
    kovri::core::CBCDecryption decryption;
    hop = m_Config->GetLastHop()->GetPreviousHop();
    while (hop) {
      decryption.SetKey(hop->GetAESAttributes().reply_key.data());
      // decrypt records after current hop
      TunnelHopConfig* hop1 = hop->GetNextHop();
      while (hop1) {
        decryption.SetIV(hop->GetAESAttributes().reply_IV.data());
        std::uint8_t* record =
          records + hop1->GetRecordIndex() * TUNNEL_BUILD_RECORD_SIZE;
        decryption.Decrypt(record, TUNNEL_BUILD_RECORD_SIZE, record);
        hop1 = hop1->GetNextHop();
      }
      hop = hop->GetPreviousHop();
    }
    msg->FillI2NPMessageHeader(I2NPVariableTunnelBuild);
    // send message
    if (outbound_tunnel)
      outbound_tunnel->SendTunnelDataMsg(
          GetNextIdentHash(),
          0,
          ToSharedI2NPMessage(std::move(msg)));
    else
      kovri::core::transports.SendMessage(
          GetNextIdentHash(),
          ToSharedI2NPMessage(std::move(msg)));
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

bool Tunnel::HandleTunnelBuildResponse(
    std::uint8_t* msg,
    std::size_t) {
  bool established = true;
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    LOG(debug)
      << "Tunnel: TunnelBuildResponse " << static_cast<int>(msg[0]) << " records.";
    kovri::core::CBCDecryption decryption;
    TunnelHopConfig* hop = m_Config->GetLastHop();
    while (hop) {
      decryption.SetKey(hop->GetAESAttributes().reply_key.data());
      // decrypt records before and including current hop
      TunnelHopConfig* hop1 = hop;
      while (hop1) {
        auto idx = hop1->GetRecordIndex();
        if (idx >= 0 && idx < msg[0]) {
          std::uint8_t* record = msg + 1 + idx * TUNNEL_BUILD_RECORD_SIZE;
          decryption.SetIV(hop->GetAESAttributes().reply_IV.data());
          decryption.Decrypt(record, TUNNEL_BUILD_RECORD_SIZE, record);
        } else {
          LOG(warning) << "Tunnel: hop index " << idx << " is out of range";
        }
        hop1 = hop1->GetPreviousHop();
      }
      hop = hop->GetPreviousHop();
    }
    hop = m_Config->GetFirstHop();
    while (hop) {
      const std::uint8_t* record =
        msg + 1 + hop->GetRecordIndex() * TUNNEL_BUILD_RECORD_SIZE;
      std::uint8_t ret = record[BUILD_RESPONSE_RECORD_RET_OFFSET];
      LOG(debug) << "Tunnel: ret code=" << static_cast<int>(ret);
      hop->GetCurrentRouter()->GetProfile()->TunnelBuildResponse(ret);
      if (ret)
        // if any of participants declined the tunnel is not established
        established = false;
      hop = hop->GetNextHop();
    }
    if (established) {
      // change reply keys to layer keys
      hop = m_Config->GetFirstHop();
      while (hop) {
        hop->GetDecryption().SetKeys(
            hop->GetAESAttributes().layer_key.data(),
            hop->GetAESAttributes().IV_key.data());
        hop = hop->GetNextHop();
      }
    }
    if (established)
      m_State = e_TunnelStateEstablished;
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  return established;
}

void Tunnel::EncryptTunnelMsg(
    std::shared_ptr<const I2NPMessage> in,
    std::shared_ptr<I2NPMessage> out) {
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    const std::uint8_t* in_payload = in->GetPayload() + 4;
    std::uint8_t* out_payload = out->GetPayload() + 4;
    TunnelHopConfig* hop = m_Config->GetLastHop();
    while (hop) {
      hop->GetDecryption().Decrypt(in_payload, out_payload);
      hop = hop->GetPreviousHop();
      in_payload = out_payload;
    }
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

void Tunnel::SendTunnelDataMsg(
    std::shared_ptr<kovri::core::I2NPMessage>) {
  // TODO(unassigned): review for missing code
  LOG(debug) << "Tunnel: can't send I2NP messages without delivery instructions";
}

void InboundTunnel::HandleTunnelDataMsg(
    std::shared_ptr<const I2NPMessage> msg) {
  // incoming messages means a tunnel is alive
  if (IsFailed())
    SetState(e_TunnelStateEstablished);
  auto new_msg = CreateEmptyTunnelDataMsg();
  EncryptTunnelMsg(msg, new_msg);
  new_msg->from = shared_from_this();
  m_Endpoint.HandleDecryptedTunnelDataMsg(new_msg);
}

void OutboundTunnel::SendTunnelDataMsg(
    const std::uint8_t* gw_hash,
    std::uint32_t gw_tunnel,
    std::shared_ptr<kovri::core::I2NPMessage> msg) {
  TunnelMessageBlock block;
  if (gw_hash) {
    block.hash = gw_hash;
    if (gw_tunnel) {
      block.delivery_type = e_DeliveryTypeTunnel;
      block.tunnel_ID = gw_tunnel;
    } else {
      block.delivery_type = e_DeliveryTypeRouter;
    }
  } else {
    block.delivery_type = e_DeliveryTypeLocal;
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
    std::shared_ptr<const kovri::core::I2NPMessage>) {
  LOG(error)
    << "OutboundTunnel: incoming message for outbound tunnel "
    << GetTunnelID();
}

// Simply instantiating in namespace scope ties into, and is limited by, the current singleton design
// TODO(unassigned): refactoring this requires global work but will help to remove the singleton
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
    std::uint32_t tunnel_ID) {
  auto it = m_InboundTunnels.find(tunnel_ID);
  if (it != m_InboundTunnels.end())
    return it->second;
  return nullptr;
}

TransitTunnel* Tunnels::GetTransitTunnel(
    std::uint32_t tunnel_ID) {
  auto it = m_TransitTunnels.find(tunnel_ID);
  if (it != m_TransitTunnels.end())
    return it->second;
  return nullptr;
}

std::shared_ptr<InboundTunnel> Tunnels::GetPendingInboundTunnel(
    std::uint32_t reply_msg_ID) {
  return GetPendingTunnel(
      reply_msg_ID,
      m_PendingInboundTunnels);
}

std::shared_ptr<OutboundTunnel> Tunnels::GetPendingOutboundTunnel(
    std::uint32_t reply_msg_ID) {
  return GetPendingTunnel(
      reply_msg_ID,
      m_PendingOutboundTunnels);
}

template<class TTunnel>
std::shared_ptr<TTunnel> Tunnels::GetPendingTunnel(
    std::uint32_t reply_msg_ID,
    const std::map<std::uint32_t,
    std::shared_ptr<TTunnel> >& pending_tunnels) {
  auto it = pending_tunnels.find(reply_msg_ID);
  if (it != pending_tunnels.end() &&
      it->second->GetState() == e_TunnelStatePending) {
    it->second->SetState(e_TunnelStateBuildReplyReceived);
    return it->second;
  }
  return nullptr;
}

std::shared_ptr<InboundTunnel> Tunnels::GetNextInboundTunnel() {
  std::shared_ptr<InboundTunnel> tunnel;
  std::size_t min_received = 0;
  for (auto it : m_InboundTunnels) {
    if (!it.second->IsEstablished ())
      continue;
    if (!tunnel || it.second->GetNumReceivedBytes() < min_received) {
      tunnel = it.second;
      min_received = it.second->GetNumReceivedBytes();
    }
  }
  return tunnel;
}

std::shared_ptr<OutboundTunnel> Tunnels::GetNextOutboundTunnel() {
  // TODO(unassigned): integer size
  std::uint32_t s = m_OutboundTunnels.size();
  std::uint32_t ind = kovri::core::RandInRange32(0, s - 1);
  std::uint32_t i = 0;
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
    kovri::core::GarlicDestination* local_destination,
    int num_inbound_hops,
    int num_outbound_hops,
    int num_inbound_tunnels,
    int num_outbound_tunnels) {
  auto pool =
    std::make_shared<TunnelPool> (
      local_destination,
      num_inbound_hops,
      num_outbound_hops,
      num_inbound_tunnels,
      num_outbound_tunnels);
  std::unique_lock<std::mutex> l(m_PoolsMutex);
  m_Pools.push_back(pool);
  return pool;
}

void Tunnels::DeleteTunnelPool(
    std::shared_ptr<TunnelPool> pool) {
  LOG(debug) << "Tunnels: deleting tunnel pool";
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
    LOG(error)
      << "Tunnels: transit tunnel "
      << tunnel->GetTunnelID() << " already exists";
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
  std::uint64_t last_ts = 0;
  while (m_IsRunning) {
    try {
      auto msg = m_Queue.GetNextWithTimeout(1000);  // 1 sec
      if (msg) {
        std::uint32_t prev_tunnel_ID = 0,
                 tunnel_ID = 0;
        TunnelBase* prev_tunnel = nullptr;
        do {
          TunnelBase* tunnel = nullptr;
          std::uint8_t type_ID = msg->GetTypeID();
          switch (type_ID) {
            case I2NPTunnelData:
            case I2NPTunnelGateway: {
              tunnel_ID = bufbe32toh(msg->GetPayload());
              if (tunnel_ID == prev_tunnel_ID)
                tunnel = prev_tunnel;
              else if (prev_tunnel)
                prev_tunnel->FlushTunnelDataMsgs();
              if (!tunnel && type_ID == I2NPTunnelData)
                tunnel = GetInboundTunnel(tunnel_ID).get();
              if (!tunnel)
                tunnel = GetTransitTunnel(tunnel_ID);
              if (tunnel) {
                if (type_ID == I2NPTunnelData)
                  tunnel->HandleTunnelDataMsg(msg);
                else  // tunnel gateway assumed
                  HandleTunnelGatewayMsg(tunnel, msg);
              } else {
                LOG(warning) << "Tunnels: tunnel " << tunnel_ID << " not found";
              }
              break;
            }
            case I2NPVariableTunnelBuild:
            case I2NPVariableTunnelBuildReply:
            case I2NPTunnelBuild:
            case I2NPTunnelBuildReply:
              HandleI2NPMessage(msg->GetBuffer(), msg->GetLength());
            break;
            default:
              LOG(error)
                << "Tunnels: unexpected messsage type "
                << static_cast<int>(type_ID);
          }
          msg = m_Queue.Get();
          if (msg) {
            prev_tunnel_ID = tunnel_ID;
            prev_tunnel = tunnel;
          } else if (tunnel) {
            tunnel->FlushTunnelDataMsgs();
          }
        }
        while (msg);
      }
      std::uint64_t ts = kovri::core::GetSecondsSinceEpoch();
      if (ts - last_ts >= 15) {  // manage tunnels every 15 seconds
        ManageTunnels();
        last_ts = ts;
      }
    } catch (std::exception& ex) {
      LOG(error) << "Tunnels: " << __func__ << " exception: " << ex.what();
    }
  }
}

void Tunnels::HandleTunnelGatewayMsg(
    TunnelBase* tunnel,
    std::shared_ptr<I2NPMessage> msg) {
  if (!tunnel) {
    LOG(error) << "Tunnels: missing tunnel for TunnelGateway";
    return;
  }
  const std::uint8_t* payload = msg->GetPayload();
  std::uint16_t len = bufbe16toh(payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET);
  // we make payload as new I2NP message to send
  msg->offset += I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE;
  msg->len = msg->offset + len;
  auto type_ID = msg->GetTypeID();
  LOG(debug)
    << "Tunnels: TunnelGateway of " << static_cast<int>(len)
    << " bytes for tunnel " << tunnel->GetTunnelID()
    << ". Msg type " << static_cast<int>(type_ID);
  if (type_ID == I2NPDatabaseStore || type_ID == I2NPDatabaseSearchReply)
    // transit DatabaseStore my contain new/updated RI
    // or DatabaseSearchReply with new routers
    kovri::core::netdb.PostI2NPMsg(msg);
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
    PendingTunnels& pending_tunnels) {
  // check pending tunnel. delete failed or timeout
  std::uint64_t ts = kovri::core::GetSecondsSinceEpoch();
  for (auto it = pending_tunnels.begin(); it != pending_tunnels.end();) {
    auto tunnel = it->second;
    switch (tunnel->GetState()) {
      case e_TunnelStatePending:
        if (ts > tunnel->GetCreationTime() + TUNNEL_CREATION_TIMEOUT) {
          LOG(debug)
            << "Tunnels: pending tunnel build request "
            << it->first << " timeout. Deleted";
          // update stats
          auto config = tunnel->GetTunnelConfig();
          if (config) {
            auto hop = config->GetFirstHop();
            while (hop) {
              if (hop->GetCurrentRouter())
                hop->GetCurrentRouter()->GetProfile()->TunnelNonReplied();
              hop = hop->GetNextHop();
            }
          }
          // delete
          it = pending_tunnels.erase(it);
          m_NumFailedTunnelCreations++;
        } else {
          it++;
        }
      break;
      case e_TunnelStateBuildFailed:
        LOG(debug)
          << "Tunnels: pending tunnel build request "
          << it->first << " failed. Deleted";
        it = pending_tunnels.erase(it);
        m_NumFailedTunnelCreations++;
      break;
      case e_TunnelStateBuildReplyReceived:
        // intermediate state, will be either established of build failed
        it++;
      break;
      default:
        // success
        it = pending_tunnels.erase(it);
        m_NumSuccesiveTunnelCreations++;
    }
  }
}

void Tunnels::ManageOutboundTunnels() {
  std::uint64_t ts = kovri::core::GetSecondsSinceEpoch(); {
    for (auto it = m_OutboundTunnels.begin(); it != m_OutboundTunnels.end();) {
      auto tunnel = *it;
      if (ts > tunnel->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT) {
        LOG(debug) << "Tunnels: tunnel " << tunnel->GetTunnelID() << " expired";
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
    auto inbound_tunnel = GetNextInboundTunnel();
    auto router = kovri::core::netdb.GetRandomRouter();
    if (!inbound_tunnel || !router)
      return;
    LOG(debug) << "Tunnels: creating one hop outbound tunnel";
    CreateTunnel<OutboundTunnel> (
        std::make_shared<TunnelConfig> (
          std::vector<std::shared_ptr<const kovri::core::RouterInfo> > { router },
          inbound_tunnel->GetTunnelConfig()));
  }
}

void Tunnels::ManageInboundTunnels() {
  std::uint64_t ts = kovri::core::GetSecondsSinceEpoch(); {
    for (auto it = m_InboundTunnels.begin(); it != m_InboundTunnels.end();) {
      auto tunnel = it->second;
      if (ts > tunnel->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT) {
        LOG(debug) << "Tunnels: tunnel " << tunnel->GetTunnelID() << " expired";
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
    LOG(debug) << "Tunnels: creating zero hops inbound tunnel";
    CreateZeroHopsInboundTunnel();
    if (!m_ExploratoryPool)
      m_ExploratoryPool =
        // 2-hop exploratory, 5 tunnels
        CreateTunnelPool(&kovri::context, 2, 2, 5, 5);
    return;
  }
  if (m_OutboundTunnels.empty() || m_InboundTunnels.size() < 5) {
    // trying to create one more inbound tunnel
    auto router = kovri::core::netdb.GetRandomRouter();
    LOG(debug) << "Tunnels: creating one hop inbound tunnel";
    CreateTunnel<InboundTunnel> (
        std::make_shared<TunnelConfig> (
          std::vector<std::shared_ptr<const kovri::core::RouterInfo> > {router}));
  }
}

void Tunnels::ManageTransitTunnels() {
  std::uint64_t ts = kovri::core::GetSecondsSinceEpoch();
  for (auto it = m_TransitTunnels.begin(); it != m_TransitTunnels.end();) {
    if (ts > it->second->GetCreationTime() + TUNNEL_EXPIRATION_TIMEOUT) {
      auto tmp = it->second;
      LOG(debug) << "Tunnels: transit tunnel " << tmp->GetTunnelID() << " expired"; {
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
    std::shared_ptr<OutboundTunnel> outbound_tunnel) {
  auto new_tunnel = std::make_shared<TTunnel> (config);
  std::uint32_t reply_msg_ID = kovri::core::Rand<std::uint32_t>();
  AddPendingTunnel(reply_msg_ID, new_tunnel);
  new_tunnel->Build(reply_msg_ID, outbound_tunnel);
  return new_tunnel;
}

void Tunnels::AddPendingTunnel(
    std::uint32_t reply_msg_ID,
    std::shared_ptr<InboundTunnel> tunnel) {
  m_PendingInboundTunnels[reply_msg_ID] = tunnel;
}

void Tunnels::AddPendingTunnel(
    std::uint32_t reply_msg_ID,
    std::shared_ptr<OutboundTunnel> tunnel) {
  m_PendingOutboundTunnels[reply_msg_ID] = tunnel;
}

void Tunnels::AddOutboundTunnel(
    std::shared_ptr<OutboundTunnel> new_tunnel) {
  m_OutboundTunnels.push_back(new_tunnel);
  auto pool = new_tunnel->GetTunnelPool();
  if (pool && pool->IsActive())
    pool->TunnelCreated(new_tunnel);
  else
    new_tunnel->SetTunnelPool(nullptr);
}

void Tunnels::AddInboundTunnel(
    std::shared_ptr<InboundTunnel> new_tunnel) {
  m_InboundTunnels[new_tunnel->GetTunnelID()] = new_tunnel;
  auto pool = new_tunnel->GetTunnelPool();
  if (!pool) {
    // build symmetric outbound tunnel
    CreateTunnel<OutboundTunnel> (
        new_tunnel->GetTunnelConfig()->Invert(),
        GetNextOutboundTunnel());
  } else {
    if (pool->IsActive())
      pool->TunnelCreated(new_tunnel);
    else
      new_tunnel->SetTunnelPool(nullptr);
  }
}

void Tunnels::CreateZeroHopsInboundTunnel() {
  CreateTunnel<InboundTunnel> (
      std::make_shared<TunnelConfig> (
        std::vector<std::shared_ptr<const kovri::core::RouterInfo> > {
        kovri::context.GetSharedRouterInfo()
      }));
}

std::uint64_t Tunnels::GetTransitTunnelsExpirationTimeout()
{
  std::uint64_t timeout = 0;
  std::uint64_t timestamp = kovri::core::GetSecondsSinceEpoch();
  std::unique_lock<std::mutex> l(m_TransitTunnelsMutex);
  for (auto tunnel : m_TransitTunnels)
    {
      std::uint64_t time = tunnel.second->GetCreationTime()
                           + TUNNEL_EXPIRATION_TIMEOUT - timestamp;
      if (time > timeout)
        timeout = time;
    }
  return timeout;
}

}  // namespace core
}  // namespace kovri
