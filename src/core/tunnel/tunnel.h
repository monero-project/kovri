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

#ifndef SRC_CORE_TUNNEL_TUNNEL_H_
#define SRC_CORE_TUNNEL_TUNNEL_H_

#include <inttypes.h>

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "i2np_protocol.h"
#include "transit_tunnel.h"
#include "tunnel_base.h"
#include "tunnel_config.h"
#include "tunnel_endpoint.h"
#include "tunnel_gateway.h"
#include "tunnel_pool.h"
#include "util/queue.h"

namespace kovri {
namespace tunnel {

const int TUNNEL_EXPIRATION_TIMEOUT = 660,    // 11 minutes
          TUNNEL_EXPIRATION_THRESHOLD = 60,   // 1 minute
          TUNNEL_RECREATION_THRESHOLD = 90,   // 1.5 minutes
          TUNNEL_CREATION_TIMEOUT = 30,       // 30 seconds
          STANDARD_NUM_RECORDS = 5;           // in VariableTunnelBuild message

enum TunnelState {
  e_TunnelStatePending,
  e_TunnelStateBuildReplyReceived,
  e_TunnelStateBuildFailed,
  e_TunnelStateEstablished,
  e_TunnelStateTestFailed,
  e_TunnelStateFailed,
  e_TunnelStateExpiring
};

class OutboundTunnel;
class InboundTunnel;
class Tunnel : public TunnelBase {
 public:
  Tunnel(
      std::shared_ptr<const TunnelConfig> config);
  ~Tunnel();

  void Build(
      uint32_t reply_msg_ID,
      std::shared_ptr<OutboundTunnel> outbound_tunnel = nullptr);

  std::shared_ptr<const TunnelConfig> GetTunnelConfig() const {
    return m_Config;
  }

  TunnelState GetState() const {
    return m_State;
  }

  void SetState(
      TunnelState state) {
    m_State = state;
  }

  bool IsEstablished() const {
    return m_State == e_TunnelStateEstablished;
  }

  bool IsFailed() const {
    return m_State == e_TunnelStateFailed;
  }

  bool IsRecreated() const {
    return m_IsRecreated;
  }

  void SetIsRecreated() {
    m_IsRecreated = true;
  }

  std::shared_ptr<TunnelPool> GetTunnelPool() const {
    return m_Pool;
  }

  void SetTunnelPool(
      std::shared_ptr<TunnelPool> pool) {
    m_Pool = pool;
  }

  bool HandleTunnelBuildResponse(
      uint8_t* msg,
      size_t len);

  // implements TunnelBase
  void SendTunnelDataMsg(
      std::shared_ptr<kovri::I2NPMessage> msg);

  void EncryptTunnelMsg(
      std::shared_ptr<const I2NPMessage> in,
      std::shared_ptr<I2NPMessage> out);

  uint32_t GetNextTunnelID() const {
    return m_Config->GetFirstHop()->tunnel_ID;
  }

  const kovri::data::IdentHash& GetNextIdentHash() const {
    return m_Config->GetFirstHop()->router->GetIdentHash();
  }

 private:
  std::shared_ptr<const TunnelConfig> m_Config;
  std::shared_ptr<TunnelPool> m_Pool;  // pool, tunnel belongs to, or null
  TunnelState m_State;
  bool m_IsRecreated;
};

class OutboundTunnel
    : public Tunnel  {
 public:
  OutboundTunnel(
      std::shared_ptr<const TunnelConfig> config)
      : Tunnel(config),
        m_Gateway(this) {}

  void SendTunnelDataMsg(
      const uint8_t* gw_hash,
      uint32_t gw_tunnel,
      std::shared_ptr<kovri::I2NPMessage> msg);

  // multiple messages
  void SendTunnelDataMsg(
      const std::vector<TunnelMessageBlock>& msgs);

  std::shared_ptr<const kovri::data::RouterInfo> GetEndpointRouter() const {
    return GetTunnelConfig()->GetLastHop()->router;
  }

  size_t GetNumSentBytes() const {
    return m_Gateway.GetNumSentBytes();
  }

  // implements TunnelBase
  void HandleTunnelDataMsg(
      std::shared_ptr<const kovri::I2NPMessage> tunnel_msg);

  uint32_t GetTunnelID() const {
    return GetNextTunnelID();
  }

 private:
  std::mutex m_SendMutex;
  TunnelGateway m_Gateway;
};

class InboundTunnel
    : public Tunnel,
      public std::enable_shared_from_this<InboundTunnel> {
 public:
  InboundTunnel(
      std::shared_ptr<const TunnelConfig> config)
      : Tunnel(config),
        m_Endpoint(true) {}

  void HandleTunnelDataMsg(
      std::shared_ptr<const I2NPMessage> msg);

  size_t GetNumReceivedBytes() const {
    return m_Endpoint.GetNumReceivedBytes();
  }

  // implements TunnelBase
  uint32_t GetTunnelID() const {
    return GetTunnelConfig()->GetLastHop()->next_tunnel_ID;
  }

 private:
  TunnelEndpoint m_Endpoint;
};


class Tunnels {
 public:
  Tunnels();
  ~Tunnels();
  void Start();
  void Stop();

  std::shared_ptr<InboundTunnel> GetInboundTunnel(
      uint32_t tunnel_ID);

  std::shared_ptr<InboundTunnel> GetPendingInboundTunnel(
      uint32_t reply_msg_ID);

  std::shared_ptr<OutboundTunnel> GetPendingOutboundTunnel(
      uint32_t reply_msg_ID);

  std::shared_ptr<InboundTunnel> GetNextInboundTunnel();

  std::shared_ptr<OutboundTunnel> GetNextOutboundTunnel();

  std::shared_ptr<TunnelPool> GetExploratoryPool() const {
    return m_ExploratoryPool;
  }

  TransitTunnel* GetTransitTunnel(
      uint32_t tunnel_ID);

  int GetTransitTunnelsExpirationTimeout();

  void AddTransitTunnel(
      TransitTunnel* tunnel);

  void AddOutboundTunnel(
      std::shared_ptr<OutboundTunnel> new_tunnel);

  void AddInboundTunnel(
      std::shared_ptr<InboundTunnel> new_tunnel);

  void PostTunnelData(
      std::shared_ptr<I2NPMessage> msg);

  void PostTunnelData(
      const std::vector<std::shared_ptr<I2NPMessage> >& msgs);

  template<class TTunnel>
  std::shared_ptr<TTunnel> CreateTunnel(
      std::shared_ptr<TunnelConfig> config,
      std::shared_ptr<OutboundTunnel> outbound_tunnel = nullptr);

  void AddPendingTunnel(
      uint32_t reply_msg_ID,
      std::shared_ptr<InboundTunnel> tunnel);  // inbound
  void AddPendingTunnel(
      uint32_t reply_msg_ID,
      std::shared_ptr<OutboundTunnel> tunnel);  // outbound

  std::shared_ptr<TunnelPool> CreateTunnelPool(
      kovri::garlic::GarlicDestination* local_destination,
      int num_inbound_hops,
      int num_oubound_hops,
      int num_inbound_tunnels,
      int num_outbound_tunnels);

  void DeleteTunnelPool(
      std::shared_ptr<TunnelPool> pool);

  void StopTunnelPool(
      std::shared_ptr<TunnelPool> pool);

 private:
  template<class TTunnel>
  std::shared_ptr<TTunnel> GetPendingTunnel(
      uint32_t reply_msg_ID,
      const std::map<uint32_t,
      std::shared_ptr<TTunnel> >& pending_tunnels);

  void HandleTunnelGatewayMsg(
      TunnelBase* tunnel,
      std::shared_ptr<I2NPMessage> msg);

  void Run();

  void ManageTunnels();

  void ManageOutboundTunnels();

  void ManageInboundTunnels();

  void ManageTransitTunnels();

  void ManagePendingTunnels();

  template<class PendingTunnels>
  void ManagePendingTunnels(
      PendingTunnels& pending_tunnels);

  void ManageTunnelPools();

  void CreateZeroHopsInboundTunnel();

 private:
  bool m_IsRunning;
  std::unique_ptr<std::thread> m_Thread;

  // by reply_msg_ID
  std::map<uint32_t, std::shared_ptr<InboundTunnel> > m_PendingInboundTunnels;
  // by reply_msg_ID
  std::map<uint32_t, std::shared_ptr<OutboundTunnel> > m_PendingOutboundTunnels;

  std::map<uint32_t, std::shared_ptr<InboundTunnel> > m_InboundTunnels;
  std::list<std::shared_ptr<OutboundTunnel> > m_OutboundTunnels;
  std::mutex m_TransitTunnelsMutex;
  std::map<uint32_t, TransitTunnel *> m_TransitTunnels;
  std::mutex m_PoolsMutex;
  std::list<std::shared_ptr<TunnelPool>> m_Pools;
  std::shared_ptr<TunnelPool> m_ExploratoryPool;
  kovri::util::Queue<std::shared_ptr<I2NPMessage> > m_Queue;

  // some stats
  int m_NumSuccesiveTunnelCreations,
      m_NumFailedTunnelCreations;

 public:
  // for HTTP only
  const decltype(m_OutboundTunnels)& GetOutboundTunnels() const {
    return m_OutboundTunnels;
  }

  const decltype(m_InboundTunnels)& GetInboundTunnels() const {
    return m_InboundTunnels;
  }

  const decltype(m_TransitTunnels)& GetTransitTunnels() const {
    return m_TransitTunnels;
  }

  int GetQueueSize() {
    return m_Queue.GetSize();
  }

  int GetTunnelCreationSuccessRate() const {  // in percents
    int total_num =
      m_NumSuccesiveTunnelCreations + m_NumFailedTunnelCreations;
    return total_num ?
      m_NumSuccesiveTunnelCreations * 100 / total_num :
      0;
  }
};

extern Tunnels tunnels;

}  // namespace tunnel
}  // namespace kovri

#endif  // SRC_CORE_TUNNEL_TUNNEL_H_
