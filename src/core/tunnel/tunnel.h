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

namespace i2p {
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
      uint32_t replyMsgID,
      std::shared_ptr<OutboundTunnel> outboundTunnel = nullptr);

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
      std::shared_ptr<i2p::I2NPMessage> msg);

  void EncryptTunnelMsg(
      std::shared_ptr<const I2NPMessage> in,
      std::shared_ptr<I2NPMessage> out);

  uint32_t GetNextTunnelID() const {
    return m_Config->GetFirstHop()->tunnelID;
  }

  const i2p::data::IdentHash& GetNextIdentHash() const {
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
      const uint8_t* gwHash,
      uint32_t gwTunnel,
      std::shared_ptr<i2p::I2NPMessage> msg);

  // multiple messages
  void SendTunnelDataMsg(
      const std::vector<TunnelMessageBlock>& msgs);

  std::shared_ptr<const i2p::data::RouterInfo> GetEndpointRouter() const {
    return GetTunnelConfig()->GetLastHop()->router;
  }

  size_t GetNumSentBytes() const {
    return m_Gateway.GetNumSentBytes();
  }

  // implements TunnelBase
  void HandleTunnelDataMsg(
      std::shared_ptr<const i2p::I2NPMessage> tunnelMsg);

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
    return GetTunnelConfig()->GetLastHop()->nextTunnelID;
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
      uint32_t tunnelID);

  std::shared_ptr<InboundTunnel> GetPendingInboundTunnel(
      uint32_t replyMsgID);

  std::shared_ptr<OutboundTunnel> GetPendingOutboundTunnel(
      uint32_t replyMsgID);

  std::shared_ptr<InboundTunnel> GetNextInboundTunnel();

  std::shared_ptr<OutboundTunnel> GetNextOutboundTunnel();

  std::shared_ptr<TunnelPool> GetExploratoryPool() const {
    return m_ExploratoryPool;
  }

  TransitTunnel* GetTransitTunnel(
      uint32_t tunnelID);

  int GetTransitTunnelsExpirationTimeout();

  void AddTransitTunnel(
      TransitTunnel* tunnel);

  void AddOutboundTunnel(
      std::shared_ptr<OutboundTunnel> newTunnel);

  void AddInboundTunnel(
      std::shared_ptr<InboundTunnel> newTunnel);

  void PostTunnelData(
      std::shared_ptr<I2NPMessage> msg);

  void PostTunnelData(
      const std::vector<std::shared_ptr<I2NPMessage> >& msgs);

  template<class TTunnel>
  std::shared_ptr<TTunnel> CreateTunnel(
      std::shared_ptr<TunnelConfig> config,
      std::shared_ptr<OutboundTunnel> outboundTunnel = nullptr);

  void AddPendingTunnel(
      uint32_t replyMsgID,
      std::shared_ptr<InboundTunnel> tunnel);  // inbound
  void AddPendingTunnel(
      uint32_t replyMsgID,
      std::shared_ptr<OutboundTunnel> tunnel);  // outbound

  std::shared_ptr<TunnelPool> CreateTunnelPool(
      i2p::garlic::GarlicDestination* localDestination,
      int numInboundHops,
      int numOuboundHops,
      int numInboundTunnels,
      int numOutboundTunnels);

  void DeleteTunnelPool(
      std::shared_ptr<TunnelPool> pool);

  void StopTunnelPool(
      std::shared_ptr<TunnelPool> pool);

 private:
  template<class TTunnel>
  std::shared_ptr<TTunnel> GetPendingTunnel(
      uint32_t replyMsgID,
      const std::map<uint32_t,
      std::shared_ptr<TTunnel> >& pendingTunnels);

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
      PendingTunnels& pendingTunnels);

  void ManageTunnelPools();

  void CreateZeroHopsInboundTunnel();

 private:
  bool m_IsRunning;
  std::unique_ptr<std::thread> m_Thread;

  // by replyMsgID
  std::map<uint32_t, std::shared_ptr<InboundTunnel> > m_PendingInboundTunnels;
  // by replyMsgID
  std::map<uint32_t, std::shared_ptr<OutboundTunnel> > m_PendingOutboundTunnels;

  std::map<uint32_t, std::shared_ptr<InboundTunnel> > m_InboundTunnels;
  std::list<std::shared_ptr<OutboundTunnel> > m_OutboundTunnels;
  std::mutex m_TransitTunnelsMutex;
  std::map<uint32_t, TransitTunnel *> m_TransitTunnels;
  std::mutex m_PoolsMutex;
  std::list<std::shared_ptr<TunnelPool>> m_Pools;
  std::shared_ptr<TunnelPool> m_ExploratoryPool;
  i2p::util::Queue<std::shared_ptr<I2NPMessage> > m_Queue;

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
    int totalNum =
      m_NumSuccesiveTunnelCreations + m_NumFailedTunnelCreations;
    return totalNum ?
      m_NumSuccesiveTunnelCreations * 100 / totalNum :
      0;
  }
};

extern Tunnels tunnels;

}  // namespace tunnel
}  // namespace i2p

#endif  // SRC_CORE_TUNNEL_TUNNEL_H_
