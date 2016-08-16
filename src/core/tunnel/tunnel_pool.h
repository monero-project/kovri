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

#ifndef SRC_CORE_TUNNEL_TUNNEL_POOL_H_
#define SRC_CORE_TUNNEL_TUNNEL_POOL_H_

#include <inttypes.h>

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <utility>
#include <vector>

#include "garlic.h"
#include "i2np_protocol.h"
#include "identity.h"
#include "lease_set.h"
#include "router_context.h"
#include "router_info.h"
#include "tunnel_base.h"

namespace i2p {
namespace tunnel {

class Tunnel;
class InboundTunnel;
class OutboundTunnel;

class TunnelPool
    : public std::enable_shared_from_this<TunnelPool> {  // per local destination
 public:
  TunnelPool(
      i2p::garlic::GarlicDestination* localDestination,
      int numInboundHops,
      int numOutboundHops,
      int numInboundTunnels,
      int numOutboundTunnels);
  ~TunnelPool();

  i2p::garlic::GarlicDestination* GetLocalDestination() const {
    return m_LocalDestination;
  }

  void SetLocalDestination(
      i2p::garlic::GarlicDestination* destination) {
    m_LocalDestination = destination;
  }

  void SetExplicitPeers(
      std::shared_ptr<std::vector<i2p::data::IdentHash> > explicitPeers);

  void CreateTunnels();

  void TunnelCreated(
      std::shared_ptr<InboundTunnel> createdTunnel);

  void TunnelExpired(
      std::shared_ptr<InboundTunnel> expiredTunnel);

  void TunnelCreated(
      std::shared_ptr<OutboundTunnel> createdTunnel);

  void TunnelExpired(
      std::shared_ptr<OutboundTunnel> expiredTunnel);

  void RecreateInboundTunnel(
      std::shared_ptr<InboundTunnel> tunnel);

  void RecreateOutboundTunnel(
      std::shared_ptr<OutboundTunnel> tunnel);

  std::vector<std::shared_ptr<InboundTunnel> > GetInboundTunnels(
      int num) const;

  std::shared_ptr<OutboundTunnel> GetNextOutboundTunnel(
      std::shared_ptr<OutboundTunnel> excluded = nullptr) const;

  std::shared_ptr<InboundTunnel> GetNextInboundTunnel(
      std::shared_ptr<InboundTunnel> excluded = nullptr) const;

  std::shared_ptr<OutboundTunnel> GetNewOutboundTunnel(
      std::shared_ptr<OutboundTunnel> old) const;

  void TestTunnels();

  void ProcessGarlicMessage(
      std::shared_ptr<I2NPMessage> msg);

  void ProcessDeliveryStatus(
      std::shared_ptr<I2NPMessage> msg);

  bool IsActive() const {
    return m_IsActive;
  }

  void SetActive(
      bool isActive) {
    m_IsActive = isActive;
  }

  void DetachTunnels();

 private:
  void CreateInboundTunnel();

  void CreateOutboundTunnel();

  void CreatePairedInboundTunnel(
      std::shared_ptr<OutboundTunnel> outboundTunnel);

  template<class TTunnels>
  typename TTunnels::value_type GetNextTunnel(
      TTunnels& tunnels,
      typename TTunnels::value_type excluded) const;

  std::shared_ptr<const i2p::data::RouterInfo> SelectNextHop(
      std::shared_ptr<const i2p::data::RouterInfo> prevHop) const;

  bool SelectPeers(
      std::vector<std::shared_ptr<const i2p::data::RouterInfo> >& hops,
      bool isInbound);

  bool SelectExplicitPeers(
      std::vector<std::shared_ptr<const i2p::data::RouterInfo> >& hops,
      bool isInbound);

 private:
  i2p::garlic::GarlicDestination* m_LocalDestination;
  int m_NumInboundHops,
      m_NumOutboundHops,
      m_NumInboundTunnels,
      m_NumOutboundTunnels;
  std::shared_ptr<std::vector<i2p::data::IdentHash> > m_ExplicitPeers;
  mutable std::mutex m_InboundTunnelsMutex;

  // recent tunnel appears first
  std::set<std::shared_ptr<InboundTunnel>, TunnelCreationTimeCmp> m_InboundTunnels;

  mutable std::mutex m_OutboundTunnelsMutex;
  std::set<std::shared_ptr<OutboundTunnel>, TunnelCreationTimeCmp> m_OutboundTunnels;
  std::map<uint32_t, std::pair<std::shared_ptr<OutboundTunnel>, std::shared_ptr<InboundTunnel> > > m_Tests;
  bool m_IsActive;

 public:
  // for HTTP only
  const decltype(m_OutboundTunnels)& GetOutboundTunnels() const {
    return m_OutboundTunnels;
  }

  const decltype(m_InboundTunnels)& GetInboundTunnels() const {
    return m_InboundTunnels;
  }
};

}  // namespace tunnel
}  // namespace i2p

#endif  // SRC_CORE_TUNNEL_TUNNEL_POOL_H_
