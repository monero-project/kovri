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

#include "core/router/tunnel/pool.h"

#include <algorithm>
#include <vector>

#include "core/crypto/rand.h"

#include "core/router/garlic.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/impl.h"
#include "core/router/tunnel/impl.h"

#include "core/util/i2p_endian.h"
#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {

TunnelPool::TunnelPool(
    kovri::core::GarlicDestination* local_destination,
    int num_inbound_hops,
    int num_outbound_hops,
    int num_inbound_tunnels,
    int num_outbound_tunnels)
    : m_LocalDestination(local_destination),
      m_NumInboundHops(num_inbound_hops),
      m_NumOutboundHops(num_outbound_hops),
      m_NumInboundTunnels(num_inbound_tunnels),
      m_NumOutboundTunnels(num_outbound_tunnels),
      m_IsActive(true) {}

TunnelPool::~TunnelPool() {
  DetachTunnels();
}

void TunnelPool::SetExplicitPeers(
    std::shared_ptr<std::vector<kovri::core::IdentHash> > explicit_peers) {
  m_ExplicitPeers = explicit_peers;
  if (m_ExplicitPeers) {
    int size = m_ExplicitPeers->size();
    if (m_NumInboundHops > size) {
      m_NumInboundHops = size;
      LogPrint(eLogDebug,
          "TunnelPool: inbound tunnel length has been adjusted to ",
          size, " for explicit peers");
    }
    if (m_NumOutboundHops > size) {
      m_NumOutboundHops = size;
      LogPrint(eLogDebug,
          "TunnelPool: outbound tunnel length has been adjusted to ",
          size, " for explicit peers");
    }
    m_NumInboundTunnels = 1;
    m_NumOutboundTunnels = 1;
  }
}

void TunnelPool::DetachTunnels() {
  {
    std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
    for (auto it : m_InboundTunnels)
      it->SetTunnelPool(nullptr);
    m_InboundTunnels.clear();
  }
  {
    std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
    for (auto it : m_OutboundTunnels)
      it->SetTunnelPool(nullptr);
    m_OutboundTunnels.clear();
  }
  m_Tests.clear();
}

void TunnelPool::TunnelCreated(
    std::shared_ptr<InboundTunnel> created_tunnel) {
  if (!m_IsActive)
    return;
  {
    std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
    m_InboundTunnels.insert(created_tunnel);
  }
  if (m_LocalDestination)
    m_LocalDestination->SetLeaseSetUpdated();
}

void TunnelPool::TunnelExpired(
    std::shared_ptr<InboundTunnel> expired_tunnel) {
  if (expired_tunnel) {
    expired_tunnel->SetTunnelPool(nullptr);
    for (auto it : m_Tests)
      if (it.second.second == expired_tunnel)
        it.second.second = nullptr;
    std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
    m_InboundTunnels.erase(expired_tunnel);
  }
}

void TunnelPool::TunnelCreated(
    std::shared_ptr<OutboundTunnel> created_tunnel) {
  if (!m_IsActive)
    return;
  {
    std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
    m_OutboundTunnels.insert(created_tunnel);
  }
  // CreatePairedInboundTunnel (created_tunnel);
  // TODO(unassigned): ^ ???
}

void TunnelPool::TunnelExpired(
    std::shared_ptr<OutboundTunnel> expired_tunnel) {
  if (expired_tunnel) {
    expired_tunnel->SetTunnelPool(nullptr);
    for (auto it : m_Tests)
      if (it.second.first == expired_tunnel)
        it.second.first = nullptr;
    std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
    m_OutboundTunnels.erase(expired_tunnel);
  }
}

std::vector<std::shared_ptr<InboundTunnel> > TunnelPool::GetInboundTunnels(
    int num) const {
  std::vector<std::shared_ptr<InboundTunnel> > v;
  int i = 0;
  std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
  for (auto it : m_InboundTunnels) {
    if (i >= num) break;
    if (it->IsEstablished()) {
      v.push_back(it);
      i++;
    }
  }
  return v;
}

std::shared_ptr<OutboundTunnel> TunnelPool::GetNextOutboundTunnel(
    std::shared_ptr<OutboundTunnel> excluded) const {
  std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
  return GetNextTunnel(m_OutboundTunnels, excluded);
}

std::shared_ptr<InboundTunnel> TunnelPool::GetNextInboundTunnel(
    std::shared_ptr<InboundTunnel> excluded) const {
  std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
  return GetNextTunnel(m_InboundTunnels, excluded);
}

template<class TTunnels>
typename TTunnels::value_type TunnelPool::GetNextTunnel(
    TTunnels& tunnels,
    typename TTunnels::value_type excluded) const {
  if (tunnels.empty ())
    return nullptr;
  std::uint32_t ind = kovri::core::RandInRange32(0, tunnels.size() / 2);
  std::uint32_t i = 0;
  typename TTunnels::value_type tunnel = nullptr;
  for (auto it : tunnels) {
    if (it->IsEstablished() && it != excluded) {
      tunnel = it;
      i++;
    }
    if (i > ind && tunnel)
      break;
  }
  if (!tunnel && excluded && excluded->IsEstablished())
    tunnel = excluded;
  return tunnel;
}

std::shared_ptr<OutboundTunnel> TunnelPool::GetNewOutboundTunnel(
    std::shared_ptr<OutboundTunnel> old) const {
  if (old && old->IsEstablished())
    return old;
  std::shared_ptr<OutboundTunnel> tunnel;
  if (old) {
    std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
    for (auto it : m_OutboundTunnels)
      if (it->IsEstablished() &&
          old->GetEndpointRouter()->GetIdentHash() ==
          it->GetEndpointRouter()->GetIdentHash()) {
        tunnel = it;
        break;
      }
  }
  if (!tunnel)
    tunnel = GetNextOutboundTunnel();
  return tunnel;
}

void TunnelPool::CreateTunnels() {
  int num = 0;
  {
    std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
    for (auto it : m_InboundTunnels)
      if (it->IsEstablished())
        num++;
  }
  for (int i = num; i < m_NumInboundTunnels; i++)
    CreateInboundTunnel();
  num = 0;
  {
    std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
    for (auto it : m_OutboundTunnels)
      if (it->IsEstablished())
        num++;
  }
  for (int i = num; i < m_NumOutboundTunnels; i++)
    CreateOutboundTunnel();
}

void TunnelPool::TestTunnels() {
  for (auto it : m_Tests) {
    LogPrint(eLogWarn,
        "TunnelPool: tunnel test ", it.first, " failed");
    // if test failed again with another tunnel we consider it failed
    if (it.second.first) {
      if (it.second.first->GetState() == e_TunnelStateTestFailed) {
        it.second.first->SetState(e_TunnelStateFailed);
        std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
        m_OutboundTunnels.erase(it.second.first);
      } else {
        it.second.first->SetState(e_TunnelStateTestFailed);
      }
    }
    if (it.second.second) {
      if (it.second.second->GetState() == e_TunnelStateTestFailed) {
        it.second.second->SetState(e_TunnelStateFailed);
        {
          std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
          m_InboundTunnels.erase(it.second.second);
        }
        if (m_LocalDestination)
          m_LocalDestination->SetLeaseSetUpdated();
      } else {
        it.second.second->SetState(e_TunnelStateTestFailed);
      }
    }
  }
  m_Tests.clear();
  // new tests
  auto it1 = m_OutboundTunnels.begin();
  auto it2 = m_InboundTunnels.begin();
  while (it1 != m_OutboundTunnels.end() && it2 != m_InboundTunnels.end()) {
    bool failed = false;
    if ((*it1)->IsFailed()) {
      failed = true;
      it1++;
    }
    if ((*it2)->IsFailed()) {
      failed = true;
      it2++;
    }
    if (!failed) {
      std::uint32_t msg_ID = kovri::core::Rand<std::uint32_t>();
      m_Tests[msg_ID] = std::make_pair(*it1, *it2);
      (*it1)->SendTunnelDataMsg(
          (*it2)->GetNextIdentHash(),
          (*it2)->GetNextTunnelID(),
          CreateDeliveryStatusMsg(msg_ID));
      it1++;
      it2++;
    }
  }
}

void TunnelPool::ProcessGarlicMessage(
    std::shared_ptr<I2NPMessage> msg) {
  if (m_LocalDestination)
    m_LocalDestination->ProcessGarlicMessage(msg);
  else
    LogPrint(eLogWarn,
        "TunnelPool: local destination doesn't exist, dropped");
}

void TunnelPool::ProcessDeliveryStatus(
    std::shared_ptr<I2NPMessage> msg) {
  const std::uint8_t* buf = msg->GetPayload();
  std::uint32_t msg_ID = bufbe32toh(buf);
  buf += 4;
  std::uint64_t timestamp = bufbe64toh(buf);
  auto it = m_Tests.find(msg_ID);
  if (it != m_Tests.end()) {
    // restore from test failed state if any
    if (it->second.first->GetState() == e_TunnelStateTestFailed)
      it->second.first->SetState(e_TunnelStateEstablished);
    if (it->second.second->GetState() == e_TunnelStateTestFailed)
      it->second.second->SetState(e_TunnelStateEstablished);
    LogPrint(eLogDebug,
        "TunnelPool: tunnel test ", it->first,
        " successful: ", kovri::core::GetMillisecondsSinceEpoch() - timestamp,
        " milliseconds");
    m_Tests.erase(it);
  } else {
    if (m_LocalDestination)
      m_LocalDestination->ProcessDeliveryStatusMessage(msg);
    else
      LogPrint(eLogWarn, "TunnelPool: local destination doesn't exist, dropped");
  }
}

std::shared_ptr<const kovri::core::RouterInfo> TunnelPool::SelectNextHop(
    std::shared_ptr<const kovri::core::RouterInfo> prev_hop) const {
  // TODO(unassigned): implement it better
  bool is_exploratory = (m_LocalDestination == &kovri::context);
  auto hop = is_exploratory ?
    kovri::core::netdb.GetRandomRouter(prev_hop) :
    kovri::core::netdb.GetHighBandwidthRandomRouter(prev_hop);
  if (!hop || hop->GetProfile ()->IsBad())
    hop = kovri::core::netdb.GetRandomRouter();
  return hop;
}

bool TunnelPool::SelectPeers(
    std::vector<std::shared_ptr<const kovri::core::RouterInfo> >& hops,
    bool is_inbound) {
  if (m_ExplicitPeers)
    return SelectExplicitPeers(hops, is_inbound);
  auto prev_hop = kovri::context.GetSharedRouterInfo();
  int num_hops = is_inbound ?
    m_NumInboundHops :
    m_NumOutboundHops;
  if (kovri::core::transports.GetNumPeers() > 25) {
    auto r = kovri::core::transports.GetRandomPeer();
    if (r && !r->GetProfile()->IsBad()) {
      prev_hop = r;
      hops.push_back(r);
      num_hops--;
    }
  }
  for (int i = 0; i < num_hops; i++) {
    auto hop = SelectNextHop(prev_hop);
    if (!hop) {
      LogPrint(eLogError, "TunnelPool: can't select next hop");
      return false;
    }
    prev_hop = hop;
    hops.push_back(hop);
  }
  return true;
}

bool TunnelPool::SelectExplicitPeers(
    std::vector<std::shared_ptr<const kovri::core::RouterInfo> >& hops,
    bool is_inbound) {
  int size = m_ExplicitPeers->size();
  std::vector<int> peer_indicies;
  for (int i = 0; i < size; i++)
    peer_indicies.push_back(i);
  kovri::core::Shuffle(peer_indicies.begin(), peer_indicies.end());
  int num_hops = is_inbound ? m_NumInboundHops : m_NumOutboundHops;
  for (int i = 0; i < num_hops; i++) {
    auto& ident = (*m_ExplicitPeers)[peer_indicies[i]];
    auto r = kovri::core::netdb.FindRouter(ident);
    if (r) {
      hops.push_back(r);
    } else {
      LogPrint(eLogDebug,
          "TunnelPool: can't find router for ", ident.ToBase64());
      kovri::core::netdb.RequestDestination(ident);
      return false;
    }
  }
  return true;
}

void TunnelPool::CreateInboundTunnel() {
  auto outbound_tunnel = GetNextOutboundTunnel();
  if (!outbound_tunnel)
    outbound_tunnel = tunnels.GetNextOutboundTunnel();
  LogPrint(eLogDebug, "TunnelPool: creating destination inbound tunnel");
  std::vector<std::shared_ptr<const kovri::core::RouterInfo> > hops;
  if (SelectPeers(hops, true)) {
    std::reverse(hops.begin(), hops.end());
    auto tunnel = tunnels.CreateTunnel<InboundTunnel> (
        std::make_shared<TunnelConfig> (hops),
        outbound_tunnel);
    tunnel->SetTunnelPool(shared_from_this());
  } else {
    LogPrint(eLogError,
        "TunnelPool: can't create inbound tunnel, no peers available");
  }
}

void TunnelPool::RecreateInboundTunnel(
    std::shared_ptr<InboundTunnel> tunnel) {
  auto outbound_tunnel = GetNextOutboundTunnel();
  if (!outbound_tunnel)
    outbound_tunnel = tunnels.GetNextOutboundTunnel();
  LogPrint(eLogDebug, "TunnelPool: re-creating destination inbound tunnel");
  auto new_tunnel =
    tunnels.CreateTunnel<InboundTunnel> (
      tunnel->GetTunnelConfig()->Clone(),
      outbound_tunnel);
  new_tunnel->SetTunnelPool(shared_from_this());
}

void TunnelPool::CreateOutboundTunnel() {
  auto inbound_tunnel = GetNextInboundTunnel();
  if (!inbound_tunnel)
    inbound_tunnel = tunnels.GetNextInboundTunnel();
  if (inbound_tunnel) {
    LogPrint(eLogDebug, "TunnelPool: creating destination outbound tunnel");
    std::vector<std::shared_ptr<const kovri::core::RouterInfo> > hops;
    if (SelectPeers(hops, false)) {
      auto tunnel = tunnels.CreateTunnel<OutboundTunnel> (
        std::make_shared<TunnelConfig> (
          hops,
          inbound_tunnel->GetTunnelConfig()));
      tunnel->SetTunnelPool(shared_from_this());
    } else {
      LogPrint(eLogError,
          "TunnelPool: can't create outbound tunnel, no peers available");
    }
  } else {
    LogPrint(eLogWarn,
        "TunnelPool: can't create outbound tunnel, no inbound tunnels found "
        "(router may need more time to integrate into the network)");
  }
}

void TunnelPool::RecreateOutboundTunnel(
    std::shared_ptr<OutboundTunnel> tunnel) {
  auto inbound_tunnel = GetNextInboundTunnel();
  if (!inbound_tunnel)
    inbound_tunnel = tunnels.GetNextInboundTunnel();
  if (inbound_tunnel) {
    LogPrint(eLogDebug, "TunnelPool: re-creating destination outbound tunnel");
    auto new_tunnel = tunnels.CreateTunnel<OutboundTunnel> (
      tunnel->GetTunnelConfig()->Clone(
        inbound_tunnel->GetTunnelConfig()));
    new_tunnel->SetTunnelPool(shared_from_this());
  } else {
    LogPrint(eLogError,
        "TunnelPool: can't re-create outbound tunnel, no inbound tunnels found");
  }
}

void TunnelPool::CreatePairedInboundTunnel(
    std::shared_ptr<OutboundTunnel> outbound_tunnel) {
  LogPrint(eLogDebug, "TunnelPool: creating paired inbound tunnel");
  auto tunnel = tunnels.CreateTunnel<InboundTunnel> (
      outbound_tunnel->GetTunnelConfig()->Invert(),
      outbound_tunnel);
  tunnel->SetTunnelPool(shared_from_this());
}

}  // namespace core
}  // namespace kovri
