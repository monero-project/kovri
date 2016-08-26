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

#include "tunnel_pool.h"

#include <algorithm>
#include <vector>

#include "garlic.h"
#include "net_db.h"
#include "tunnel.h"
#include "crypto/rand.h"
#include "transport/transports.h"
#include "util/i2p_endian.h"
#include "util/timestamp.h"
#include "util/log.h"

namespace i2p {
namespace tunnel {

TunnelPool::TunnelPool(
    i2p::garlic::GarlicDestination* localDestination,
    int numInboundHops,
    int numOutboundHops,
    int numInboundTunnels,
    int numOutboundTunnels)
    : m_LocalDestination(localDestination),
      m_NumInboundHops(numInboundHops),
      m_NumOutboundHops(numOutboundHops),
      m_NumInboundTunnels(numInboundTunnels),
      m_NumOutboundTunnels(numOutboundTunnels),
      m_IsActive(true) {}

TunnelPool::~TunnelPool() {
  DetachTunnels();
}

void TunnelPool::SetExplicitPeers(
    std::shared_ptr<std::vector<i2p::data::IdentHash> > explicitPeers) {
  m_ExplicitPeers = explicitPeers;
  if (m_ExplicitPeers) {
    int size = m_ExplicitPeers->size();
    if (m_NumInboundHops > size) {
      m_NumInboundHops = size;
      LogPrint(eLogInfo,
          "TunnelPool: inbound tunnel length has been adjusted to ",
          size, " for explicit peers");
    }
    if (m_NumOutboundHops > size) {
      m_NumOutboundHops = size;
      LogPrint(eLogInfo,
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
    std::shared_ptr<InboundTunnel> createdTunnel) {
  if (!m_IsActive)
    return;
  {
    std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
    m_InboundTunnels.insert(createdTunnel);
  }
  if (m_LocalDestination)
    m_LocalDestination->SetLeaseSetUpdated();
}

void TunnelPool::TunnelExpired(
    std::shared_ptr<InboundTunnel> expiredTunnel) {
  if (expiredTunnel) {
    expiredTunnel->SetTunnelPool(nullptr);
    for (auto it : m_Tests)
      if (it.second.second == expiredTunnel)
        it.second.second = nullptr;
    std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
    m_InboundTunnels.erase(expiredTunnel);
  }
}

void TunnelPool::TunnelCreated(
    std::shared_ptr<OutboundTunnel> createdTunnel) {
  if (!m_IsActive)
    return;
  {
    std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
    m_OutboundTunnels.insert(createdTunnel);
  }
  // CreatePairedInboundTunnel (createdTunnel);
  // TODO(unassigned): ^ ???
}

void TunnelPool::TunnelExpired(
    std::shared_ptr<OutboundTunnel> expiredTunnel) {
  if (expiredTunnel) {
    expiredTunnel->SetTunnelPool(nullptr);
    for (auto it : m_Tests)
      if (it.second.first == expiredTunnel)
        it.second.first = nullptr;
    std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
    m_OutboundTunnels.erase(expiredTunnel);
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
  uint32_t ind = i2p::crypto::RandInRange<uint32_t>(0, tunnels.size() / 2);
  uint32_t i = 0;
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
        "TunnelPool: tunnel test ", static_cast<int>(it.first), " failed");
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
      uint32_t msgID = i2p::crypto::Rand<uint32_t>();
      m_Tests[msgID] = std::make_pair(*it1, *it2);
      (*it1)->SendTunnelDataMsg(
          (*it2)->GetNextIdentHash(),
          (*it2)->GetNextTunnelID(),
          CreateDeliveryStatusMsg(msgID));
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
  const uint8_t* buf = msg->GetPayload();
  uint32_t msgID = bufbe32toh(buf);
  buf += 4;
  uint64_t timestamp = bufbe64toh(buf);
  auto it = m_Tests.find(msgID);
  if (it != m_Tests.end()) {
    // restore from test failed state if any
    if (it->second.first->GetState() == e_TunnelStateTestFailed)
      it->second.first->SetState(e_TunnelStateEstablished);
    if (it->second.second->GetState() == e_TunnelStateTestFailed)
      it->second.second->SetState(e_TunnelStateEstablished);
    LogPrint(eLogInfo,
        "TunnelPool: tunnel test ", it->first,
        " successful: ", i2p::util::GetMillisecondsSinceEpoch() - timestamp,
        " milliseconds");
    m_Tests.erase(it);
  } else {
    if (m_LocalDestination)
      m_LocalDestination->ProcessDeliveryStatusMessage(msg);
    else
      LogPrint(eLogWarn, "TunnelPool: local destination doesn't exist, dropped");
  }
}

std::shared_ptr<const i2p::data::RouterInfo> TunnelPool::SelectNextHop(
    std::shared_ptr<const i2p::data::RouterInfo> prevHop) const {
  // TODO(unassigned): implement it better
  bool isExploratory = (m_LocalDestination == &i2p::context);
  auto hop = isExploratory ?
    i2p::data::netdb.GetRandomRouter(prevHop) :
    i2p::data::netdb.GetHighBandwidthRandomRouter(prevHop);
  if (!hop || hop->GetProfile ()->IsBad())
    hop = i2p::data::netdb.GetRandomRouter();
  return hop;
}

bool TunnelPool::SelectPeers(
    std::vector<std::shared_ptr<const i2p::data::RouterInfo> >& hops,
    bool isInbound) {
  if (m_ExplicitPeers)
    return SelectExplicitPeers(hops, isInbound);
  auto prevHop = i2p::context.GetSharedRouterInfo();
  int numHops = isInbound ?
    m_NumInboundHops :
    m_NumOutboundHops;
  if (i2p::transport::transports.GetNumPeers() > 25) {
    auto r = i2p::transport::transports.GetRandomPeer();
    if (r && !r->GetProfile()->IsBad()) {
      prevHop = r;
      hops.push_back(r);
      numHops--;
    }
  }
  for (int i = 0; i < numHops; i++) {
    auto hop = SelectNextHop(prevHop);
    if (!hop) {
      LogPrint(eLogError, "TunnelPool: can't select next hop");
      return false;
    }
    prevHop = hop;
    hops.push_back(hop);
  }
  return true;
}

bool TunnelPool::SelectExplicitPeers(
    std::vector<std::shared_ptr<const i2p::data::RouterInfo> >& hops,
    bool isInbound) {
  int size = m_ExplicitPeers->size();
  std::vector<int> peerIndicies;
  for (int i = 0; i < size; i++)
    peerIndicies.push_back(i);
  std::random_shuffle(peerIndicies.begin(), peerIndicies.end());
  int numHops = isInbound ? m_NumInboundHops : m_NumOutboundHops;
  for (int i = 0; i < numHops; i++) {
    auto& ident = (*m_ExplicitPeers)[peerIndicies[i]];
    auto r = i2p::data::netdb.FindRouter(ident);
    if (r) {
      hops.push_back(r);
    } else {
      LogPrint(eLogInfo,
          "TunnelPool: can't find router for ", ident.ToBase64());
      i2p::data::netdb.RequestDestination(ident);
      return false;
    }
  }
  return true;
}

void TunnelPool::CreateInboundTunnel() {
  auto outboundTunnel = GetNextOutboundTunnel();
  if (!outboundTunnel)
    outboundTunnel = tunnels.GetNextOutboundTunnel();
  LogPrint(eLogInfo, "TunnelPool: creating destination inbound tunnel");
  std::vector<std::shared_ptr<const i2p::data::RouterInfo> > hops;
  if (SelectPeers(hops, true)) {
    std::reverse(hops.begin(), hops.end());
    auto tunnel = tunnels.CreateTunnel<InboundTunnel> (
        std::make_shared<TunnelConfig> (hops),
        outboundTunnel);
    tunnel->SetTunnelPool(shared_from_this());
  } else {
    LogPrint(eLogError,
        "TunnelPool: can't create inbound tunnel, no peers available");
  }
}

void TunnelPool::RecreateInboundTunnel(
    std::shared_ptr<InboundTunnel> tunnel) {
  auto outboundTunnel = GetNextOutboundTunnel();
  if (!outboundTunnel)
    outboundTunnel = tunnels.GetNextOutboundTunnel();
  LogPrint(eLogInfo, "TunnelPool: re-creating destination inbound tunnel");
  auto newTunnel =
    tunnels.CreateTunnel<InboundTunnel> (
      tunnel->GetTunnelConfig()->Clone(),
      outboundTunnel);
  newTunnel->SetTunnelPool(shared_from_this());
}

void TunnelPool::CreateOutboundTunnel() {
  auto inboundTunnel = GetNextInboundTunnel();
  if (!inboundTunnel)
    inboundTunnel = tunnels.GetNextInboundTunnel();
  if (inboundTunnel) {
    LogPrint(eLogInfo, "TunnelPool: creating destination outbound tunnel");
    std::vector<std::shared_ptr<const i2p::data::RouterInfo> > hops;
    if (SelectPeers(hops, false)) {
      auto tunnel = tunnels.CreateTunnel<OutboundTunnel> (
        std::make_shared<TunnelConfig> (
          hops,
          inboundTunnel->GetTunnelConfig()));
      tunnel->SetTunnelPool(shared_from_this());
    } else {
      LogPrint(eLogError,
          "TunnelPool: can't create outbound tunnel, no peers available");
    }
  } else {
    LogPrint(eLogError,
        "TunnelPool: can't create outbound tunnel, no inbound tunnels found");
  }
}

void TunnelPool::RecreateOutboundTunnel(
    std::shared_ptr<OutboundTunnel> tunnel) {
  auto inboundTunnel = GetNextInboundTunnel();
  if (!inboundTunnel)
    inboundTunnel = tunnels.GetNextInboundTunnel();
  if (inboundTunnel) {
    LogPrint(eLogInfo, "TunnelPool: re-creating destination outbound tunnel");
    auto newTunnel = tunnels.CreateTunnel<OutboundTunnel> (
      tunnel->GetTunnelConfig()->Clone(
        inboundTunnel->GetTunnelConfig()));
    newTunnel->SetTunnelPool(shared_from_this());
  } else {
    LogPrint(eLogError,
        "TunnelPool: can't re-create outbound tunnel, no inbound tunnels found");
  }
}

void TunnelPool::CreatePairedInboundTunnel(
    std::shared_ptr<OutboundTunnel> outboundTunnel) {
  LogPrint(eLogInfo, "TunnelPool: creating paired inbound tunnel");
  auto tunnel = tunnels.CreateTunnel<InboundTunnel> (
      outboundTunnel->GetTunnelConfig()->Invert(),
      outboundTunnel);
  tunnel->SetTunnelPool(shared_from_this());
}

}  // namespace tunnel
}  // namespace i2p
