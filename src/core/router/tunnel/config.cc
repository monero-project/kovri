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

#include "core/router/tunnel/config.h"

#include <vector>

#include "core/crypto/rand.h"

#include "core/router/context.h"
#include "core/router/i2np.h"

#include "core/util/timestamp.h"

namespace kovri {
namespace core {

// TODO(unassigned): refactor all tunnel implementation (applies across entire namespace)

TunnelHopConfig::TunnelHopConfig(
    std::shared_ptr<const kovri::core::RouterInfo> r) {
  kovri::core::RandBytes(layer_key, 32);
  kovri::core::RandBytes(iv_key, 32);
  kovri::core::RandBytes(reply_key, 32);
  kovri::core::RandBytes(reply_IV, 16);
  kovri::core::RandBytes(rand_pad, 29);
  tunnel_ID = kovri::core::Rand<uint32_t>();
  is_gateway = true;
  is_endpoint = true;
  router = r;
  next_router = nullptr;
  next_tunnel_ID = 0;
  next = nullptr;
  prev = nullptr;
}

void TunnelHopConfig::SetNextRouter(
    std::shared_ptr<const kovri::core::RouterInfo> r) {
  next_router = r;
  is_endpoint = false;
  next_tunnel_ID = kovri::core::Rand<uint32_t>();
}

void TunnelHopConfig::SetReplyHop(
    const TunnelHopConfig* reply_first_hop) {
  next_router = reply_first_hop->router;
  next_tunnel_ID = reply_first_hop->tunnel_ID;
  is_endpoint = true;
}

void TunnelHopConfig::SetNext(
    TunnelHopConfig* n) {
  next = n;
  if (next) {
    next->prev = this;
    next->is_gateway = false;
    is_endpoint = false;
    next_router = next->router;
    next_tunnel_ID = next->tunnel_ID;
  }
}

void TunnelHopConfig::SetPrev(
    TunnelHopConfig* p) {
  prev = p;
  if (prev) {
    prev->next = this;
    prev->is_endpoint = false;
    is_gateway = false;
  }
}

void TunnelHopConfig::CreateBuildRequestRecord(
    uint8_t* record,
    uint32_t reply_msg_ID) const {
  uint8_t clear_text[BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE] = {};
  htobe32buf(
      clear_text + BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET,
      tunnel_ID);
  memcpy(
      clear_text + BUILD_REQUEST_RECORD_OUR_IDENT_OFFSET,
      router->GetIdentHash(),
      32);
  htobe32buf(
      clear_text + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET,
      next_tunnel_ID);
  memcpy(
      clear_text + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
      next_router->GetIdentHash(),
      32);
  memcpy(
      clear_text + BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET,
      layer_key,
      32);
  memcpy(
      clear_text + BUILD_REQUEST_RECORD_IV_KEY_OFFSET,
      iv_key,
      32);
  memcpy(
      clear_text + BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET,
      reply_key,
      32);
  memcpy(
      clear_text + BUILD_REQUEST_RECORD_REPLY_IV_OFFSET,
      reply_IV,
      16);
  uint8_t flag = 0;
  if (is_gateway)
    flag |= 0x80;
  if (is_endpoint)
    flag |= 0x40;
  clear_text[BUILD_REQUEST_RECORD_FLAG_OFFSET] = flag;
  htobe32buf(
      clear_text + BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET,
      kovri::core::GetHoursSinceEpoch());
  htobe32buf(
      clear_text + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET,
      reply_msg_ID);
  memcpy(
      clear_text + BUILD_REQUEST_RECORD_PADDING_OFFSET,
      rand_pad,
      29);
  router->GetElGamalEncryption()->Encrypt(
      clear_text,
      BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE,
      record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET);
  memcpy(
      record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET,
      (const uint8_t *)router->GetIdentHash(),
      16);
}

TunnelConfig::TunnelConfig(
    std::vector<std::shared_ptr<const kovri::core::RouterInfo> > peers,
    std::shared_ptr<const TunnelConfig> reply_tunnel_config)
    : TunnelConfig() {
  TunnelHopConfig* prev = nullptr;
  for (auto it : peers) {
    auto hop = new TunnelHopConfig(it);
    if (prev)
      prev->SetNext(hop);
    else
      m_FirstHop = hop;
    prev = hop;
  }
  // TODO(unassigned): We shouldn't depend on the assumption that we're
  // initialized with non-empty vector of peers (if null, we'll fall apart)
  if (prev) {
    m_LastHop = prev;
    if (reply_tunnel_config) {  // outbound
      m_FirstHop->is_gateway = false;
      m_LastHop->SetReplyHop(reply_tunnel_config->GetFirstHop());
    } else {  // inbound
      m_LastHop->SetNextRouter(kovri::context.GetSharedRouterInfo());
    }
  }
}

TunnelConfig::~TunnelConfig() {
  TunnelHopConfig* hop = m_FirstHop;
  while (hop) {
    auto tmp = hop;
    hop = hop->next;
    delete tmp;
  }
}

TunnelHopConfig* TunnelConfig::GetFirstHop() const {
  return m_FirstHop;
}

TunnelHopConfig* TunnelConfig::GetLastHop() const {
  return m_LastHop;
}

int TunnelConfig::GetNumHops() const {
  int num = 0;
  TunnelHopConfig* hop = m_FirstHop;
  while (hop) {
    num++;
    hop = hop->next;
  }
  return num;
}

bool TunnelConfig::IsInbound() const {
  return m_FirstHop->is_gateway;
}

std::vector<std::shared_ptr<const kovri::core::RouterInfo> > TunnelConfig::GetPeers() const {
  std::vector<std::shared_ptr<const kovri::core::RouterInfo> > peers;
  TunnelHopConfig* hop = m_FirstHop;
  while (hop) {
    peers.push_back(hop->router);
    hop = hop->next;
  }
  return peers;
}

void TunnelConfig::Print(
    std::stringstream& s) const {
  TunnelHopConfig* hop = m_FirstHop;
  if (!IsInbound())  // outbound
    s << "me";
  s << "-->" << m_FirstHop->tunnel_ID;
  while (hop) {
    s << ":" << hop->router->GetIdentHashAbbreviation() << "-->";
    if (!hop->is_endpoint)
      s << hop->next_tunnel_ID;
    else
      return;
    hop = hop->next;
  }
  // we didn't reach endpoint; this means that we are the last hop
  s << ":me";
}

std::shared_ptr<TunnelConfig> TunnelConfig::Invert() const {
  auto peers = GetPeers();
  std::reverse(peers.begin(), peers.end());
  // we use ourself as reply tunnel for outbound tunnel
  return IsInbound()
    ? std::make_shared<TunnelConfig>(peers, shared_from_this())
    : std::make_shared<TunnelConfig>(peers);
}

std::shared_ptr<TunnelConfig> TunnelConfig::Clone(
    std::shared_ptr<const TunnelConfig> reply_tunnel_config) const {
  return std::make_shared<TunnelConfig>(GetPeers(), reply_tunnel_config);
}

}  // namespace core
}  // namespace kovri
