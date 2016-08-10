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

#include "tunnel_config.h"

#include <vector>

#include "crypto/rand.h"
#include "i2np_protocol.h"
#include "router_context.h"
#include "util/timestamp.h"

namespace i2p {
namespace tunnel {

TunnelHopConfig::TunnelHopConfig(
    std::shared_ptr<const i2p::data::RouterInfo> r) {
  i2p::crypto::RandBytes(layerKey, 32);
  i2p::crypto::RandBytes(ivKey, 32);
  i2p::crypto::RandBytes(replyKey, 32);
  i2p::crypto::RandBytes(replyIV, 16);
  i2p::crypto::RandBytes(randPad, 29);
  tunnelID = i2p::crypto::Rand<uint32_t>();
  isGateway = true;
  isEndpoint = true;
  router = r;
  // nextRouter = nullptr;
  nextTunnelID = 0;
  next = nullptr;
  prev = nullptr;
}

void TunnelHopConfig::SetNextRouter(
    std::shared_ptr<const i2p::data::RouterInfo> r) {
  nextRouter = r;
  isEndpoint = false;
  nextTunnelID = i2p::crypto::Rand<uint32_t>();
}

void TunnelHopConfig::SetReplyHop(
    const TunnelHopConfig* replyFirstHop) {
  nextRouter = replyFirstHop->router;
  nextTunnelID = replyFirstHop->tunnelID;
  isEndpoint = true;
}

void TunnelHopConfig::SetNext(
    TunnelHopConfig* n) {
  next = n;
  if (next) {
    next->prev = this;
    next->isGateway = false;
    isEndpoint = false;
    nextRouter = next->router;
    nextTunnelID = next->tunnelID;
  }
}

void TunnelHopConfig::SetPrev(
    TunnelHopConfig* p) {
  prev = p;
  if (prev) {
    prev->next = this;
    prev->isEndpoint = false;
    isGateway = false;
  }
}

void TunnelHopConfig::CreateBuildRequestRecord(
    uint8_t* record,
    uint32_t replyMsgID) const {
  uint8_t clearText[BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE] = {};
  htobe32buf(
      clearText + BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET,
      tunnelID);
  memcpy(
      clearText + BUILD_REQUEST_RECORD_OUR_IDENT_OFFSET,
      router->GetIdentHash(),
      32);
  htobe32buf(
      clearText + BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET,
      nextTunnelID);
  memcpy(
      clearText + BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
      nextRouter->GetIdentHash(),
      32);
  memcpy(
      clearText + BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET,
      layerKey,
      32);
  memcpy(
      clearText + BUILD_REQUEST_RECORD_IV_KEY_OFFSET,
      ivKey,
      32);
  memcpy(
      clearText + BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET,
      replyKey,
      32);
  memcpy(
      clearText + BUILD_REQUEST_RECORD_REPLY_IV_OFFSET,
      replyIV,
      16);
  uint8_t flag = 0;
  if (isGateway)
    flag |= 0x80;
  if (isEndpoint)
    flag |= 0x40;
  clearText[BUILD_REQUEST_RECORD_FLAG_OFFSET] = flag;
  htobe32buf(
      clearText + BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET,
      i2p::util::GetHoursSinceEpoch());
  htobe32buf(
      clearText + BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET,
      replyMsgID);
  memcpy(
      clearText + BUILD_REQUEST_RECORD_PADDING_OFFSET,
      randPad,
      29);
  router->GetElGamalEncryption()->Encrypt(
      clearText,
      BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE,
      record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET);
  memcpy(
      record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET,
      (const uint8_t *)router->GetIdentHash(),
      16);
}

TunnelConfig::TunnelConfig(
    std::vector<std::shared_ptr<const i2p::data::RouterInfo> > peers,
    std::shared_ptr<const TunnelConfig> replyTunnelConfig)
    : TunnelConfig() {
  // replyTunnelConfig=nullptr means inbound
  TunnelHopConfig* prev = nullptr;
  for (auto it : peers) {
    auto hop = new TunnelHopConfig(it);
    if (prev)
      prev->SetNext(hop);
    else
      m_FirstHop = hop;
    prev = hop;
  }
  m_LastHop = prev;
  if (replyTunnelConfig) {  // outbound
    m_FirstHop->isGateway = false;
    m_LastHop->SetReplyHop(replyTunnelConfig->GetFirstHop());
  } else {  // inbound
    m_LastHop->SetNextRouter(i2p::context.GetSharedRouterInfo());
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
  return m_FirstHop->isGateway;
}

std::vector<std::shared_ptr<const i2p::data::RouterInfo> > TunnelConfig::GetPeers() const {
  std::vector<std::shared_ptr<const i2p::data::RouterInfo> > peers;
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
  s << "-->" << m_FirstHop->tunnelID;
  while (hop) {
    s << ":" << hop->router->GetIdentHashAbbreviation() << "-->";
    if (!hop->isEndpoint)
      s << hop->nextTunnelID;
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
  return IsInbound() ?
    std::make_shared<TunnelConfig>(
        peers,
        shared_from_this()) :
    std::make_shared<TunnelConfig>(peers);
}

std::shared_ptr<TunnelConfig> TunnelConfig::Clone(
    std::shared_ptr<const TunnelConfig> replyTunnelConfig) const {
  return std::make_shared<TunnelConfig> (GetPeers(), replyTunnelConfig);
}

}  // namespace tunnel
}  // namespace i2p
