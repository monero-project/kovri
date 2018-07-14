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

#include "core/router/tunnel/config.h"

#include <cstring>

#include "core/router/context.h"
#include "core/router/i2np.h"

#include "core/util/byte_stream.h"
#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {

// TODO(unassigned): refactor all tunnel implementation (applies across entire namespace)

TunnelAESRecordAttributes::TunnelAESRecordAttributes() {
  RandBytes(layer_key.data(), layer_key.size());
  RandBytes(IV_key.data(), IV_key.size());
  RandBytes(reply_key.data(), reply_key.size());
  RandBytes(reply_IV.data(), reply_IV.size());
}

TunnelHopConfig::TunnelHopConfig(
    std::shared_ptr<const RouterInfo> router)
    : m_CurrentRouter(router),
      m_TunnelID(Rand<std::uint32_t>()),
      m_AESRecordAttributes(),
      m_NextRouter(nullptr),
      m_NextTunnelID(0),
      m_PreviousHop(nullptr),
      m_NextHop(nullptr),
      m_IsGateway(true),
      m_IsEndpoint(true),
      m_RecordIndex(0),
      m_Exception(__func__) {
        if (!router)
          throw std::invalid_argument("TunnelHopConfig: current router is null");
      }

const std::shared_ptr<const RouterInfo>& TunnelHopConfig::GetCurrentRouter() const noexcept {
  return m_CurrentRouter;
}

void TunnelHopConfig::SetNextRouter(
    std::shared_ptr<const RouterInfo> router,
    std::uint32_t tunnel_id,
    bool is_endpoint) {
  if (!router)
    throw std::invalid_argument("TunnelHopConfig: next router is null");
  m_NextRouter = router;
  m_NextTunnelID = tunnel_id;
  m_IsEndpoint = is_endpoint;
}

const std::shared_ptr<const RouterInfo>& TunnelHopConfig::GetNextRouter() const noexcept {
  return m_NextRouter;
}

void TunnelHopConfig::SetReplyHop(const TunnelHopConfig* hop) {
  if (!hop)
    throw std::invalid_argument("TunnelHopConfig: reply hop is null");
  SetNextRouter(hop->GetCurrentRouter(), hop->GetTunnelID(), true);
}

void TunnelHopConfig::SetNextHop(TunnelHopConfig* hop) {
  m_NextHop = hop;
  if (m_NextHop) {
    m_NextHop->m_PreviousHop = this;
    m_NextHop->m_IsGateway = false;
    SetNextRouter(m_NextHop->GetCurrentRouter(), m_NextHop->GetTunnelID());
  }
}

TunnelHopConfig* TunnelHopConfig::GetNextHop() const noexcept {
  return m_NextHop;
}

void TunnelHopConfig::SetPreviousHop(TunnelHopConfig* hop) noexcept {
  m_PreviousHop = hop;
  if (m_PreviousHop) {
    m_PreviousHop->m_NextHop = this;
    m_PreviousHop->m_IsEndpoint = false;
    m_IsGateway = false;
  }
}

TunnelHopConfig* TunnelHopConfig::GetPreviousHop() const noexcept {
  return m_PreviousHop;
}

std::uint32_t TunnelHopConfig::GetTunnelID() const {
  return m_TunnelID;
}

std::uint32_t TunnelHopConfig::GetNextTunnelID() const noexcept {
  return m_NextTunnelID;
}

const TunnelAESRecordAttributes& TunnelHopConfig::GetAESAttributes() const {
  return m_AESRecordAttributes;
}

void TunnelHopConfig::SetIsGateway(bool value) noexcept {
  m_IsGateway = value;
}

bool TunnelHopConfig::IsGateway() const noexcept {
  return m_IsGateway;
}

void TunnelHopConfig::SetIsEndpoint(bool value) noexcept {
  m_IsEndpoint = value;
}

bool TunnelHopConfig::IsEndpoint() const noexcept {
  return m_IsEndpoint;
}

TunnelDecryption& TunnelHopConfig::GetDecryption() noexcept {
  return m_Decryption;
}

// TODO(anonimal): review type
void TunnelHopConfig::SetRecordIndex(int record) noexcept {
  m_RecordIndex = record;
}

// TODO(anonimal): review type
int TunnelHopConfig::GetRecordIndex() const noexcept {
  return m_RecordIndex;
}

void TunnelHopConfig::CreateBuildRequestRecord(
    std::uint8_t* record,
    std::uint32_t reply_msg_ID) {
  LOG(debug) << "TunnelHopConfig: creating build request record";

  // Create clear text record
  std::array<std::uint8_t, BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE> clear_text {{}};
  auto stream = std::make_unique<OutputByteStream>(clear_text.data(), clear_text.size());

  // Tunnel ID to receive messages as
  stream->Write<std::uint32_t>(GetTunnelID());

  // Local ident hash
  auto& local_ident = GetCurrentRouter()->GetIdentHash();
  stream->WriteData(local_ident, sizeof(local_ident));

  // Next tunnel ID
  stream->Write<std::uint32_t>(GetNextTunnelID());

  // Next ident hash
  auto& next_ident = GetNextRouter()->GetIdentHash();
  stream->WriteData(next_ident, sizeof(next_ident));

  // AES attributes
  auto& aes = GetAESAttributes();
  stream->WriteData(aes.layer_key.data(), aes.layer_key.size());
  stream->WriteData(aes.IV_key.data(), aes.IV_key.size());
  stream->WriteData(aes.reply_key.data(), aes.reply_key.size());
  stream->WriteData(aes.reply_IV.data(), aes.reply_IV.size());

  // Flag (IBGW or OBEP or neither (intermediary))
  std::uint8_t flag = 0;
  if (IsGateway())
    flag |= 0x80;
  if (IsEndpoint())
    flag |= 0x40;
  stream->Write<std::uint8_t>(flag);

  // Request time
  stream->Write<std::uint32_t>(GetHoursSinceEpoch());  // TODO(unassigned): should we/does boost "round down"?

  // Next message ID
  stream->Write<std::uint32_t>(reply_msg_ID);

  // Uninterpreted / Random padding
  std::array<std::uint8_t, BUILD_REQUEST_RECORD_RAND_PAD_SIZE> padding;
  RandBytes(padding.data(), padding.size());
  stream->WriteData(padding.data(), padding.size());

  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    // ElGamal encrypt with the hop's public encryption key
    GetCurrentRouter()->GetElGamalEncryption()->Encrypt(
        stream->data(),
        stream->size(),
        // TODO(unassigned): Passing pointer argument interferes with more needed refactor work.
        // Pointing to record argument appears to only lead to more spaghetti code
        record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }

  // First half of the SHA-256 of the current hop's router identity
  std::memcpy(
      record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET,
      local_ident,
      BUILD_REQUEST_RECORD_CURRENT_HOP_IDENT_HASH_SIZE);
}

// TODO(unassigned): smart pointers, please
TunnelConfig::TunnelConfig(
    std::vector<std::shared_ptr<const kovri::core::RouterInfo> > peers,
    std::shared_ptr<const TunnelConfig> reply_tunnel_config)
    : TunnelConfig() {
  TunnelHopConfig* prev = nullptr;
  for (auto it : peers) {
    auto hop = new TunnelHopConfig(it);
    if (prev)
      prev->SetNextHop(hop);
    else
      m_FirstHop = hop;
    prev = hop;
  }
  if (prev) {
    m_LastHop = prev;
    if (reply_tunnel_config) {  // outbound
      m_FirstHop->SetIsGateway(false);
      m_LastHop->SetReplyHop(reply_tunnel_config->GetFirstHop());
    } else {  // inbound
      m_LastHop->SetNextRouter(context.GetSharedRouterInfo());
    }
  }
}

TunnelConfig::~TunnelConfig() {
  TunnelHopConfig* hop = m_FirstHop;
  while (hop) {
    auto tmp = hop;
    hop = hop->GetNextHop();
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
    hop = hop->GetNextHop();
  }
  return num;
}

bool TunnelConfig::IsInbound() const {
  return m_FirstHop->IsGateway();
}

std::vector<std::shared_ptr<const kovri::core::RouterInfo> > TunnelConfig::GetPeers() const {
  std::vector<std::shared_ptr<const kovri::core::RouterInfo> > peers;
  TunnelHopConfig* hop = m_FirstHop;
  while (hop) {
    peers.push_back(hop->GetCurrentRouter());
    hop = hop->GetNextHop();
  }
  return peers;
}

void TunnelConfig::Print(
    std::stringstream& s) const {
  TunnelHopConfig* hop = m_FirstHop;
  if (!IsInbound())  // outbound
    s << "me";
  s << "-->" << m_FirstHop->GetTunnelID();
  while (hop) {
    s << ":" << hop->GetCurrentRouter()->GetIdentHashAbbreviation() << "-->";
    if (!hop->IsEndpoint())
      s << hop->GetNextTunnelID();
    else
      return;
    hop = hop->GetNextHop();
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
