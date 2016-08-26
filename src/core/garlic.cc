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

#include "garlic.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include "i2np_protocol.h"
#include "router_context.h"
#include "client/destination.h"
#include "crypto/hash.h"
#include "crypto/rand.h"
#include "tunnel/tunnel.h"
#include "tunnel/tunnel_pool.h"
#include "util/i2p_endian.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace garlic {

GarlicRoutingSession::GarlicRoutingSession(
    GarlicDestination* owner,
    std::shared_ptr<const i2p::data::RoutingDestination> destination,
    int num_tags,
    bool attach_leaseset)
    : m_Owner(owner),
      m_Destination(destination),
      m_NumTags(num_tags),
      m_LeaseSetUpdateStatus(
          attach_leaseset ? eLeaseSetUpdated : eLeaseSetDoNotSend),
      m_LeaseSetUpdateMsgID(0),
      m_LeaseSetSubmissionTime(0) {
  // create new session tags and session key
  i2p::crypto::RandBytes(m_SessionKey, 32);
  m_Encryption.SetKey(m_SessionKey);
}

GarlicRoutingSession::GarlicRoutingSession(
    const std::uint8_t* session_key,
    const SessionTag& session_tag)
    : m_Owner(nullptr),
      m_Destination(nullptr),
      m_NumTags(1),
      m_LeaseSetUpdateStatus(eLeaseSetDoNotSend),
      m_LeaseSetUpdateMsgID(0),
      m_LeaseSetSubmissionTime(0) {
  memcpy(m_SessionKey, session_key, 32);
  m_Encryption.SetKey(m_SessionKey);
  m_SessionTags.push_back(session_tag);
  m_SessionTags.back().creation_time = i2p::util::GetSecondsSinceEpoch();
}

GarlicRoutingSession::~GarlicRoutingSession() {
  for (auto it : m_UnconfirmedTagsMsgs)
    delete it.second;
  m_UnconfirmedTagsMsgs.clear();
}

GarlicRoutingSession::UnconfirmedTags*
GarlicRoutingSession::GenerateSessionTags() {
  auto tags = new UnconfirmedTags(m_NumTags);
  tags->tags_creation_time = i2p::util::GetSecondsSinceEpoch();
  // TODO(unassigned): change int to std::size_t, adjust related code
  for (int i = 0; i < m_NumTags; i++) {
    i2p::crypto::RandBytes(tags->session_tags[i], 32);
    tags->session_tags[i].creation_time = tags->tags_creation_time;
  }
  return tags;
}

void GarlicRoutingSession::MessageConfirmed(
    std::uint32_t msg_ID) {
  TagsConfirmed(msg_ID);
  if (msg_ID == m_LeaseSetUpdateMsgID) {
    m_LeaseSetUpdateStatus = eLeaseSetUpToDate;
    LogPrint(eLogInfo, "GarlicRoutingSession: leaseset update confirmed");
  } else {
    CleanupExpiredTags();
  }
}

void GarlicRoutingSession::TagsConfirmed(uint32_t msg_ID) {
  auto it = m_UnconfirmedTagsMsgs.find(msg_ID);
  if (it != m_UnconfirmedTagsMsgs.end()) {
    std::uint32_t ts = i2p::util::GetSecondsSinceEpoch();
    UnconfirmedTags* tags = it->second;
    if (ts < tags->tags_creation_time + OUTGOING_TAGS_EXPIRATION_TIMEOUT) {
      // TODO(unassigned): change int to std::size_t, adjust related code
      for (int i = 0; i < tags->num_tags; i++)
        m_SessionTags.push_back(tags->session_tags[i]);
    }
    m_UnconfirmedTagsMsgs.erase(it);
    delete tags;
  }
}

bool GarlicRoutingSession::CleanupExpiredTags() {
  std::uint32_t ts = i2p::util::GetSecondsSinceEpoch();
  for (auto it = m_SessionTags.begin(); it != m_SessionTags.end();) {
    if (ts >= it->creation_time + OUTGOING_TAGS_EXPIRATION_TIMEOUT)
      it = m_SessionTags.erase(it);
    else
      it++;
  }
  // delete expired unconfirmed tags
  for (auto it = m_UnconfirmedTagsMsgs.begin();
      it != m_UnconfirmedTagsMsgs.end();) {
    if (ts >= it->second->tags_creation_time + OUTGOING_TAGS_EXPIRATION_TIMEOUT) {
      if (m_Owner)
        m_Owner->RemoveCreatedSession(it->first);
      delete it->second;
      it = m_UnconfirmedTagsMsgs.erase(it);
    } else {
      it++;
    }
  }
  return !m_SessionTags.empty() || m_UnconfirmedTagsMsgs.empty();
}

std::shared_ptr<I2NPMessage> GarlicRoutingSession::WrapSingleMessage(
    std::shared_ptr<const I2NPMessage> msg) {
  auto m = ToSharedI2NPMessage(NewI2NPMessage());
  m->Align(12);  // in order to get buf aligned to 16 (12 + 4)
  std::size_t len = 0;
  std::uint8_t* buf = m->GetPayload() + 4;  // 4 bytes for length
  // find non-expired tag
  bool tag_found = false;
  SessionTag tag;
  if (m_NumTags > 0) {
    std::uint32_t ts = i2p::util::GetSecondsSinceEpoch();
    while (!m_SessionTags.empty()) {
      if (ts < m_SessionTags.front().creation_time +
          OUTGOING_TAGS_EXPIRATION_TIMEOUT) {
        tag = m_SessionTags.front();
        m_SessionTags.pop_front();  // use same tag only once
        tag_found = true;
        break;
      } else {
        m_SessionTags.pop_front();  // remove expired tag
      }
    }
  }
  // create message
  if (!tag_found) {  // new session
    LogPrint(eLogWarn,
        "GarlicRoutingSession: no garlic tags available, using ElGamal");
    if (!m_Destination) {
      LogPrint(eLogWarn,
          "GarlicRoutingSession: can't use ElGamal for unknown destination");
      return nullptr;
    }
    // create ElGamal block
    ElGamalBlock eg_block;
    memcpy(eg_block.session_key.data(), m_SessionKey, 32);
    i2p::crypto::RandBytes(eg_block.pre_IV.data(), 32);  // Pre-IV
    std::array<std::uint8_t, 32> iv;  // IV is first 16 bytes
    i2p::crypto::SHA256().CalculateDigest(
        iv.data(),
        eg_block.pre_IV.data(),
        iv.size());
    m_Destination->GetElGamalEncryption()->Encrypt(
        reinterpret_cast<uint8_t *>(&eg_block),
        sizeof(eg_block),
        buf,
        true);
    m_Encryption.SetIV(iv.data());
    buf += 514;
    len += 514;
  } else {  // existing session
    // session tag
    memcpy(buf, tag, 32);
    std::array<std::uint8_t, 32> iv;  // IV is first 16 bytes
    i2p::crypto::SHA256().CalculateDigest(iv.data(), tag, iv.size());
    m_Encryption.SetIV(iv.data());
    buf += iv.size();
    len += iv.size();
  }
  // AES block
  len += CreateAESBlock(buf, msg);
  htobe32buf(m->GetPayload(), len);
  m->len += len + 4;
  m->FillI2NPMessageHeader(e_I2NPGarlic);
  return m;
}

std::size_t GarlicRoutingSession::CreateAESBlock(
    std::uint8_t* buf,
    std::shared_ptr<const I2NPMessage> msg) {
  std::size_t block_size = 0;
  bool create_new_tags =
    m_Owner &&
    m_NumTags &&
    (static_cast<int>(m_SessionTags.size()) <= m_NumTags * 2 / 3);
  UnconfirmedTags* new_tags = create_new_tags ? GenerateSessionTags() : nullptr;
  htobuf16(buf, new_tags ? htobe16(new_tags->num_tags) : 0);  // tag count
  block_size += 2;
  if (new_tags) {  // session tags recreated
    for (int i = 0; i < new_tags->num_tags; i++) {
      memcpy(buf + block_size, new_tags->session_tags[i], 32);  // tags
      block_size += 32;
    }
  }
  std::uint32_t* payload_size = reinterpret_cast<uint32_t *>((buf + block_size));
  block_size += 4;
  std::uint8_t* payload_hash = buf + block_size;
  block_size += 32;
  buf[block_size] = 0;  // flag
  block_size++;
  std::size_t len = CreateGarlicPayload(buf + block_size, msg, new_tags);
  htobe32buf(payload_size, len);
  i2p::crypto::SHA256().CalculateDigest(payload_hash, buf + block_size, len);
  block_size += len;
  std::size_t rem = block_size % 16;
  if (rem)
    block_size += (16-rem);  // padding
  m_Encryption.Encrypt(buf, block_size, buf);
  return block_size;
}

std::size_t GarlicRoutingSession::CreateGarlicPayload(
    std::uint8_t* payload,
    std::shared_ptr<const I2NPMessage> msg,
    UnconfirmedTags* new_tags) {
  std::uint64_t ts = i2p::util::GetMillisecondsSinceEpoch() + 5000;  // 5 sec
  std::uint32_t msg_ID = i2p::crypto::Rand<std::uint32_t>();
  std::size_t size = 0;
  std::uint8_t* num_cloves = payload + size;
  *num_cloves = 0;
  size++;
  if (m_Owner) {
    // resubmit non-confirmed LeaseSet
    if (m_LeaseSetUpdateStatus == eLeaseSetSubmitted &&
        i2p::util::GetMillisecondsSinceEpoch() >
        m_LeaseSetSubmissionTime + LEASET_CONFIRMATION_TIMEOUT)
      m_LeaseSetUpdateStatus = eLeaseSetUpdated;
    // attach DeviveryStatus if necessary
    if (new_tags || m_LeaseSetUpdateStatus ==
        eLeaseSetUpdated) {  // new tags created or leaseset updated
      // clove is DeliveryStatus
      auto clove_size = CreateDeliveryStatusClove(payload + size, msg_ID);
      if (clove_size > 0) {  // successive?
        size += clove_size;
        (*num_cloves)++;
        if (new_tags)  // new tags created
          m_UnconfirmedTagsMsgs[msg_ID] = new_tags;
        m_Owner->DeliveryStatusSent(shared_from_this(), msg_ID);
      } else {
        LogPrint(eLogWarn,
            "GarlicRoutingSession: DeliveryStatus clove was not created");
      }
    }
    // attach LeaseSet
    if (m_LeaseSetUpdateStatus == eLeaseSetUpdated) {
      m_LeaseSetUpdateStatus = eLeaseSetSubmitted;
      m_LeaseSetUpdateMsgID = msg_ID;
      m_LeaseSetSubmissionTime = i2p::util::GetMillisecondsSinceEpoch();
      // clove if our leaseset must be attached
      auto leaseset = CreateDatabaseStoreMsg(m_Owner->GetLeaseSet());
      size += CreateGarlicClove(payload + size, leaseset, false);
      (*num_cloves)++;
    }
  }
  if (msg) {  // clove message ifself if presented
    size += CreateGarlicClove(
        payload + size,
        msg,
        m_Destination ? m_Destination->IsDestination() : false);
    (*num_cloves)++;
  }
  memset(payload + size, 0, 3);  // certificate of message
  size += 3;
  htobe32buf(payload + size, msg_ID);  // MessageID
  size += 4;
  htobe64buf(payload + size, ts);  // Expiration of message
  size += 8;
  return size;
}

std::size_t GarlicRoutingSession::CreateGarlicClove(
    std::uint8_t* buf,
    std::shared_ptr<const I2NPMessage> msg,
    bool is_destination) {
  std::uint64_t ts = i2p::util::GetMillisecondsSinceEpoch() + 5000;  // 5 sec
  std::size_t size = 0;
  if (is_destination && m_Destination) {
    // delivery instructions flag destination
    buf[size] = eGarlicDeliveryTypeDestination << 5;
    size++;
    memcpy(buf + size, m_Destination->GetIdentHash(), 32);
    size += 32;
  } else {
    buf[size] = 0;  //  delivery instructions flag local
    size++;
  }
  memcpy(buf + size, msg->GetBuffer(), msg->GetLength());
  size += msg->GetLength();
  // CloveID
  htobe32buf(buf + size, i2p::crypto::Rand<std::uint32_t>());
  size += 4;
  htobe64buf(buf + size, ts);  // Expiration of clove
  size += 8;
  memset(buf + size, 0, 3);  // certificate of clove
  size += 3;
  return size;
}

std::size_t GarlicRoutingSession::CreateDeliveryStatusClove(
    std::uint8_t* buf,
    std::uint32_t msg_ID) {
  std::size_t size = 0;
  if (m_Owner) {
    auto inbound_tunnel = m_Owner->GetTunnelPool()->GetNextInboundTunnel();
    if (inbound_tunnel) {
      // delivery instructions flag tunnel
      buf[size] = eGarlicDeliveryTypeTunnel << 5;
      size++;
      // hash and tunnelID sequence is reversed for Garlic
      memcpy(buf + size, inbound_tunnel->GetNextIdentHash(), 32);  // To Hash
      size += 32;
      htobe32buf(buf + size, inbound_tunnel->GetNextTunnelID());  // tunnelID
      size += 4;
      // create msg
      auto msg = CreateDeliveryStatusMsg(msg_ID);
      if (m_Owner) {
        // encrypt
        std::array<std::uint8_t, 32> key, tag;
        i2p::crypto::RandBytes(key.data(), key.size());  // random session key
        i2p::crypto::RandBytes(tag.data(), tag.size());  // random session tag
        m_Owner->SubmitSessionKey(key.data(), tag.data());
        GarlicRoutingSession garlic(key.data(), tag.data());
        msg = garlic.WrapSingleMessage(msg);
      }
      memcpy(buf + size, msg->GetBuffer(), msg->GetLength());
      size += msg->GetLength();
      // fill clove
      std::uint64_t ts = i2p::util::GetMillisecondsSinceEpoch() + 5000;  // 5 sec
      // CloveID
      htobe32buf(buf + size, i2p::crypto::Rand<std::uint32_t>());
      size += 4;
      htobe64buf(buf + size, ts);  // Expiration of clove
      size += 8;
      memset(buf + size, 0, 3);  // certificate of clove
      size += 3;
    } else {
      LogPrint(eLogError,
          "GarlicRoutingSession: no inbound tunnels in the pool for DeliveryStatus");
    }
  } else {
    LogPrint(eLogWarn, "GarlicRoutingSession: missing local LeaseSet");
  }
  return size;
}

GarlicDestination::~GarlicDestination() {}

void GarlicDestination::AddSessionKey(
    const std::uint8_t* key,
    const std::uint8_t* tag) {
  if (key) {
    std::uint32_t ts = i2p::util::GetSecondsSinceEpoch();
    auto decryption = std::make_shared<i2p::crypto::CBCDecryption>();
    decryption->SetKey(key);
    m_Tags[SessionTag(tag, ts)] = decryption;
  }
}

bool GarlicDestination::SubmitSessionKey(
    const std::uint8_t* key,
    const std::uint8_t* tag) {
  AddSessionKey(key, tag);
  return true;
}

void GarlicDestination::HandleGarlicMessage(
    std::shared_ptr<I2NPMessage> msg) {
  std::uint8_t* buf = msg->GetPayload();
  std::uint32_t length = bufbe32toh(buf);
  if (length > msg->GetLength()) {
    LogPrint(eLogError,
        "GarlicDestination: message length ", length,
        " exceeds I2NP message length ", msg->GetLength());
    return;
  }
  buf += 4;  // length
  auto it = m_Tags.find(SessionTag(buf));
  if (it != m_Tags.end()) {
    // tag found. Use AES
    if (length >= 32) {
      std::array<std::uint8_t, 32> iv;  // IV is first 16 bytes
      i2p::crypto::SHA256().CalculateDigest(
          iv.data(),
          buf,
          iv.size());
      it->second->SetIV(iv.data());
      it->second->Decrypt(
          buf + iv.size(),
          length - iv.size(),
          buf + iv.size());
      HandleAESBlock(
          buf + iv.size(),
          length - iv.size(),
          it->second, msg->from);
    } else {
      LogPrint(eLogError,
          "GarlicDestination: message length ",
          length, " is less than 32 bytes");
    }
    m_Tags.erase(it);  // tag might be used only once
  } else {
    // tag not found. Use ElGamal
    ElGamalBlock eg_block;
    if (length >= 514 &&
        i2p::crypto::ElGamalDecrypt(
            GetEncryptionPrivateKey(),
            buf,
            reinterpret_cast<std::uint8_t *>(&eg_block),
            true)) {
      auto decryption = std::make_shared<i2p::crypto::CBCDecryption>();
      decryption->SetKey(eg_block.session_key.data());
      std::array<std::uint8_t, 32> iv;  // IV is first 16 bytes
      i2p::crypto::SHA256().CalculateDigest(
          iv.data(),
          eg_block.pre_IV.data(),
          iv.size());
      decryption->SetIV(iv.data());
      decryption->Decrypt(buf + 514, length - 514, buf + 514);
      HandleAESBlock(buf + 514, length - 514, decryption, msg->from);
    } else {
      LogPrint(eLogError, "GarlicDestination: failed to decrypt garlic");
    }
  }
  // cleanup expired tags
  std::uint32_t ts = i2p::util::GetSecondsSinceEpoch();
  if (ts > m_LastTagsCleanupTime + INCOMING_TAGS_EXPIRATION_TIMEOUT) {
    if (m_LastTagsCleanupTime) {
      int num_expired_tags = 0;
      for (auto it = m_Tags.begin(); it != m_Tags.end();) {
        if (ts > it->first.creation_time + INCOMING_TAGS_EXPIRATION_TIMEOUT) {
          num_expired_tags++;
          it = m_Tags.erase(it);
        } else {
          it++;
        }
      }
      LogPrint(eLogInfo,
          "GarlicDestination: ", num_expired_tags,
          " tags expired for ", GetIdentHash().ToBase64());
    }
    m_LastTagsCleanupTime = ts;
  }
}

void GarlicDestination::HandleAESBlock(
    std::uint8_t* buf,
    std::size_t len,
    std::shared_ptr<i2p::crypto::CBCDecryption> decryption,
    std::shared_ptr<i2p::tunnel::InboundTunnel> from) {
  std::uint16_t tag_count = bufbe16toh(buf);
  buf += 2;
  len -= 2;
  if (tag_count > 0) {
    if (tag_count * 32 > len) {
      LogPrint(eLogError,
          "GarlicDestination: tag count ", tag_count, " exceeds length ", len);
      return;
    }
    std::uint32_t ts = i2p::util::GetSecondsSinceEpoch();
    for (int i = 0; i < tag_count; i++)
      m_Tags[SessionTag(buf + i * 32, ts)] = decryption;
  }
  buf += tag_count * 32;
  len -= tag_count * 32;
  std::uint32_t payload_size = bufbe32toh(buf);
  if (payload_size > len) {
    LogPrint(eLogError,
        "GarlicDestination: unexpected payload size ", payload_size);
    return;
  }
  buf += 4;
  std::uint8_t* payload_hash = buf;
  buf += 32;  // payload hash.
  if (*buf)  // session key?
    buf += 32;  // new session key
  buf++;  // flag
  // payload
  if (!i2p::crypto::SHA256().VerifyDigest(payload_hash, buf, payload_size)) {
    // payload hash doesn't match
    LogPrint(eLogError, "GarlicDestination: wrong payload hash");
    return;
  }
  HandleGarlicPayload(buf, payload_size, from);
}

void GarlicDestination::HandleGarlicPayload(
    std::uint8_t* buf,
    std::size_t len,
    std::shared_ptr<i2p::tunnel::InboundTunnel> from) {
  const std::uint8_t* buf1 = buf;
  std::size_t num_cloves = buf[0];
  LogPrint(eLogDebug, "GarlicDestination: ", num_cloves, " cloves");
  buf++;
  for (std::size_t i(0); i < num_cloves; i++) {
    // delivery instructions
    std::uint8_t flag = buf[0];
    buf++;  // flag
    if (flag & 0x80) {  // encrypted?
      // TODO(unassigned): implement
      LogPrint(eLogDebug, "GarlicDestination: clove encrypted");
      buf += 32;
    }
    GarlicDeliveryType delivery_type = (GarlicDeliveryType)((flag >> 5) & 0x03);
    switch (delivery_type) {
      case eGarlicDeliveryTypeLocal:
        LogPrint(eLogDebug, "GarlicDestination: Garlic type local");
        HandleI2NPMessage(buf, len, from);
      break;
      case eGarlicDeliveryTypeDestination:
        LogPrint(eLogDebug, "GarlicDestination: Garlic type destination");
        buf += 32;  // destination. check it later or for multiple destinations
        HandleI2NPMessage(buf, len, from);
      break;
      case eGarlicDeliveryTypeTunnel: {
        LogPrint(eLogDebug, "GarlicDestination: Garlic type tunnel");
        // gateway_hash and gateway_tunnel sequence is reverted
        std::uint8_t* gateway_hash = buf;
        buf += 32;
        std::uint32_t gateway_tunnel = bufbe32toh(buf);
        buf += 4;
        std::shared_ptr<i2p::tunnel::OutboundTunnel> tunnel;
        if (from && from->GetTunnelPool())
          tunnel = from->GetTunnelPool()->GetNextOutboundTunnel();
        if (tunnel) {  // we have send it through an outbound tunnel
          auto msg = CreateI2NPMessage(buf, GetI2NPMessageLength(buf), from);
          tunnel->SendTunnelDataMsg(gateway_hash, gateway_tunnel, msg);
        } else {
          LogPrint(eLogInfo,
              "GarlicDestination: no outbound tunnels available for garlic clove");
        }
        break;
      }
      case eGarlicDeliveryTypeRouter:
        LogPrint(eLogWarn,
            "GarlicDestination: Garlic type router not supported");
        buf += 32;
      break;
      default:
        LogPrint(eLogError,
            "GarlicDestination: unknown garlic delivery type ",
            static_cast<int>(delivery_type));
    }
    buf += GetI2NPMessageLength(buf);  // I2NP
    buf += 4;  // CloveID
    buf += 8;  // Date
    buf += 3;  // Certificate
    if (buf - buf1  > static_cast<int>(len)) {
      LogPrint(eLogError, "GarlicDestination: clove is too long");
      break;
    }
  }
}

std::shared_ptr<I2NPMessage> GarlicDestination::WrapMessage(
    std::shared_ptr<const i2p::data::RoutingDestination> destination,
    std::shared_ptr<I2NPMessage> msg,
    bool attach_leaseset) {
  // 32 tags by default
  auto session = GetRoutingSession(destination, attach_leaseset);
  return session->WrapSingleMessage(msg);
}

std::shared_ptr<GarlicRoutingSession> GarlicDestination::GetRoutingSession(
    std::shared_ptr<const i2p::data::RoutingDestination> destination,
    bool attach_leaseset) {
  auto it = m_Sessions.find(destination->GetIdentHash());
  std::shared_ptr<GarlicRoutingSession> session;
  if (it != m_Sessions.end())
    session = it->second;
  if (!session) {
    session = std::make_shared<GarlicRoutingSession>(
        this,
        destination,
        // 40 tags for connections and 4 for LS requests
        attach_leaseset ? 40 : 4, attach_leaseset);
    std::unique_lock<std::mutex> l(m_SessionsMutex);
    m_Sessions[destination->GetIdentHash()] = session;
  }
  return session;
}

void GarlicDestination::CleanupRoutingSessions() {
  std::unique_lock<std::mutex> l(m_SessionsMutex);
  for (auto it = m_Sessions.begin(); it != m_Sessions.end();) {
    if (!it->second->CleanupExpiredTags()) {
      LogPrint(eLogInfo,
          "GarlicDestination: routing session to ",
          it->first.ToBase32(), " deleted");
      it = m_Sessions.erase(it);
    } else {
      it++;
    }
  }
}

void GarlicDestination::RemoveCreatedSession(
    std::uint32_t msg_ID) {
  m_CreatedSessions.erase(msg_ID);
}

void GarlicDestination::DeliveryStatusSent(
    std::shared_ptr<GarlicRoutingSession> session,
    std::uint32_t msg_ID) {
  m_CreatedSessions[msg_ID] = session;
}

void GarlicDestination::HandleDeliveryStatusMessage(
    std::shared_ptr<I2NPMessage> msg) {
    std::uint32_t msg_ID = bufbe32toh(msg->GetPayload()); {
    auto it = m_CreatedSessions.find(msg_ID);
    if (it != m_CreatedSessions.end()) {
      it->second->MessageConfirmed(msg_ID);
      m_CreatedSessions.erase(it);
      LogPrint(eLogInfo, "GarlicDestination: message ", msg_ID, " acknowledged");
    }
  }
}

void GarlicDestination::SetLeaseSetUpdated() {
  std::unique_lock<std::mutex> l(m_SessionsMutex);
  for (auto it : m_Sessions)
    it.second->SetLeaseSetUpdated();
}

void GarlicDestination::ProcessGarlicMessage(
    std::shared_ptr<I2NPMessage> msg) {
  HandleGarlicMessage(msg);
}

void GarlicDestination::ProcessDeliveryStatusMessage(
    std::shared_ptr<I2NPMessage> msg) {
  HandleDeliveryStatusMessage(msg);
}

}  // namespace garlic
}  // namespace i2p
