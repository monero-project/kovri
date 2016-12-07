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

#ifndef SRC_CORE_ROUTER_I2NP_H_
#define SRC_CORE_ROUTER_I2NP_H_

#include <cstdint>
#include <cstring>

#include <memory>
#include <set>
#include <vector>

#include "core/crypto/hash.h"

#include "core/router/identity.h"
#include "core/router/info.h"
#include "core/router/lease_set.h"

#include "core/util/i2p_endian.h"

namespace kovri {
namespace core {
             // I2NP header
const std::size_t I2NP_HEADER_TYPEID_OFFSET = 0,
             I2NP_HEADER_MSGID_OFFSET = I2NP_HEADER_TYPEID_OFFSET + 1,
             I2NP_HEADER_EXPIRATION_OFFSET = I2NP_HEADER_MSGID_OFFSET + 4,
             I2NP_HEADER_SIZE_OFFSET = I2NP_HEADER_EXPIRATION_OFFSET + 8,
             I2NP_HEADER_CHKS_OFFSET = I2NP_HEADER_SIZE_OFFSET + 2,
             I2NP_HEADER_SIZE = I2NP_HEADER_CHKS_OFFSET + 1,
             I2NP_HEADER_DEFAULT_EXPIRATION_TIME = 1 * 60 * 1000,  // 1 minute

             // I2NP short header
             I2NP_SHORT_HEADER_TYPEID_OFFSET = 0,
             I2NP_SHORT_HEADER_EXPIRATION_OFFSET = I2NP_SHORT_HEADER_TYPEID_OFFSET + 1,
             I2NP_SHORT_HEADER_SIZE = I2NP_SHORT_HEADER_EXPIRATION_OFFSET + 4,

             I2NP_MAX_MESSAGE_SIZE = 32768,
             I2NP_MAX_SHORT_MESSAGE_SIZE = 4096,

             // Tunnel Gateway header
             TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET = 0,
             TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET = TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET + 4,
             TUNNEL_GATEWAY_HEADER_SIZE = TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET + 2,

             // DeliveryStatus
             DELIVERY_STATUS_MSGID_OFFSET = 0,
             DELIVERY_STATUS_TIMESTAMP_OFFSET = DELIVERY_STATUS_MSGID_OFFSET + 4,
             DELIVERY_STATUS_SIZE = DELIVERY_STATUS_TIMESTAMP_OFFSET + 8,

             // DatabaseStore
             DATABASE_STORE_KEY_OFFSET = 0,
             DATABASE_STORE_TYPE_OFFSET = DATABASE_STORE_KEY_OFFSET + 32,
             DATABASE_STORE_REPLY_TOKEN_OFFSET = DATABASE_STORE_TYPE_OFFSET + 1,
             DATABASE_STORE_HEADER_SIZE = DATABASE_STORE_REPLY_TOKEN_OFFSET + 4,

             // TunnelBuild
             TUNNEL_BUILD_RECORD_SIZE = 528,

             // BuildRequestRecordClearText
             BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET = 0,
             BUILD_REQUEST_RECORD_OUR_IDENT_OFFSET = BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET + 4,
             BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET = BUILD_REQUEST_RECORD_OUR_IDENT_OFFSET + 32,
             BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET = BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET + 4,
             BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET = BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET + 32,
             BUILD_REQUEST_RECORD_IV_KEY_OFFSET = BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET + 32,
             BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET = BUILD_REQUEST_RECORD_IV_KEY_OFFSET + 32,
             BUILD_REQUEST_RECORD_REPLY_IV_OFFSET = BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET + 32,
             BUILD_REQUEST_RECORD_FLAG_OFFSET = BUILD_REQUEST_RECORD_REPLY_IV_OFFSET + 16,
             BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET = BUILD_REQUEST_RECORD_FLAG_OFFSET + 1,
             BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET = BUILD_REQUEST_RECORD_REQUEST_TIME_OFFSET + 4,
             BUILD_REQUEST_RECORD_PADDING_OFFSET = BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET + 4,
             BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE = 222,

             // BuildRequestRecordEncrypted
             BUILD_REQUEST_RECORD_TO_PEER_OFFSET = 0,
             BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET = BUILD_REQUEST_RECORD_TO_PEER_OFFSET + 16,

             // BuildResponseRecord
             BUILD_RESPONSE_RECORD_SHA256HASH_OFFSET = 0,
             BUILD_RESPONSE_RECORD_RANDPAD_OFFSET = 32,
             BUILD_RESPONSE_RECORD_RANDPAD_SIZE = 495,  // Random padding
             BUILD_RESPONSE_RECORD_RET_OFFSET =
               BUILD_RESPONSE_RECORD_RANDPAD_OFFSET +
               BUILD_RESPONSE_RECORD_RANDPAD_SIZE;

              // DatabaseLookup flags
const std::uint8_t DATABASE_LOOKUP_DELIVERY_FLAG = 0x01,
              DATABASE_LOOKUP_ENCYPTION_FLAG = 0x02,
              DATABASE_LOOKUP_TYPE_FLAGS_MASK = 0x0C,
              DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP = 0,
              DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP = 0x04,  // 0100
              DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP = 0x08,  // 1000
              DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP = 0x0C;  // 1100

const int NUM_TUNNEL_BUILD_RECORDS = 8,
          MAX_NUM_TRANSIT_TUNNELS = 2500;

enum I2NPMessageType {
  I2NPDatabaseStore = 1,
  I2NPDatabaseLookup = 2,
  I2NPDatabaseSearchReply = 3,
  I2NPDeliveryStatus = 10,
  I2NPGarlic = 11,
  I2NPTunnelData = 18,
  I2NPTunnelGateway = 19,
  I2NPData = 20,
  I2NPTunnelBuild = 21,
  I2NPTunnelBuildReply = 22,
  I2NPVariableTunnelBuild = 23,
  I2NPVariableTunnelBuildReply = 24
};

class InboundTunnel;
class TunnelPool;

struct I2NPMessage {
  std::uint8_t* buf;
  std::size_t len, offset, max_len;
  std::shared_ptr<kovri::core::InboundTunnel> from;

  I2NPMessage()
      : buf(nullptr),
        len(I2NP_HEADER_SIZE + 2),
        offset(2),
        max_len(0),
        from(nullptr) {}  // reserve 2 bytes for NTCP header

  // header accessors
  std::uint8_t* GetHeader() {
    return GetBuffer();
  }
  const std::uint8_t* GetHeader() const {
    return GetBuffer();
  }

  void SetTypeID(std::uint8_t type_ID) {
    GetHeader()[I2NP_HEADER_TYPEID_OFFSET] = type_ID;
  }

  std::uint8_t GetTypeID() const {
    return GetHeader()[I2NP_HEADER_TYPEID_OFFSET];
  }

  void SetMsgID(std::uint32_t msg_ID) {
    htobe32buf(GetHeader() + I2NP_HEADER_MSGID_OFFSET, msg_ID);
  }

  std::uint32_t GetMsgID() const {
    return bufbe32toh(GetHeader() + I2NP_HEADER_MSGID_OFFSET);
  }

  void SetExpiration(std::uint64_t expiration) {
    htobe64buf(GetHeader() + I2NP_HEADER_EXPIRATION_OFFSET, expiration);
  }

  std::uint64_t GetExpiration() const {
    return bufbe64toh(GetHeader() + I2NP_HEADER_EXPIRATION_OFFSET);
  }

  void SetSize(std::uint16_t size) {
    htobe16buf(GetHeader() + I2NP_HEADER_SIZE_OFFSET, size);
  }

  std::uint16_t GetSize() const {
    return bufbe16toh(GetHeader () + I2NP_HEADER_SIZE_OFFSET);
  }

  void UpdateSize() {
    SetSize(GetPayloadLength());
  }

  void SetChks(std::uint8_t chks) {
    GetHeader()[I2NP_HEADER_CHKS_OFFSET] = chks;
  }

  void UpdateChks() {
    std::uint8_t hash[32];
    kovri::core::SHA256().CalculateDigest(hash, GetPayload(), GetPayloadLength());
    GetHeader()[I2NP_HEADER_CHKS_OFFSET] = hash[0];
  }

  // payload
  std::uint8_t* GetPayload() {
    return GetBuffer() + I2NP_HEADER_SIZE;
  }
  const std::uint8_t* GetPayload() const {
    return GetBuffer() + I2NP_HEADER_SIZE;
  }

  std::uint8_t* GetBuffer() {
    return buf + offset;
  }
  const std::uint8_t* GetBuffer() const {
    return buf + offset;
  }

  std::size_t GetLength() const {
    return len - offset;
  }

  std::size_t GetPayloadLength() const {
    return GetLength () - I2NP_HEADER_SIZE;
  }

  void Align(std::size_t alignment) {
    if (len + alignment > max_len) return;
    std::size_t rem = ((std::size_t)GetBuffer()) % alignment;
    if (rem) {
      offset += (alignment - rem);
      len += (alignment - rem);
    }
  }

  I2NPMessage& operator=(const I2NPMessage& other) {
    memcpy(buf + offset, other.buf + other.offset, other.GetLength());
    len = offset + other.GetLength();
    from = other.from;
    max_len = other.max_len;
    return *this;
  }

  // for SSU only
  std::uint8_t* GetSSUHeader() {
    return buf + offset + I2NP_HEADER_SIZE - I2NP_SHORT_HEADER_SIZE;
  }

  // we have received SSU message and convert it to regular
  void FromSSU(std::uint32_t msg_ID) {
    const std::uint8_t* ssu = GetSSUHeader();
    GetHeader()[I2NP_HEADER_TYPEID_OFFSET] =
      ssu[I2NP_SHORT_HEADER_TYPEID_OFFSET];  // typeid
    SetMsgID(msg_ID);
    SetExpiration(
        bufbe32toh(
          ssu + I2NP_SHORT_HEADER_EXPIRATION_OFFSET) * 1000LL);
    SetSize(len - offset - I2NP_HEADER_SIZE);
    SetChks(0);
  }

  // return msg_ID
  std::uint32_t ToSSU() {
    std::uint8_t header[I2NP_HEADER_SIZE];
    memcpy(header, GetHeader(), I2NP_HEADER_SIZE);
    std::uint8_t * ssu = GetSSUHeader();
    ssu[I2NP_SHORT_HEADER_TYPEID_OFFSET] =
      header[I2NP_HEADER_TYPEID_OFFSET];  // typeid
    htobe32buf(
        ssu + I2NP_SHORT_HEADER_EXPIRATION_OFFSET,
        bufbe64toh(
          header + I2NP_HEADER_EXPIRATION_OFFSET) / 1000LL);
    len = offset + I2NP_SHORT_HEADER_SIZE + bufbe16toh(
        header + I2NP_HEADER_SIZE_OFFSET);
    return bufbe32toh(header + I2NP_HEADER_MSGID_OFFSET);
  }

  void FillI2NPMessageHeader(
      I2NPMessageType msg_type,
      std::uint32_t reply_msg_ID = 0);

  void RenewI2NPMessageHeader();
};

template<int SZ>
struct I2NPMessageBuffer : public I2NPMessage {
  I2NPMessageBuffer() {
    buf = m_Buffer;
    max_len = SZ;
  }
  std::uint8_t m_Buffer[SZ + 16] = {};
};

// TODO(rakhimov): Consider shared_ptr instead of unique_ptr
//                 if a shared msg is the common case.
//                 ``ToSharedI2NPMessage`` is already providing a shared_ptr.
std::unique_ptr<I2NPMessage> NewI2NPMessage();
std::unique_ptr<I2NPMessage> NewI2NPMessage(
    std::size_t len);

std::unique_ptr<I2NPMessage> NewI2NPShortMessage();

std::shared_ptr<I2NPMessage> ToSharedI2NPMessage(
    std::unique_ptr<I2NPMessage> msg);

std::unique_ptr<I2NPMessage> CreateI2NPMessage(
    I2NPMessageType msg_type,
    const std::uint8_t* buf,
    int len,
    std::uint32_t reply_msg_ID = 0);

std::shared_ptr<I2NPMessage> CreateI2NPMessage(
    const std::uint8_t* buf,
    int len,
    std::shared_ptr<kovri::core::InboundTunnel> from = nullptr);

std::shared_ptr<I2NPMessage> CreateDeliveryStatusMsg(std::uint32_t msg_ID);

std::shared_ptr<I2NPMessage> CreateRouterInfoDatabaseLookupMsg(
    const std::uint8_t* key,
    const std::uint8_t * from,
    std::uint32_t reply_tunnel_ID,
    bool exploratory = false,
    std::set<kovri::core::IdentHash>* excluded_peers = nullptr);

std::shared_ptr<I2NPMessage> CreateLeaseSetDatabaseLookupMsg(
    const kovri::core::IdentHash& dest,
    const std::set<kovri::core::IdentHash>& excluded_floodfills,
    const kovri::core::InboundTunnel* reply_tunnel,
    const std::uint8_t* reply_key,
    const std::uint8_t* reply_tag);

std::shared_ptr<I2NPMessage> CreateDatabaseSearchReply(
    const kovri::core::IdentHash& ident,
    std::vector<kovri::core::IdentHash> routers);

std::shared_ptr<I2NPMessage> CreateDatabaseStoreMsg(
    std::shared_ptr<const kovri::core::RouterInfo> router = nullptr,
    std::uint32_t reply_token = 0);
std::shared_ptr<I2NPMessage> CreateDatabaseStoreMsg(
    std::shared_ptr<const kovri::core::LeaseSet> lease_set,
    std::uint32_t reply_token = 0);

bool HandleBuildRequestRecords(
    int num,
    std::uint8_t* records,
    std::uint8_t* clear_text);

void HandleVariableTunnelBuildMsg(
    std::uint32_t reply_msg_ID,
    std::uint8_t* buf,
    std::size_t len);

void HandleVariableTunnelBuildReplyMsg(
    std::uint32_t reply_msg_ID,
    std::uint8_t* buf,
    std::size_t len);

void HandleTunnelBuildMsg(
    std::uint8_t* buf,
    std::size_t len);

std::unique_ptr<I2NPMessage> CreateTunnelDataMsg(
    const std::uint8_t * buf);

std::unique_ptr<I2NPMessage> CreateTunnelDataMsg(
    std::uint32_t tunnel_ID,
    const std::uint8_t* payload);

std::shared_ptr<I2NPMessage> CreateEmptyTunnelDataMsg();

std::unique_ptr<I2NPMessage> CreateTunnelGatewayMsg(
    std::uint32_t tunnel_ID,
    const std::uint8_t* buf,
    std::size_t len);

std::unique_ptr<I2NPMessage> CreateTunnelGatewayMsg(
    std::uint32_t tunnel_ID,
    I2NPMessageType msg_type,
    const std::uint8_t* buf,
    std::size_t len,
    std::uint32_t reply_msg_ID = 0);

std::shared_ptr<I2NPMessage> CreateTunnelGatewayMsg(
    std::uint32_t tunnel_ID,
    std::shared_ptr<I2NPMessage> msg);

std::size_t GetI2NPMessageLength(
    const std::uint8_t* msg);

void HandleI2NPMessage(
    std::uint8_t* msg,
    std::size_t len);

void HandleI2NPMessage(
    std::shared_ptr<I2NPMessage> msg);

class I2NPMessagesHandler {
 public:
  ~I2NPMessagesHandler();

  void PutNextMessage(
      std::shared_ptr<I2NPMessage> msg);

  void Flush();

 private:
  std::vector<std::shared_ptr<I2NPMessage> > m_TunnelMsgs,
                                             m_TunnelGatewayMsgs;
};
}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_I2NP_H_
