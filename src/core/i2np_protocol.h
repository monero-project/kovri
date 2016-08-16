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

#ifndef SRC_CORE_I2NP_PROTOCOL_H_
#define SRC_CORE_I2NP_PROTOCOL_H_

#include <inttypes.h>
#include <string.h>

#include <set>
#include <memory>
#include <vector>

#include "identity.h"
#include "lease_set.h"
#include "router_info.h"
#include "crypto/hash.h"
#include "util/i2p_endian.h"

namespace i2p {

             // I2NP header
const size_t I2NP_HEADER_TYPEID_OFFSET = 0,
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
const uint8_t DATABASE_LOOKUP_DELIVERY_FLAG = 0x01,
              DATABASE_LOOKUP_ENCYPTION_FLAG = 0x02,
              DATABASE_LOOKUP_TYPE_FLAGS_MASK = 0x0C,
              DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP = 0,
              DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP = 0x04,  // 0100
              DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP = 0x08,  // 1000
              DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP = 0x0C;  // 1100

const int NUM_TUNNEL_BUILD_RECORDS = 8,
          MAX_NUM_TRANSIT_TUNNELS = 2500;

enum I2NPMessageType {
  e_I2NPDatabaseStore = 1,
  e_I2NPDatabaseLookup = 2,
  e_I2NPDatabaseSearchReply = 3,
  e_I2NPDeliveryStatus = 10,
  e_I2NPGarlic = 11,
  e_I2NPTunnelData = 18,
  e_I2NPTunnelGateway = 19,
  e_I2NPData = 20,
  e_I2NPTunnelBuild = 21,
  e_I2NPTunnelBuildReply = 22,
  e_I2NPVariableTunnelBuild = 23,
  e_I2NPVariableTunnelBuildReply = 24
};

namespace tunnel {
class InboundTunnel;
class TunnelPool;
}

struct I2NPMessage {
  uint8_t* buf;
  size_t len, offset, maxLen;
  std::shared_ptr<i2p::tunnel::InboundTunnel> from;

  I2NPMessage()
      : buf(nullptr),
        len(I2NP_HEADER_SIZE + 2),
        offset(2),
        maxLen(0),
        from(nullptr) {}  // reserve 2 bytes for NTCP header

  // header accessors
  uint8_t* GetHeader() {
    return GetBuffer();
  }
  const uint8_t* GetHeader() const {
    return GetBuffer();
  }

  void SetTypeID(uint8_t typeID) {
    GetHeader()[I2NP_HEADER_TYPEID_OFFSET] = typeID;
  }

  uint8_t GetTypeID() const {
    return GetHeader()[I2NP_HEADER_TYPEID_OFFSET];
  }

  void SetMsgID(uint32_t msgID) {
    htobe32buf(GetHeader() + I2NP_HEADER_MSGID_OFFSET, msgID);
  }

  uint32_t GetMsgID() const {
    return bufbe32toh(GetHeader() + I2NP_HEADER_MSGID_OFFSET);
  }

  void SetExpiration(uint64_t expiration) {
    htobe64buf(GetHeader() + I2NP_HEADER_EXPIRATION_OFFSET, expiration);
  }

  uint64_t GetExpiration() const {
    return bufbe64toh(GetHeader() + I2NP_HEADER_EXPIRATION_OFFSET);
  }

  void SetSize(uint16_t size) {
    htobe16buf(GetHeader() + I2NP_HEADER_SIZE_OFFSET, size);
  }

  uint16_t GetSize() const {
    return bufbe16toh(GetHeader () + I2NP_HEADER_SIZE_OFFSET);
  }

  void UpdateSize() {
    SetSize(GetPayloadLength());
  }

  void SetChks(uint8_t chks) {
    GetHeader()[I2NP_HEADER_CHKS_OFFSET] = chks;
  }

  void UpdateChks() {
    uint8_t hash[32];
    i2p::crypto::SHA256().CalculateDigest(hash, GetPayload(), GetPayloadLength());
    GetHeader()[I2NP_HEADER_CHKS_OFFSET] = hash[0];
  }

  // payload
  uint8_t* GetPayload() {
    return GetBuffer() + I2NP_HEADER_SIZE;
  }
  const uint8_t* GetPayload() const {
    return GetBuffer() + I2NP_HEADER_SIZE;
  }

  uint8_t* GetBuffer() {
    return buf + offset;
  }
  const uint8_t* GetBuffer() const {
    return buf + offset;
  }

  size_t GetLength() const {
    return len - offset;
  }

  size_t GetPayloadLength() const {
    return GetLength () - I2NP_HEADER_SIZE;
  }

  void Align(size_t alignment) {
    if (len + alignment > maxLen) return;
    size_t rem = ((size_t)GetBuffer()) % alignment;
    if (rem) {
      offset += (alignment - rem);
      len += (alignment - rem);
    }
  }

  I2NPMessage& operator=(const I2NPMessage& other) {
    memcpy(buf + offset, other.buf + other.offset, other.GetLength());
    len = offset + other.GetLength();
    from = other.from;
    maxLen = other.maxLen;
    return *this;
  }

  // for SSU only
  uint8_t* GetSSUHeader() {
    return buf + offset + I2NP_HEADER_SIZE - I2NP_SHORT_HEADER_SIZE;
  }

  // we have received SSU message and convert it to regular
  void FromSSU(uint32_t msgID) {
    const uint8_t* ssu = GetSSUHeader();
    GetHeader()[I2NP_HEADER_TYPEID_OFFSET] =
      ssu[I2NP_SHORT_HEADER_TYPEID_OFFSET];  // typeid
    SetMsgID(msgID);
    SetExpiration(
        bufbe32toh(
          ssu + I2NP_SHORT_HEADER_EXPIRATION_OFFSET) * 1000LL);
    SetSize(len - offset - I2NP_HEADER_SIZE);
    SetChks(0);
  }

  // return msgID
  uint32_t ToSSU() {
    uint8_t header[I2NP_HEADER_SIZE];
    memcpy(header, GetHeader(), I2NP_HEADER_SIZE);
    uint8_t * ssu = GetSSUHeader();
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
      I2NPMessageType msgType,
      uint32_t replyMsgID = 0);

  void RenewI2NPMessageHeader();
};

template<int SZ>
struct I2NPMessageBuffer : public I2NPMessage {
  I2NPMessageBuffer() {
    buf = m_Buffer;
    maxLen = SZ;
  }
  uint8_t m_Buffer[SZ + 16] = {};
};

I2NPMessage* NewI2NPMessage();
I2NPMessage* NewI2NPMessage(
    size_t len);

I2NPMessage* NewI2NPShortMessage();

void DeleteI2NPMessage(
    I2NPMessage* msg);

std::shared_ptr<I2NPMessage> ToSharedI2NPMessage(
    I2NPMessage* msg);

I2NPMessage* CreateI2NPMessage(
    I2NPMessageType msgType,
    const uint8_t* buf,
    int len,
    uint32_t replyMsgID = 0);
std::shared_ptr<I2NPMessage> CreateI2NPMessage(
    const uint8_t* buf,
    int len,
    std::shared_ptr<i2p::tunnel::InboundTunnel> from = nullptr);

std::shared_ptr<I2NPMessage> CreateDeliveryStatusMsg(uint32_t msgID);

std::shared_ptr<I2NPMessage> CreateRouterInfoDatabaseLookupMsg(
    const uint8_t* key,
    const uint8_t * from,
    uint32_t replyTunnelID,
    bool exploratory = false,
    std::set<i2p::data::IdentHash>* excludedPeers = nullptr);

std::shared_ptr<I2NPMessage> CreateLeaseSetDatabaseLookupMsg(
    const i2p::data::IdentHash& dest,
    const std::set<i2p::data::IdentHash>& excludedFloodfills,
    const i2p::tunnel::InboundTunnel* replyTunnel,
    const uint8_t* replyKey,
    const uint8_t* replyTag);

std::shared_ptr<I2NPMessage> CreateDatabaseSearchReply(
    const i2p::data::IdentHash& ident,
    std::vector<i2p::data::IdentHash> routers);

std::shared_ptr<I2NPMessage> CreateDatabaseStoreMsg(
    std::shared_ptr<const i2p::data::RouterInfo> router = nullptr,
    uint32_t replyToken = 0);
std::shared_ptr<I2NPMessage> CreateDatabaseStoreMsg(
    std::shared_ptr<const i2p::data::LeaseSet> leaseSet,
    uint32_t replyToken = 0);

bool HandleBuildRequestRecords(
    int num,
    uint8_t* records,
    uint8_t* clearText);

void HandleVariableTunnelBuildMsg(
    uint32_t replyMsgID,
    uint8_t* buf,
    size_t len);

void HandleVariableTunnelBuildReplyMsg(
    uint32_t replyMsgID,
    uint8_t* buf,
    size_t len);

void HandleTunnelBuildMsg(
    uint8_t* buf,
    size_t len);

I2NPMessage* CreateTunnelDataMsg(
    const uint8_t * buf);
I2NPMessage* CreateTunnelDataMsg(
    uint32_t tunnelID,
    const uint8_t* payload);

std::shared_ptr<I2NPMessage> CreateEmptyTunnelDataMsg();

I2NPMessage* CreateTunnelGatewayMsg(
    uint32_t tunnelID,
    const uint8_t* buf,
    size_t len);
I2NPMessage* CreateTunnelGatewayMsg(
    uint32_t tunnelID,
    I2NPMessageType msgType,
    const uint8_t* buf,
    size_t len,
    uint32_t replyMsgID = 0);
std::shared_ptr<I2NPMessage> CreateTunnelGatewayMsg(
    uint32_t tunnelID,
    std::shared_ptr<I2NPMessage> msg);

size_t GetI2NPMessageLength(
    const uint8_t* msg);

void HandleI2NPMessage(
    uint8_t* msg,
    size_t len);
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

}  // namespace i2p

#endif  // SRC_CORE_I2NP_PROTOCOL_H_
