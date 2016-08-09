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

#include <string.h>

#include "router_context.h"
#include "tunnel_gateway.h"
#include "crypto/hash.h"
#include "crypto/rand.h"
#include "transport/transports.h"
#include "util/i2p_endian.h"
#include "util/log.h"

namespace i2p {
namespace tunnel {

TunnelGatewayBuffer::TunnelGatewayBuffer(
    uint32_t tunnelID)
    : m_TunnelID(tunnelID),
      m_CurrentTunnelDataMsg(nullptr),
      m_RemainingSize(0) {
  i2p::crypto::RandBytes(
      m_NonZeroRandomBuffer,
      TUNNEL_DATA_MAX_PAYLOAD_SIZE);
  for (size_t i = 0; i < TUNNEL_DATA_MAX_PAYLOAD_SIZE; i++)
    if (!m_NonZeroRandomBuffer[i])
      m_NonZeroRandomBuffer[i] = 1;
}

TunnelGatewayBuffer::~TunnelGatewayBuffer() {}

void TunnelGatewayBuffer::PutI2NPMsg(
    const TunnelMessageBlock& block) {
  bool messageCreated = false;
  if (!m_CurrentTunnelDataMsg) {
    CreateCurrentTunnelDataMessage();
    messageCreated = true;
  }
  // create delivery instructions
  uint8_t di[43];  // max delivery instruction length is 43 for tunnel
  size_t diLen = 1;  // flag
  if (block.deliveryType != e_DeliveryTypeLocal) {  // tunnel or router
    if (block.deliveryType == e_DeliveryTypeTunnel) {
      htobe32buf(di + diLen, block.tunnelID);
      diLen += 4;  // tunnelID
    }
    memcpy(di + diLen, block.hash, 32);
    diLen += 32;  // len
  }
  // set delivery type
  di[0] = block.deliveryType << 5;
  // create fragments
  std::shared_ptr<I2NPMessage> msg = block.data;
  // delivery instructions + payload + 2 bytes length
  auto fullMsgLen = diLen + msg->GetLength() + 2;
  if (fullMsgLen <= m_RemainingSize) {
    // message fits. First and last fragment
    htobe16buf(di + diLen, msg->GetLength());
    diLen += 2;  // size
    memcpy(
        m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len,
        di,
        diLen);
    memcpy(
        m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len + diLen,
        msg->GetBuffer(),
        msg->GetLength());
    m_CurrentTunnelDataMsg->len += diLen + msg->GetLength();
    m_RemainingSize -= diLen + msg->GetLength();
    if (!m_RemainingSize)
      CompleteCurrentTunnelDataMessage();
  } else {
    if (!messageCreated) {  // check if we should complete previous message
      auto numFollowOnFragments = fullMsgLen / TUNNEL_DATA_MAX_PAYLOAD_SIZE;
      // length of bytes don't fit full tunnel message
      // every follow-on fragment adds 7 bytes
      auto nonFit =
        (fullMsgLen + numFollowOnFragments * 7) % TUNNEL_DATA_MAX_PAYLOAD_SIZE;
      if (!nonFit || nonFit > m_RemainingSize) {
        CompleteCurrentTunnelDataMessage();
        CreateCurrentTunnelDataMessage();
      }
    }
    if (diLen + 6 <= m_RemainingSize) {
      // delivery instructions fit
      uint32_t msgID;
      // in network bytes order
      memcpy(
          &msgID,
          msg->GetHeader() + I2NP_HEADER_MSGID_OFFSET,
          4);
      // 6 = 4 (msgID) + 2 (size)
      size_t size = m_RemainingSize - diLen - 6;
      // first fragment
      di[0] |= 0x08;  // fragmented
      htobuf32(di + diLen, msgID);
      diLen += 4;  // Message ID
      htobe16buf(di + diLen, size);
      diLen += 2;  // size
      memcpy(
          m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len,
          di,
          diLen);
      memcpy(
          m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len + diLen,
          msg->GetBuffer(),
          size);
      m_CurrentTunnelDataMsg->len += diLen + size;
      CompleteCurrentTunnelDataMessage();
      // follow on fragments
      int fragmentNumber = 1;
      while (size < msg->GetLength()) {
        CreateCurrentTunnelDataMessage();
        uint8_t* buf = m_CurrentTunnelDataMsg->GetBuffer();
        buf[0] = 0x80 | (fragmentNumber << 1);  // frag
        bool isLastFragment = false;
        size_t s = msg->GetLength() - size;
        if (s > TUNNEL_DATA_MAX_PAYLOAD_SIZE - 7) {  // 7 follow on instructions
          s = TUNNEL_DATA_MAX_PAYLOAD_SIZE - 7;
        } else {  // last fragment
          buf[0] |= 0x01;
          isLastFragment = true;
        }
        htobuf32(buf + 1, msgID);  // Message ID
        htobe16buf(buf + 5, s);  // size
        memcpy(buf + 7, msg->GetBuffer() + size, s);
        m_CurrentTunnelDataMsg->len += s+7;
        if (isLastFragment) {
          m_RemainingSize -= s+7;
          if (!m_RemainingSize)
            CompleteCurrentTunnelDataMessage();
        } else {
          CompleteCurrentTunnelDataMessage();
        }
        size += s;
        fragmentNumber++;
      }
    } else {
      // delivery instructions don't fit. Create new message
      CompleteCurrentTunnelDataMessage();
      PutI2NPMsg(block);
      // don't delete msg because it's taken care inside
    }
  }
}

void TunnelGatewayBuffer::ClearTunnelDataMsgs() {
  m_TunnelDataMsgs.clear();
}

void TunnelGatewayBuffer::CreateCurrentTunnelDataMessage() {
  m_CurrentTunnelDataMsg = ToSharedI2NPMessage(NewI2NPShortMessage());
  m_CurrentTunnelDataMsg->Align(12);
  // we reserve space for padding
  m_CurrentTunnelDataMsg->offset += TUNNEL_DATA_MSG_SIZE + I2NP_HEADER_SIZE;
  m_CurrentTunnelDataMsg->len = m_CurrentTunnelDataMsg->offset;
  m_RemainingSize = TUNNEL_DATA_MAX_PAYLOAD_SIZE;
}

void TunnelGatewayBuffer::CompleteCurrentTunnelDataMessage() {
  if (!m_CurrentTunnelDataMsg)
    return;
  uint8_t* payload = m_CurrentTunnelDataMsg->GetBuffer();
  size_t size = m_CurrentTunnelDataMsg->len - m_CurrentTunnelDataMsg->offset;
  m_CurrentTunnelDataMsg->offset =
    m_CurrentTunnelDataMsg->len - TUNNEL_DATA_MSG_SIZE - I2NP_HEADER_SIZE;
  uint8_t* buf = m_CurrentTunnelDataMsg->GetPayload();
  htobe32buf(buf, m_TunnelID);
  i2p::crypto::RandBytes(buf + 4, 16);  // original IV
  memcpy(payload + size, buf + 4, 16);  // copy IV for checksum
  uint8_t hash[32];
  i2p::crypto::SHA256().CalculateDigest(hash, payload, size + 16);
  memcpy(buf + 20, hash, 4);  // checksum
  // XXX: WTF?!
  payload[-1] = 0;  // zero
  ptrdiff_t paddingSize = payload - buf - 25;  // 25  = 24 + 1
  if (paddingSize > 0) {
    // non-zero padding
    uint32_t randomOffset =
      i2p::crypto::RandInRange<uint32_t>(
        0,
        TUNNEL_DATA_MAX_PAYLOAD_SIZE - paddingSize);
    memcpy(
        buf + 24,
        m_NonZeroRandomBuffer + randomOffset,
        paddingSize);
  }
  // we can't fill message header yet because encryption is required
  m_TunnelDataMsgs.push_back(m_CurrentTunnelDataMsg);
  m_CurrentTunnelDataMsg = nullptr;
}

void TunnelGateway::SendTunnelDataMsg(
    const TunnelMessageBlock& block) {
  if (block.data) {
    PutTunnelDataMsg(block);
    SendBuffer();
  }
}

void TunnelGateway::PutTunnelDataMsg(
    const TunnelMessageBlock& block) {
  if (block.data)
    m_Buffer.PutI2NPMsg(block);
}

void TunnelGateway::SendBuffer() {
  m_Buffer.CompleteCurrentTunnelDataMessage();
  auto tunnelMsgs = m_Buffer.GetTunnelDataMsgs();
  for (auto tunnelMsg : tunnelMsgs) {
    m_Tunnel->EncryptTunnelMsg(tunnelMsg, tunnelMsg);
    tunnelMsg->FillI2NPMessageHeader(e_I2NPTunnelData);
    m_NumSentBytes += TUNNEL_DATA_MSG_SIZE;
  }
  i2p::transport::transports.SendMessages(
      m_Tunnel->GetNextIdentHash(),
      tunnelMsgs);
  m_Buffer.ClearTunnelDataMsgs();
}

}  // namespace tunnel
}  // namespace i2p

