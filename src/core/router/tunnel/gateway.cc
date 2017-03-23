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

#include "core/router/tunnel/gateway.h"

#include <string.h>

#include "core/crypto/hash.h"
#include "core/crypto/rand.h"

#include "core/router/context.h"
#include "core/router/transports/impl.h"

#include "core/util/i2p_endian.h"
#include "core/util/log.h"

namespace kovri {
namespace core {

TunnelGatewayBuffer::TunnelGatewayBuffer(
    std::uint32_t tunnel_ID)
    : m_TunnelID(tunnel_ID),
      m_CurrentTunnelDataMsg(nullptr),
      m_RemainingSize(0),
      m_Exception(__func__) {
  kovri::core::RandBytes(
      m_NonZeroRandomBuffer,
      TUNNEL_DATA_MAX_PAYLOAD_SIZE);
  for (std::size_t i = 0; i < TUNNEL_DATA_MAX_PAYLOAD_SIZE; i++)
    if (!m_NonZeroRandomBuffer[i])
      m_NonZeroRandomBuffer[i] = 1;
}

TunnelGatewayBuffer::~TunnelGatewayBuffer() {}

void TunnelGatewayBuffer::PutI2NPMsg(
    const TunnelMessageBlock& block) {
  bool message_created = false;
  if (!m_CurrentTunnelDataMsg) {
    CreateCurrentTunnelDataMessage();
    message_created = true;
  }
  // create delivery instructions
  std::uint8_t di[43];  // max delivery instruction length is 43 for tunnel
  std::size_t di_len = 1;  // flag
  if (block.delivery_type != e_DeliveryTypeLocal) {  // tunnel or router
    if (block.delivery_type == e_DeliveryTypeTunnel) {
      htobe32buf(di + di_len, block.tunnel_ID);
      di_len += 4;  // tunnel_ID
    }
    memcpy(di + di_len, block.hash, 32);
    di_len += 32;  // len
  }
  // set delivery type
  di[0] = block.delivery_type << 5;
  // create fragments
  std::shared_ptr<I2NPMessage> msg = block.data;
  // delivery instructions + payload + 2 bytes length
  auto full_msg_len = di_len + msg->GetLength() + 2;
  if (full_msg_len <= m_RemainingSize) {
    // message fits. First and last fragment
    htobe16buf(di + di_len, msg->GetLength());
    di_len += 2;  // size
    memcpy(
        m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len,
        di,
        di_len);
    memcpy(
        m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len + di_len,
        msg->GetBuffer(),
        msg->GetLength());
    m_CurrentTunnelDataMsg->len += di_len + msg->GetLength();
    m_RemainingSize -= di_len + msg->GetLength();
    if (!m_RemainingSize)
      CompleteCurrentTunnelDataMessage();
  } else {
    if (!message_created) {  // check if we should complete previous message
      auto num_follow_on_fragments = full_msg_len / TUNNEL_DATA_MAX_PAYLOAD_SIZE;
      // length of bytes don't fit full tunnel message
      // every follow-on fragment adds 7 bytes
      auto non_fit =
        (full_msg_len + num_follow_on_fragments * 7) % TUNNEL_DATA_MAX_PAYLOAD_SIZE;
      if (!non_fit || non_fit > m_RemainingSize) {
        CompleteCurrentTunnelDataMessage();
        CreateCurrentTunnelDataMessage();
      }
    }
    if (di_len + 6 <= m_RemainingSize) {
      // delivery instructions fit
      std::uint32_t msg_ID;
      // in network bytes order
      memcpy(
          &msg_ID,
          msg->GetHeader() + I2NP_HEADER_MSGID_OFFSET,
          4);
      // 6 = 4 (msg_ID) + 2 (size)
      std::size_t size = m_RemainingSize - di_len - 6;
      // first fragment
      di[0] |= 0x08;  // fragmented
      htobuf32(di + di_len, msg_ID);
      di_len += 4;  // Message ID
      htobe16buf(di + di_len, size);
      di_len += 2;  // size
      memcpy(
          m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len,
          di,
          di_len);
      memcpy(
          m_CurrentTunnelDataMsg->buf + m_CurrentTunnelDataMsg->len + di_len,
          msg->GetBuffer(),
          size);
      m_CurrentTunnelDataMsg->len += di_len + size;
      CompleteCurrentTunnelDataMessage();
      // follow on fragments
      int fragment_number = 1;
      while (size < msg->GetLength()) {
        CreateCurrentTunnelDataMessage();
        std::uint8_t* buf = m_CurrentTunnelDataMsg->GetBuffer();
        buf[0] = 0x80 | (fragment_number << 1);  // frag
        bool is_last_fragment = false;
        std::size_t s = msg->GetLength() - size;
        if (s > TUNNEL_DATA_MAX_PAYLOAD_SIZE - 7) {  // 7 follow on instructions
          s = TUNNEL_DATA_MAX_PAYLOAD_SIZE - 7;
        } else {  // last fragment
          buf[0] |= 0x01;
          is_last_fragment = true;
        }
        htobuf32(buf + 1, msg_ID);  // Message ID
        htobe16buf(buf + 5, s);  // size
        memcpy(buf + 7, msg->GetBuffer() + size, s);
        m_CurrentTunnelDataMsg->len += s+7;
        if (is_last_fragment) {
          m_RemainingSize -= s+7;
          if (!m_RemainingSize)
            CompleteCurrentTunnelDataMessage();
        } else {
          CompleteCurrentTunnelDataMessage();
        }
        size += s;
        fragment_number++;
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
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    if (!m_CurrentTunnelDataMsg)
      return;
    std::uint8_t* payload = m_CurrentTunnelDataMsg->GetBuffer();
    std::size_t size = m_CurrentTunnelDataMsg->len - m_CurrentTunnelDataMsg->offset;
    m_CurrentTunnelDataMsg->offset =
      m_CurrentTunnelDataMsg->len - TUNNEL_DATA_MSG_SIZE - I2NP_HEADER_SIZE;
    std::uint8_t* buf = m_CurrentTunnelDataMsg->GetPayload();
    htobe32buf(buf, m_TunnelID);
    kovri::core::RandBytes(buf + 4, 16);  // original IV
    memcpy(payload + size, buf + 4, 16);  // copy IV for checksum
    std::uint8_t hash[32];
    kovri::core::SHA256().CalculateDigest(hash, payload, size + 16);
    memcpy(buf + 20, hash, 4);  // checksum
    // TODO(unassigned): review, refactor
    payload[-1] = 0;  // zero
    ptrdiff_t padding_size = payload - buf - 25;  // 25  = 24 + 1
    if (padding_size > 0) {
      // non-zero padding
      std::uint32_t random_offset =
        kovri::core::RandInRange32(
          0,
          TUNNEL_DATA_MAX_PAYLOAD_SIZE - padding_size);
      memcpy(
          buf + 24,
          m_NonZeroRandomBuffer + random_offset,
          padding_size);
    }
    // we can't fill message header yet because encryption is required
    m_TunnelDataMsgs.push_back(m_CurrentTunnelDataMsg);
    m_CurrentTunnelDataMsg = nullptr;
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
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
  auto tunnel_msgs = m_Buffer.GetTunnelDataMsgs();
  for (auto tunnel_msg : tunnel_msgs) {
    m_Tunnel->EncryptTunnelMsg(tunnel_msg, tunnel_msg);
    tunnel_msg->FillI2NPMessageHeader(I2NPTunnelData);
    m_NumSentBytes += TUNNEL_DATA_MSG_SIZE;
  }
  kovri::core::transports.SendMessages(
      m_Tunnel->GetNextIdentHash(),
      tunnel_msgs);
  m_Buffer.ClearTunnelDataMsgs();
}

}  // namespace core
}  // namespace kovri

