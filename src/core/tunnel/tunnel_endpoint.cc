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

#include "tunnel_endpoint.h"

#include <string.h>

#include <utility>

#include "i2np_protocol.h"
#include "net_db.h"
#include "router_context.h"
#include "crypto/hash.h"
#include "transport/transports.h"
#include "util/i2p_endian.h"
#include "util/log.h"

namespace i2p {
namespace tunnel {

TunnelEndpoint::~TunnelEndpoint() {}

void TunnelEndpoint::HandleDecryptedTunnelDataMsg(
    std::shared_ptr<I2NPMessage> msg) {
  m_NumReceivedBytes += TUNNEL_DATA_MSG_SIZE;
  // 4 + 16
  uint8_t* decrypted = msg->GetPayload() + 20;
  // without 4-byte checksum
  uint8_t* zero =
    (uint8_t *)memchr(
        decrypted + 4,
        0,
        TUNNEL_DATA_ENCRYPTED_SIZE - 4);
  if (zero) {
    uint8_t* fragment = zero + 1;
    // verify checksum
    memcpy(  // copy iv to the end
        msg->GetPayload() + TUNNEL_DATA_MSG_SIZE,
        msg->GetPayload() + 4,
        16);
    uint8_t hash[32];
    i2p::crypto::SHA256().CalculateDigest(
        hash,
        fragment,
        // payload + iv
        TUNNEL_DATA_MSG_SIZE - (fragment - msg->GetPayload()) + 16);
    if (memcmp(hash, decrypted, 4)) {
      LogPrint(eLogError,
          "TunnelEndpoint: ",
          "HandleDecryptedTunnelDataMsg(): checksum verification failed");
      return;
    }
    // process fragments
    while (fragment < decrypted + TUNNEL_DATA_ENCRYPTED_SIZE) {
      uint8_t flag = fragment[0];
      fragment++;
      bool is_follow_on_fragment = flag & 0x80,
               is_last_fragment = true;
      uint32_t msg_ID = 0;
      int fragment_num = 0;
      TunnelMessageBlockEx m;
      if (!is_follow_on_fragment) {
        // first fragment
        m.delivery_type = (TunnelDeliveryType)((flag >> 5) & 0x03);
        switch (m.delivery_type) {
          case e_DeliveryTypeLocal:  // 0
          break;
          case e_DeliveryTypeTunnel:  // 1
            m.tunnel_ID = bufbe32toh(fragment);
            fragment += 4;  // tunnel_ID
            m.hash = i2p::data::IdentHash(fragment);
            fragment += 32;  // hash
          break;
          case e_DeliveryTypeRouter:  // 2
            m.hash = i2p::data::IdentHash(fragment);
            fragment += 32;  // to hash
          break;
          default: {}
        }
        bool is_fragmented = flag & 0x08;
        if (is_fragmented) {
          // Message ID
          msg_ID = bufbe32toh(fragment);
          fragment += 4;
          is_last_fragment = false;
        }
      } else {
        // follow on
        msg_ID = bufbe32toh(fragment);  // MessageID
        fragment += 4;
        fragment_num = (flag >> 1) & 0x3F;  // 6 bits
        is_last_fragment = flag & 0x01;
      }
      uint16_t size = bufbe16toh(fragment);
      fragment += 2;
      msg->offset = fragment - msg->buf;
      msg->len = msg->offset + size;
      if (fragment + size < decrypted + TUNNEL_DATA_ENCRYPTED_SIZE) {
        // this is not last message. we have to copy it
        m.data = ToSharedI2NPMessage(NewI2NPShortMessage());
        // reserve room for TunnelGateway header
        m.data->offset += TUNNEL_GATEWAY_HEADER_SIZE;
        m.data->len += TUNNEL_GATEWAY_HEADER_SIZE;
        *(m.data) = *msg;
      } else {
        m.data = msg;
      }
      if (!is_follow_on_fragment && is_last_fragment) {
        HandleNextMessage(m);
      } else {
        if (msg_ID) {  // msg_ID is presented, assume message is fragmented
          if (!is_follow_on_fragment) {  // create new incomplete message
            m.next_fragment_num = 1;
            auto ret = m_IncompleteMessages.insert(
                std::pair<uint32_t, TunnelMessageBlockEx>(msg_ID, m));
            if (ret.second)
              HandleOutOfSequenceFragment(msg_ID, ret.first->second);
            else
              LogPrint(eLogError,
                  "TunnelEndpoint: incomplete message ",
                  msg_ID, "already exists");
          } else {
            m.next_fragment_num = fragment_num;
            HandleFollowOnFragment(msg_ID, is_last_fragment, m);
          }
        } else {
          LogPrint(eLogError,
              "TunnelEndpoint: message is fragmented, "
              "but msg_ID is not presented");
        }
      }
      fragment += size;
    }
  } else {
    LogPrint(eLogError,
        "TunnelEndpoint: HandleDecryptedTunnelDataMsg(): zero not found");
  }
}

void TunnelEndpoint::HandleFollowOnFragment(
    uint32_t msg_ID,
    bool is_last_fragment,
    const TunnelMessageBlockEx& m) {
  auto fragment = m.data->GetBuffer();
  auto size = m.data->GetLength();
  auto it = m_IncompleteMessages.find(msg_ID);
  if (it != m_IncompleteMessages.end()) {
    auto& msg = it->second;
    if (m.next_fragment_num == msg.next_fragment_num) {
      // check if message is not too long
      if (msg.data->len + size < I2NP_MAX_MESSAGE_SIZE) {
        if (msg.data->len + size > msg.data->max_len) {
          LogPrint(eLogInfo,
              "TunnelEndpoint: I2NP message size ",
              msg.data->max_len, " is not enough");
          auto new_msg = ToSharedI2NPMessage(NewI2NPMessage());
          *new_msg = *(msg.data);
          msg.data = new_msg;
        }
        // concatenate fragment
        memcpy(msg.data->buf + msg.data->len, fragment, size);
        msg.data->len += size;
        if (is_last_fragment) {
          // message complete
          HandleNextMessage(msg);
          m_IncompleteMessages.erase(it);
        } else {
          msg.next_fragment_num++;
          HandleOutOfSequenceFragment(msg_ID, msg);
        }
      } else {
        LogPrint(eLogError,
            "TunnelEndpoint: fragment ", m.next_fragment_num,
            " of message ", msg_ID,
            "exceeds max I2NP message size. Message dropped");
        m_IncompleteMessages.erase(it);
      }
    } else {
      LogPrint(eLogInfo,
          "TunnelEndpoint: unexpected fragment: ",
          static_cast<int>(m.next_fragment_num),
          " instead: ",
          static_cast<int>(msg.next_fragment_num),
          " of message ", msg_ID, ". Saved");
      AddOutOfSequenceFragment(
          msg_ID,
          m.next_fragment_num,
          is_last_fragment,
          m.data);
    }
  } else {
    LogPrint(eLogInfo,
        "TunnelEndpoint: first fragment of message ",
        msg_ID, " not found. Saved");
    AddOutOfSequenceFragment(
        msg_ID,
        m.next_fragment_num,
        is_last_fragment,
        m.data);
  }
}

void TunnelEndpoint::AddOutOfSequenceFragment(
    uint32_t msg_ID,
    uint8_t fragment_num,
    bool is_last_fragment,
    std::shared_ptr<I2NPMessage> data) {
  auto it = m_OutOfSequenceFragments.find(msg_ID);
  if (it == m_OutOfSequenceFragments.end())
    m_OutOfSequenceFragments.insert(
        std::pair<uint32_t, Fragment> (
          msg_ID,
          {fragment_num, is_last_fragment, data}));
}

void TunnelEndpoint::HandleOutOfSequenceFragment(
    uint32_t msg_ID, TunnelMessageBlockEx& msg) {
  auto it = m_OutOfSequenceFragments.find(msg_ID);
  if (it != m_OutOfSequenceFragments.end()) {
    if (it->second.fragment_num == msg.next_fragment_num) {
      LogPrint(eLogInfo,
          "TunnelEndpoint: out-of-sequence fragment ",
          static_cast<int>(it->second.fragment_num),
          " of message ", msg_ID, " found");
      auto size = it->second.data->GetLength();
      if (msg.data->len + size > msg.data->max_len) {
        LogPrint(eLogInfo,
            "TunnelEndpoint: I2NP message size ",
            msg.data->max_len, " is not enough");
        auto new_msg = ToSharedI2NPMessage(NewI2NPMessage());
        *new_msg = *(msg.data);
        msg.data = new_msg;
      }
      memcpy(  // concatenate out-of-sync fragment
          msg.data->buf + msg.data->len,
          it->second.data->GetBuffer(),
          size);
      msg.data->len += size;
      if (it->second.is_last_fragment) {
        // message complete
        HandleNextMessage(msg);
        m_IncompleteMessages.erase(msg_ID);
      } else {
        msg.next_fragment_num++;
      }
      m_OutOfSequenceFragments.erase(it);
    }
  }
}

void TunnelEndpoint::HandleNextMessage(
    const TunnelMessageBlock& msg) {
  LogPrint(eLogInfo,
      "TunnelEndpoint: HandleNextMessage(): handle fragment of ",
      msg.data->GetLength(), " bytes, msg type: ",
      static_cast<int>(msg.data->GetTypeID()));
  switch (msg.delivery_type) {
    case e_DeliveryTypeLocal:
      i2p::HandleI2NPMessage(msg.data);
    break;
    case e_DeliveryTypeTunnel:
      i2p::transport::transports.SendMessage(
          msg.hash,
          i2p::CreateTunnelGatewayMsg(
            msg.tunnel_ID,
            msg.data));
    break;
    case e_DeliveryTypeRouter:
      // check if message is sent to us
      if (msg.hash == i2p::context.GetRouterInfo().GetIdentHash()) {
        i2p::HandleI2NPMessage(msg.data);
      } else {
        // to somebody else
        if (!m_IsInbound) {  // outbound transit tunnel
        /*  auto type_ID = msg.data->GetTypeID ();
          if (type_ID == eI2NPDatabaseStore || type_ID == eI2NPDatabaseSearchReply )
            // catch RI or reply with new list of routers
            i2p::data::netdb.PostI2NPMsg (msg.data);*/
          // TODO(unassigned): ^ ???
          i2p::transport::transports.SendMessage(msg.hash, msg.data);
        } else {  // we shouldn't send this message. possible leakage
          LogPrint(eLogError,
              "TunnelEndpoint: message to another router "
              "arrived from an inbound tunnel. Dropped");
        }
      }
    break;
    default:
      LogPrint(eLogError,
          "TunnelMessage: unknown delivery type ",
          static_cast<int>(msg.delivery_type));
  }
}

}  // namespace tunnel
}  // namespace i2p
