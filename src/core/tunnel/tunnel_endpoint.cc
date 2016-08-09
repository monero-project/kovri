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
      bool isFollowOnFragment = flag & 0x80,
               isLastFragment = true;
      uint32_t msgID = 0;
      int fragmentNum = 0;
      TunnelMessageBlockEx m;
      if (!isFollowOnFragment) {
        // first fragment
        m.deliveryType = (TunnelDeliveryType)((flag >> 5) & 0x03);
        switch (m.deliveryType) {
          case e_DeliveryTypeLocal:  // 0
          break;
          case e_DeliveryTypeTunnel:  // 1
            m.tunnelID = bufbe32toh(fragment);
            fragment += 4;  // tunnelID
            m.hash = i2p::data::IdentHash(fragment);
            fragment += 32;  // hash
          break;
          case e_DeliveryTypeRouter:  // 2
            m.hash = i2p::data::IdentHash(fragment);
            fragment += 32;  // to hash
          break;
          default: {}
        }
        bool isFragmented = flag & 0x08;
        if (isFragmented) {
          // Message ID
          msgID = bufbe32toh(fragment);
          fragment += 4;
          isLastFragment = false;
        }
      } else {
        // follow on
        msgID = bufbe32toh(fragment);  // MessageID
        fragment += 4;
        fragmentNum = (flag >> 1) & 0x3F;  // 6 bits
        isLastFragment = flag & 0x01;
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
      if (!isFollowOnFragment && isLastFragment) {
        HandleNextMessage(m);
      } else {
        if (msgID) {  // msgID is presented, assume message is fragmented
          if (!isFollowOnFragment) {  // create new incomplete message
            m.nextFragmentNum = 1;
            auto ret = m_IncompleteMessages.insert(
                std::pair<uint32_t, TunnelMessageBlockEx>(msgID, m));
            if (ret.second)
              HandleOutOfSequenceFragment(msgID, ret.first->second);
            else
              LogPrint(eLogError,
                  "TunnelEndpoint: incomplete message ",
                  msgID, "already exists");
          } else {
            m.nextFragmentNum = fragmentNum;
            HandleFollowOnFragment(msgID, isLastFragment, m);
          }
        } else {
          LogPrint(eLogError,
              "TunnelEndpoint: message is fragmented, "
              "but msgID is not presented");
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
    uint32_t msgID,
    bool isLastFragment,
    const TunnelMessageBlockEx& m) {
  auto fragment = m.data->GetBuffer();
  auto size = m.data->GetLength();
  auto it = m_IncompleteMessages.find(msgID);
  if (it != m_IncompleteMessages.end()) {
    auto& msg = it->second;
    if (m.nextFragmentNum == msg.nextFragmentNum) {
      // check if message is not too long
      if (msg.data->len + size < I2NP_MAX_MESSAGE_SIZE) {
        if (msg.data->len + size > msg.data->maxLen) {
          LogPrint(eLogInfo,
              "TunnelEndpoint: I2NP message size ",
              msg.data->maxLen, " is not enough");
          auto newMsg = ToSharedI2NPMessage(NewI2NPMessage());
          *newMsg = *(msg.data);
          msg.data = newMsg;
        }
        // concatenate fragment
        memcpy(msg.data->buf + msg.data->len, fragment, size);
        msg.data->len += size;
        if (isLastFragment) {
          // message complete
          HandleNextMessage(msg);
          m_IncompleteMessages.erase(it);
        } else {
          msg.nextFragmentNum++;
          HandleOutOfSequenceFragment(msgID, msg);
        }
      } else {
        LogPrint(eLogError,
            "TunnelEndpoint: fragment ", m.nextFragmentNum,
            " of message ", msgID,
            "exceeds max I2NP message size. Message dropped");
        m_IncompleteMessages.erase(it);
      }
    } else {
      LogPrint(eLogInfo,
          "TunnelEndpoint: unexpected fragment: ",
          static_cast<int>(m.nextFragmentNum),
          " instead: ",
          static_cast<int>(msg.nextFragmentNum),
          " of message ", msgID, ". Saved");
      AddOutOfSequenceFragment(
          msgID,
          m.nextFragmentNum,
          isLastFragment,
          m.data);
    }
  } else {
    LogPrint(eLogInfo,
        "TunnelEndpoint: first fragment of message ",
        msgID, " not found. Saved");
    AddOutOfSequenceFragment(
        msgID,
        m.nextFragmentNum,
        isLastFragment,
        m.data);
  }
}

void TunnelEndpoint::AddOutOfSequenceFragment(
    uint32_t msgID,
    uint8_t fragmentNum,
    bool isLastFragment,
    std::shared_ptr<I2NPMessage> data) {
  auto it = m_OutOfSequenceFragments.find(msgID);
  if (it == m_OutOfSequenceFragments.end())
    m_OutOfSequenceFragments.insert(
        std::pair<uint32_t, Fragment> (
          msgID,
          {fragmentNum, isLastFragment, data}));
}

void TunnelEndpoint::HandleOutOfSequenceFragment(
    uint32_t msgID, TunnelMessageBlockEx& msg) {
  auto it = m_OutOfSequenceFragments.find(msgID);
  if (it != m_OutOfSequenceFragments.end()) {
    if (it->second.fragmentNum == msg.nextFragmentNum) {
      LogPrint(eLogInfo,
          "TunnelEndpoint: out-of-sequence fragment ",
          static_cast<int>(it->second.fragmentNum),
          " of message ", msgID, " found");
      auto size = it->second.data->GetLength();
      if (msg.data->len + size > msg.data->maxLen) {
        LogPrint(eLogInfo,
            "TunnelEndpoint: I2NP message size ",
            msg.data->maxLen, " is not enough");
        auto newMsg = ToSharedI2NPMessage(NewI2NPMessage());
        *newMsg = *(msg.data);
        msg.data = newMsg;
      }
      memcpy(  // concatenate out-of-sync fragment
          msg.data->buf + msg.data->len,
          it->second.data->GetBuffer(),
          size);
      msg.data->len += size;
      if (it->second.isLastFragment) {
        // message complete
        HandleNextMessage(msg);
        m_IncompleteMessages.erase(msgID);
      } else {
        msg.nextFragmentNum++;
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
  switch (msg.deliveryType) {
    case e_DeliveryTypeLocal:
      i2p::HandleI2NPMessage(msg.data);
    break;
    case e_DeliveryTypeTunnel:
      i2p::transport::transports.SendMessage(
          msg.hash,
          i2p::CreateTunnelGatewayMsg(
            msg.tunnelID,
            msg.data));
    break;
    case e_DeliveryTypeRouter:
      // check if message is sent to us
      if (msg.hash == i2p::context.GetRouterInfo().GetIdentHash()) {
        i2p::HandleI2NPMessage(msg.data);
      } else {
        // to somebody else
        if (!m_IsInbound) {  // outbound transit tunnel
        /*  auto typeID = msg.data->GetTypeID ();
          if (typeID == eI2NPDatabaseStore || typeID == eI2NPDatabaseSearchReply )
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
          static_cast<int>(msg.deliveryType));
  }
}

}  // namespace tunnel
}  // namespace i2p
