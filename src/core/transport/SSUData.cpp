/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#include "SSUData.h"

#include <boost/bind.hpp>

#include <stdlib.h>

#include <cstdint>
#include <memory>

#include "NetworkDatabase.h"
#include "SSU.h"
#include "util/Log.h"
#include "util/Timestamp.h"

namespace i2p {
namespace transport {

void IncompleteMessage::AttachNextFragment(
    const uint8_t* fragment,
    size_t fragmentSize) {
  if (msg->len + fragmentSize > msg->maxLen) {
    LogPrint(eLogInfo,
        "Transport: SSU I2NP message size ", msg->maxLen, " is not enough");
    auto newMsg = ToSharedI2NPMessage(NewI2NPMessage());
    *newMsg = *msg;
    msg = newMsg;
  }
  memcpy(msg->buf + msg->len, fragment, fragmentSize);
  msg->len += fragmentSize;
  nextFragmentNum++;
}

SSUData::SSUData(
    SSUSession& session)
    : m_Session(session),
      m_ResendTimer(session.GetService()),
      m_DecayTimer(session.GetService()),
      m_IncompleteMessagesCleanupTimer(session.GetService()) {
  LogPrint(eLogDebug, "SSUData: initializing");
  m_MaxPacketSize = session.IsV6() ?
    SSU_V6_MAX_PACKET_SIZE :
    SSU_V4_MAX_PACKET_SIZE;
  m_PacketSize = m_MaxPacketSize;
  auto remoteRouter = session.GetRemoteRouter();
  if (remoteRouter)
    AdjustPacketSize(*remoteRouter);
}

SSUData::~SSUData() {
  LogPrint(eLogDebug, "SSUData: destroying");
}

void SSUData::Start() {
  LogPrint(eLogDebug, "SSUData: starting");
  ScheduleIncompleteMessagesCleanup();
}

void SSUData::Stop() {
  LogPrint(eLogDebug, "SSUData: stopping");
  m_ResendTimer.cancel();
  m_DecayTimer.cancel();
  m_IncompleteMessagesCleanupTimer.cancel();
}

void SSUData::AdjustPacketSize(
    const i2p::data::RouterInfo& remoteRouter) {
  LogPrint(eLogDebug,
      "SSUData: adjusting packet size");
  auto ssuAddress = remoteRouter.GetSSUAddress();
  if (ssuAddress && ssuAddress->mtu) {
    if (m_Session.IsV6 ())
      m_PacketSize = ssuAddress->mtu - IPV6_HEADER_SIZE - UDP_HEADER_SIZE;
    else
      m_PacketSize = ssuAddress->mtu - IPV4_HEADER_SIZE - UDP_HEADER_SIZE;
    if (m_PacketSize > 0) {
      // make sure packet size multiple of 16
      m_PacketSize >>= 4;
      m_PacketSize <<= 4;
      if (m_PacketSize > m_MaxPacketSize)
        m_PacketSize = m_MaxPacketSize;
      LogPrint(eLogInfo,
          "SSUData:", m_Session.GetFormattedSessionInfo(),
          "MTU=", ssuAddress->mtu, " packet size=", m_PacketSize);
    } else {
      LogPrint(eLogWarning, "SSUData: unexpected MTU ", ssuAddress->mtu);
      m_PacketSize = m_MaxPacketSize;
    }
  }
}

void SSUData::UpdatePacketSize(
    const i2p::data::IdentHash& remoteIdent) {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "updating packet size");
  auto routerInfo = i2p::data::netdb.FindRouter(remoteIdent);
  if (routerInfo)
    AdjustPacketSize(*routerInfo);
}

void SSUData::ProcessSentMessageAck(
    uint32_t msgID) {
  // TODO(unassigned): too spammy? keep?
  //LogPrint(eLogDebug,
      //"SSUData:", m_Session.GetFormattedSessionInfo(),
      //"processing sent message ACK");
  auto it = m_SentMessages.find(msgID);
  if (it != m_SentMessages.end()) {
    m_SentMessages.erase(it);
    if (m_SentMessages.empty())
      m_ResendTimer.cancel();
  }
}

void SSUData::ProcessAcks(
    uint8_t *& buf,
    uint8_t flag) {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(), "processing ACKs");
  if (flag & DATA_FLAG_EXPLICIT_ACKS_INCLUDED) {
    // explicit ACKs
    uint8_t numAcks =*buf;
    buf++;
    for (int i = 0; i < numAcks; i++)
      ProcessSentMessageAck(bufbe32toh(buf+i*4));
    buf += numAcks*4;
  }
  if (flag & DATA_FLAG_ACK_BITFIELDS_INCLUDED) {
    // explicit ACK bitfields
    uint8_t numBitfields =*buf;
    buf++;
    for (int i = 0; i < numBitfields; i++) {
      uint32_t msgID = bufbe32toh(buf);
      buf += 4;  // msgID
      auto it = m_SentMessages.find(msgID);
      // process individual Ack bitfields
      bool isNonLast = false;
      int fragment = 0;
      do {
        uint8_t bitfield = *buf;
        isNonLast = bitfield & 0x80;
        bitfield &= 0x7F;  // clear MSB
        if (bitfield && it != m_SentMessages.end()) {
          int numSentFragments = it->second->fragments.size();
          // process bits
          uint8_t mask = 0x01;
          for (int j = 0; j < 7; j++) {
            if (bitfield & mask) {
              if (fragment < numSentFragments)
                it->second->fragments[fragment].reset(nullptr);
            }
            fragment++;
            mask <<= 1;
          }
        }
        buf++;
      }
      while (isNonLast);
    }
  }
}

void SSUData::ProcessFragments(
    uint8_t* buf) {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "processing fragments");
  uint8_t numFragments = *buf;  // number of fragments
  buf++;
  for (int i = 0; i < numFragments; i++) {
    uint32_t msgID = bufbe32toh(buf);  // message ID
    buf += 4;
    uint8_t frag[4];
    frag[0] = 0;
    memcpy(frag + 1, buf, 3);
    buf += 3;
    uint32_t fragmentInfo = bufbe32toh(frag);  // fragment info
    uint16_t fragmentSize = fragmentInfo & 0x3FFF;  // bits 0 - 13
    bool isLast = fragmentInfo & 0x010000;  // bit 16
    uint8_t fragmentNum = fragmentInfo >> 17;  // bits 23 - 17
    if (fragmentSize >= SSU_V4_MAX_PACKET_SIZE) {
      LogPrint(eLogError,
          "SSUData:", m_Session.GetFormattedSessionInfo(),
          "fragment size ", fragmentSize, "exceeds max SSU packet size");
      return;
    }
    //  find message with msgID
    auto it = m_IncompleteMessages.find(msgID);
    if (it == m_IncompleteMessages.end()) {
      // create new message
      auto msg = ToSharedI2NPMessage(NewI2NPShortMessage());
      msg->len -= I2NP_SHORT_HEADER_SIZE;
      it = m_IncompleteMessages.insert(
          std::make_pair(
            msgID,
            std::unique_ptr<IncompleteMessage>(
                std::make_unique<IncompleteMessage>(msg)))).first;
    }
    std::unique_ptr<IncompleteMessage>& incompleteMessage = it->second;
    // handle current fragment
    if (fragmentNum == incompleteMessage->nextFragmentNum) {
      // expected fragment
      incompleteMessage->AttachNextFragment(buf, fragmentSize);
      if (!isLast && !incompleteMessage->savedFragments.empty()) {
        // try saved fragments
        for (auto it1 = incompleteMessage->savedFragments.begin();
            it1 != incompleteMessage->savedFragments.end();) {
          auto& savedFragment = *it1;
          if (savedFragment->fragmentNum ==
              incompleteMessage->nextFragmentNum) {
            incompleteMessage->AttachNextFragment(
                savedFragment->buf,
                savedFragment->len);
            isLast = savedFragment->isLast;
            incompleteMessage->savedFragments.erase(it1++);
          } else {
            break;
          }
        }
        if (isLast)
          LogPrint(eLogDebug,
              "SSUData:", m_Session.GetFormattedSessionInfo(),
              "message ", msgID, " is complete");
      }
    } else {
      if (fragmentNum < incompleteMessage->nextFragmentNum) {
        // duplicate fragment
        LogPrint(eLogWarning,
            "SSUData:", m_Session.GetFormattedSessionInfo(),
            " ignoring duplicate fragment ", static_cast<int>(fragmentNum),
            " of message ", msgID);
      } else {
        // missing fragment
        LogPrint(eLogWarning,
            "SSUData:", m_Session.GetFormattedSessionInfo(),
            " missing fragments from ",
            static_cast<int>(incompleteMessage->nextFragmentNum),
            " to ", fragmentNum - 1, " of message ", msgID);
        auto savedFragment =
          std::make_unique<Fragment>(fragmentNum, buf, fragmentSize, isLast);
        if (incompleteMessage->savedFragments.insert(
              std::unique_ptr<Fragment>(std::move(savedFragment))).second)
          incompleteMessage->lastFragmentInsertTime =
            i2p::util::GetSecondsSinceEpoch();
        else
          LogPrint(eLogWarning,
              "SSUData:", m_Session.GetFormattedSessionInfo(),
              "fragment ", static_cast<int>(fragmentNum),
              " of message ", msgID, " is already saved");
      }
      isLast = false;
    }
    if (isLast) {
      // delete incomplete message
      auto msg = incompleteMessage->msg;
      incompleteMessage->msg = nullptr;
      m_IncompleteMessages.erase(msgID);
      // process message
      SendMsgAck(msgID);
      msg->FromSSU(msgID);
      if (m_Session.GetState() == eSessionStateEstablished) {
        if (!m_ReceivedMessages.count(msgID)) {
          if (m_ReceivedMessages.size() > MAX_NUM_RECEIVED_MESSAGES)
            m_ReceivedMessages.clear();
          else
            ScheduleDecay();
          m_ReceivedMessages.insert(msgID);
          m_Handler.PutNextMessage(msg);
        } else {
          LogPrint(eLogWarning,
              "SSUData:", m_Session.GetFormattedSessionInfo(),
              "SSU message ", msgID, " already received");
        }
      } else {
        auto i2np_type = msg->GetTypeID();
        // we expect DeliveryStatus
        if (i2np_type == e_I2NPDeliveryStatus) {
          LogPrint(eLogInfo,
              "SSUData:", m_Session.GetFormattedSessionInfo(),
              "SSU session established");
          m_Session.Established();
        } else if (i2np_type == e_I2NPDatabaseStore) {
          // we got a database store message
          LogPrint(eLogInfo,
              "SSUData:", m_Session.GetFormattedSessionInfo(),
              "Got DSM From SSU");
          m_ReceivedMessages.insert(msgID);
          m_Handler.PutNextMessage(msg);
        } else {
          LogPrint(eLogError,
              "SSUData:", m_Session.GetFormattedSessionInfo(),
              "SSU unexpected message ",
              static_cast<int>(msg->GetTypeID()));
        }
      }
    } else {
      SendFragmentAck(msgID, fragmentNum);
    }
    buf += fragmentSize;
  }
}

void SSUData::FlushReceivedMessage() {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "flushing received message");
  m_Handler.Flush();
}

void SSUData::ProcessMessage(
    uint8_t* buf,
    size_t len) {
  // uint8_t* start = buf;
  uint8_t flag = *buf;
  buf++;
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "processing message: flags=", static_cast<std::size_t>(flag),
      " len=", len);
  // process acks if presented
  if (flag & (DATA_FLAG_ACK_BITFIELDS_INCLUDED | DATA_FLAG_EXPLICIT_ACKS_INCLUDED))
    ProcessAcks(buf, flag);
  // extended data if presented
  if (flag & DATA_FLAG_EXTENDED_DATA_INCLUDED) {
    uint8_t extendedDataSize = *buf;
    buf++;  // size
    LogPrint(eLogDebug,
        "SSUData:", m_Session.GetFormattedSessionInfo(),
        "SSU extended data of ",
        static_cast<int>(extendedDataSize), " bytes presented");
    buf += extendedDataSize;
  }
  // process data
  ProcessFragments(buf);
}

void SSUData::Send(
    std::shared_ptr<i2p::I2NPMessage> msg) {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "sending message");
  uint32_t msgID = msg->ToSSU();
  if (m_SentMessages.count(msgID) > 0) {
    LogPrint(eLogWarning,
        "SSUData:", m_Session.GetFormattedSessionInfo(),
        "message ", msgID, " was already sent");
    return;
  }
  if (m_SentMessages.empty())  // schedule resend at first message only
    ScheduleResend();
  auto ret = m_SentMessages.insert(
      std::make_pair(
        msgID,
        std::unique_ptr<SentMessage>(std::make_unique<SentMessage>())));
  std::unique_ptr<SentMessage>& sentMessage = ret.first->second;
  if (ret.second) {
    sentMessage->nextResendTime =
      i2p::util::GetSecondsSinceEpoch() + RESEND_INTERVAL;
    sentMessage->numResends = 0;
  }
  auto& fragments = sentMessage->fragments;
  // 9  =  flag + #frg(1) + messageID(4) + frag info (3)
  size_t payloadSize = m_PacketSize - SSU_HEADER_SIZE_MIN - 9;
  size_t len = msg->GetLength();
  uint8_t* msgBuf = msg->GetSSUHeader();
  uint32_t fragmentNum = 0;
  while (len > 0) {
    auto fragment = std::make_unique<Fragment>();
    fragment->fragmentNum = fragmentNum;
    uint8_t* buf = fragment->buf;
    uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
    *payload = DATA_FLAG_WANT_REPLY;  // for compatibility
    payload++;
    *payload = 1;  // always 1 message fragment per message
    payload++;
    htobe32buf(payload, msgID);
    payload += 4;
    bool isLast = (len <= payloadSize);
    size_t size = isLast ? len : payloadSize;
    uint32_t fragmentInfo = (fragmentNum << 17);
    if (isLast)
      fragmentInfo |= 0x010000;
    fragmentInfo |= size;
    fragmentInfo = htobe32(fragmentInfo);
    memcpy(payload, reinterpret_cast<uint8_t *>((&fragmentInfo)) + 1, 3);
    payload += 3;
    memcpy(payload, msgBuf, size);
    size += payload - buf;
    if (size & 0x0F)  // make sure 16 bytes boundary
      size = ((size >> 4) + 1) << 4;  // (/16 + 1)*16
    fragment->len = size;
    fragments.push_back(std::unique_ptr<Fragment>(std::move(fragment)));
    // encrypt message with session key
    m_Session.FillHeaderAndEncrypt(PAYLOAD_TYPE_DATA, buf, size);
    try {
      m_Session.Send(buf, size);
    } catch (boost::system::system_error& ec) {
      LogPrint(eLogError,
          "SSUData:", m_Session.GetFormattedSessionInfo(),
          "can't send SSU fragment: '", ec.what(), "'");
    }
    if (!isLast) {
      len -= payloadSize;
      msgBuf += payloadSize;
    } else {
      len = 0;
    }
    fragmentNum++;
  }
}

void SSUData::SendMsgAck(
    uint32_t msgID) {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "sending message ACK");
  // actual length is 44 = 37 + 7 but pad it to multiple of 16
  uint8_t buf[48 + 18];
  uint8_t * payload = buf + SSU_HEADER_SIZE_MIN;
  *payload = DATA_FLAG_EXPLICIT_ACKS_INCLUDED;  // flag
  payload++;
  *payload = 1;  // number of ACKs
  payload++;
  *(reinterpret_cast<uint32_t *>(payload)) = htobe32(msgID);  // msgID
  payload += 4;
  *payload = 0;  // number of fragments
  // encrypt message with session key
  m_Session.FillHeaderAndEncrypt(PAYLOAD_TYPE_DATA, buf, 48);
  m_Session.Send(buf, 48);
}

void SSUData::SendFragmentAck(
    uint32_t msgID,
    int fragmentNum) {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "sending fragment ACK");
  if (fragmentNum > 64) {
    LogPrint(eLogWarning,
        "SSUData:", m_Session.GetFormattedSessionInfo(),
        "fragment number ", fragmentNum, " exceeds 64");
    return;
  }
  uint8_t buf[64 + 18];
  uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
  *payload = DATA_FLAG_ACK_BITFIELDS_INCLUDED;  // flag
  payload++;
  *payload = 1;  // number of ACK bitfields
  payload++;
  // one ack
  *(reinterpret_cast<uint32_t *>(payload)) = htobe32(msgID);  // msgID
  payload += 4;
  div_t d = div(fragmentNum, 7);
  memset(payload, 0x80, d.quot);  // 0x80 means non-last
  payload += d.quot;
  *payload = 0x01 << d.rem;  // set corresponding bit
  payload++;
  *payload = 0;  // number of fragments
  size_t len = d.quot < 4 ? 48 : 64;  // 48 = 37 + 7 + 4 (3+1)
  // encrypt message with session key
  m_Session.FillHeaderAndEncrypt(PAYLOAD_TYPE_DATA, buf, len);
  m_Session.Send(buf, len);
}

void SSUData::ScheduleResend() {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "scheduling resend");
  m_ResendTimer.cancel();
  m_ResendTimer.expires_from_now(
      boost::posix_time::seconds(
        RESEND_INTERVAL));
  auto s = m_Session.shared_from_this();
  m_ResendTimer.async_wait(
      [s](
        const boost::system::error_code& ecode) {
      s->m_Data.HandleResendTimer(ecode);
      });
}

void SSUData::HandleResendTimer(
    const boost::system::error_code& ecode) {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "handling resend timer");
  if (ecode != boost::asio::error::operation_aborted) {
    uint32_t ts = i2p::util::GetSecondsSinceEpoch();
    for (auto it = m_SentMessages.begin(); it != m_SentMessages.end();) {
      if (ts >= it->second->nextResendTime) {
        if (it->second->numResends < MAX_NUM_RESENDS) {
          for (auto& f : it->second->fragments)
            if (f) {
              try {
                m_Session.Send(f->buf, f->len);  // resend
              } catch (boost::system::system_error& ec) {
                LogPrint(eLogError,
                    "SSUData:", m_Session.GetFormattedSessionInfo(),
                    "can't resend SSU fragment: '", ec.what(), "'");
              }
            }
          it->second->numResends++;
          it->second->nextResendTime += it->second->numResends*RESEND_INTERVAL;
          it++;
        } else {
          LogPrint(eLogError,
              "SSUData:", m_Session.GetFormattedSessionInfo(),
              "SSU message has not been ACKed after ",
              MAX_NUM_RESENDS, " attempts. Deleted");
          it = m_SentMessages.erase(it);
        }
      } else {
        it++;
      }
    }
    ScheduleResend();
  }
}

void SSUData::ScheduleDecay() {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "scheduling decay");
  m_DecayTimer.cancel();
  m_DecayTimer.expires_from_now(
      boost::posix_time::seconds(
        DECAY_INTERVAL));
  auto s = m_Session.shared_from_this();
  m_ResendTimer.async_wait(
      [s](
        const boost::system::error_code& ecode) {
      s->m_Data.HandleDecayTimer(ecode);
      });
}

void SSUData::HandleDecayTimer(
    const boost::system::error_code& ecode) {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "handling decay");
  if (ecode != boost::asio::error::operation_aborted)
    m_ReceivedMessages.clear();
}

void SSUData::ScheduleIncompleteMessagesCleanup() {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "scheduling incomplete messages cleanup");
  m_IncompleteMessagesCleanupTimer.cancel();
  m_IncompleteMessagesCleanupTimer.expires_from_now(
      boost::posix_time::seconds(
        INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT));
  auto s = m_Session.shared_from_this();
  m_IncompleteMessagesCleanupTimer.async_wait(
      [s](
        const boost::system::error_code& ecode) {
      s->m_Data.HandleIncompleteMessagesCleanupTimer(ecode);
      });
}

void SSUData::HandleIncompleteMessagesCleanupTimer(
    const boost::system::error_code& ecode) {
  LogPrint(eLogDebug,
      "SSUData:", m_Session.GetFormattedSessionInfo(),
      "handling incomplete messages cleanup");
  if (ecode != boost::asio::error::operation_aborted) {
    uint32_t ts = i2p::util::GetSecondsSinceEpoch();
    for (auto it = m_IncompleteMessages.begin ();
        it != m_IncompleteMessages.end();) {
      if (ts > it->second->lastFragmentInsertTime +
          INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT) {
        LogPrint(eLogError,
            "SSUData:", m_Session.GetFormattedSessionInfo(),
            "SSU message ", it->first, " was not completed in ",
            INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT, " seconds. Deleted");
        it = m_IncompleteMessages.erase(it);
      } else {
        it++;
      }
    }
    ScheduleIncompleteMessagesCleanup();
  }
}

}  // namespace transport
}  // namespace i2p

