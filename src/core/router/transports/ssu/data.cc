/**                                                                                           //
 * Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
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

#include "core/router/transports/ssu/data.h"

#include <boost/bind.hpp>
#include <boost/endian/conversion.hpp>

#include "core/router/info.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/ssu/server.h"

#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {

// TODO(anonimal): bytestream refactor

void IncompleteMessage::AttachNextFragment(
    const std::uint8_t* fragment,
    std::size_t fragment_size) {
  if (msg->len + fragment_size > msg->max_len) {
    LOG(debug)
      << "Transport: SSU I2NP message size "
      << msg->max_len << " is not enough";
    auto new_msg = ToSharedI2NPMessage(NewI2NPMessage());
    *new_msg = *msg;
    msg = new_msg;
  }
  memcpy(msg->buf + msg->len, fragment, fragment_size);
  msg->len += fragment_size;
  next_fragment_num++;
}

SSUData::SSUData(
    SSUSession& session)
    : m_Session(session),
      m_ResendTimer(session.GetService()),
      m_DecayTimer(session.GetService()),
      m_IncompleteMessagesCleanupTimer(session.GetService()) {
  m_MaxPacketSize = session.IsV6()
    ? SSUSize::PacketMaxIPv6
    : SSUSize::PacketMaxIPv4;
  m_PacketSize = m_MaxPacketSize;
  auto remote_router = session.GetRemoteRouter();
  if (remote_router)
    AdjustPacketSize(*remote_router);
}

SSUData::~SSUData() {}

void SSUData::Start() {
  LOG(debug) << "SSUData: starting";
  ScheduleIncompleteMessagesCleanup();
}

void SSUData::Stop() {
  LOG(debug) << "SSUData: stopping";
  m_ResendTimer.cancel();
  m_DecayTimer.cancel();
  m_IncompleteMessagesCleanupTimer.cancel();
}

void SSUData::AdjustPacketSize(
    const kovri::core::RouterInfo& remote_router) {
  LOG(debug) << "SSUData: adjusting packet size";

  const auto* ssu_address =
      remote_router.GetAddress(m_Session.IsV6(), Transport::SSU);

  if (ssu_address && ssu_address->mtu) {
    if (m_Session.IsV6 ())
      m_PacketSize =
        ssu_address->mtu
        - SSUSize::HeaderIPv6
        - SSUSize::HeaderUDP;
    else
      m_PacketSize =
        ssu_address->mtu
        - SSUSize::HeaderIPv4
        - SSUSize::HeaderUDP;
    if (m_PacketSize > 0) {
      // make sure packet size multiple of 16
      m_PacketSize >>= 4;
      m_PacketSize <<= 4;
      if (m_PacketSize > m_MaxPacketSize)
        m_PacketSize = m_MaxPacketSize;
      LOG(debug)
        << "SSUData:" << m_Session.GetFormattedSessionInfo()
        << "MTU=" << ssu_address->mtu << " packet size=" << m_PacketSize;
    } else {
      LOG(warning) << "SSUData: unexpected MTU " << ssu_address->mtu;
      m_PacketSize = m_MaxPacketSize;
    }
  }
}

void SSUData::UpdatePacketSize(
    const kovri::core::IdentHash& remote_ident) {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "updating packet size";
  auto router_info = kovri::core::netdb.FindRouter(remote_ident);
  if (router_info)
    AdjustPacketSize(*router_info);
}

void SSUData::ProcessSentMessageACK(
    std::uint32_t msg_id) {
  // TODO(unassigned): too spammy? keep?
  //LOG(debug) <<
      //"SSUData:", m_Session.GetFormattedSessionInfo(),
      //"processing sent message ACK");
  auto it = m_SentMessages.find(msg_id);
  if (it != m_SentMessages.end()) {
    m_SentMessages.erase(it);
    if (m_SentMessages.empty())
      m_ResendTimer.cancel();
  }
}

void SSUData::ProcessACKs(
    std::uint8_t*& buf,
    std::uint8_t flag) {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo() << "processing ACKs";
  if (flag & SSUFlag::DataExplicitACKsIncluded) {
    // explicit ACKs
    auto num_ACKs = *buf;
    buf++;
    for (auto i = 0; i < num_ACKs; i++)
      ProcessSentMessageACK(
          core::InputByteStream::Read<std::uint32_t>(buf + i * 4));
    buf += num_ACKs * 4;
  }
  if (flag & SSUFlag::DataACKBitfieldsIncluded) {
    // explicit ACK bitfields
    auto num_bitfields = *buf;
    buf++;
    for (auto i = 0; i < num_bitfields; i++) {
      auto const msg_id = core::InputByteStream::Read<std::uint32_t>(buf);
      buf += 4;  // message ID
      auto it = m_SentMessages.find(msg_id);
      // process individual ACK bitfields
      bool is_not_last = false;
      std::size_t fragment = 0;
      do {
        auto bitfield = *buf;
        is_not_last = bitfield & 0x80;
        bitfield &= 0x7F;  // clear MSB
        if (bitfield && it != m_SentMessages.end()) {
          auto num_send_fragments = it->second->fragments.size();
          // process bits
          std::uint8_t mask = 0x01;
          for (auto j = 0; j < 7; j++) {
            if (bitfield & mask) {
              if (fragment < num_send_fragments)
                it->second->fragments[fragment].reset(nullptr);
            }
            fragment++;
            mask <<= 1;
          }
        }
        buf++;
      }
      while (is_not_last);
    }
  }
}

void SSUData::ProcessFragments(
    std::uint8_t* buf) {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "processing fragments";
  auto num_fragments = *buf;  // number of fragments
  buf++;
  for (auto i = 0; i < num_fragments; i++) {
    auto const msg_id = core::InputByteStream::Read<std::uint32_t>(buf);
    buf += 4;
    std::array<std::uint8_t, 4> frag;
    frag.at(0) = 0;
    memcpy(frag.data() + 1, buf, 3);
    buf += 3;
    auto const fragment_info =
        core::InputByteStream::Read<std::uint32_t>(frag.data());
    auto fragment_size = fragment_info & 0x3FFF;  // bits 0 - 13
    bool is_last = fragment_info & 0x010000;  // bit 16
    std::uint8_t fragment_num = fragment_info >> 17;  // bits 23 - 17
    if (fragment_size >= SSUSize::PacketMaxIPv4) {
      LOG(error)
        << "SSUData:" << m_Session.GetFormattedSessionInfo()
        << "fragment size " << fragment_size << "exceeds max SSU packet size";
      return;
    }
    //  find message with message ID
    auto it = m_IncompleteMessages.find(msg_id);
    if (it == m_IncompleteMessages.end()) {
      // create new message
      auto msg = ToSharedI2NPMessage(NewI2NPShortMessage());
      msg->len -= I2NP_SHORT_HEADER_SIZE;
      it = m_IncompleteMessages.insert(
          std::make_pair(
              msg_id,
              std::unique_ptr<IncompleteMessage>(
                  std::make_unique<IncompleteMessage>(msg)))).first;
    }
    std::unique_ptr<IncompleteMessage>& incomplete_message = it->second;
    // handle current fragment
    if (fragment_num == incomplete_message->next_fragment_num) {
      // expected fragment
      incomplete_message->AttachNextFragment(buf, fragment_size);
      if (!is_last && !incomplete_message->saved_fragments.empty()) {
        // try saved fragments
        for (auto saved_fragment = incomplete_message->saved_fragments.begin();
            saved_fragment != incomplete_message->saved_fragments.end();) {
          auto& fragment = *saved_fragment;
          if (fragment->fragment_num ==
              incomplete_message->next_fragment_num) {
            incomplete_message->AttachNextFragment(
                fragment->buffer.data(),
                fragment->len);
            is_last = fragment->is_last;
            incomplete_message->saved_fragments.erase(saved_fragment++);
          } else {
            break;
          }
        }
        if (is_last)
          LOG(debug)
            << "SSUData:" << m_Session.GetFormattedSessionInfo()
            << "message " << msg_id << " is complete";
      }
    } else {
      if (fragment_num < incomplete_message->next_fragment_num) {
        // duplicate fragment
        LOG(warning)
          << "SSUData:" << m_Session.GetFormattedSessionInfo()
          << " ignoring duplicate fragment " << static_cast<int>(fragment_num)
          << " of message " << msg_id;
      } else {
        // missing fragment
        LOG(warning)
          << "SSUData:" << m_Session.GetFormattedSessionInfo()
          << "missing fragments from "
          << static_cast<int>(incomplete_message->next_fragment_num)
          << " to " << fragment_num - 1 << " of message " << msg_id;
        auto saved_fragment =
          std::make_unique<Fragment>(fragment_num, buf, fragment_size, is_last);
        if (incomplete_message->saved_fragments.insert(
              std::unique_ptr<Fragment>(std::move(saved_fragment))).second)
          incomplete_message->last_fragment_insert_time =
            kovri::core::GetSecondsSinceEpoch();
        else
          LOG(warning)
            << "SSUData:" << m_Session.GetFormattedSessionInfo()
            << "fragment " << static_cast<int>(fragment_num)
            << " of message " << msg_id << " is already saved";
      }
      is_last = false;
    }
    if (is_last) {
      // delete incomplete message
      auto msg = incomplete_message->msg;
      incomplete_message->msg = nullptr;
      m_IncompleteMessages.erase(msg_id);
      // process message
      SendMsgACK(msg_id);
      msg->FromSSU(msg_id);
      if (m_Session.GetState() == SessionState::Established) {
        if (!m_ReceivedMessages.count(msg_id)) {
          if (m_ReceivedMessages.size() > SSUSize::MaxReceivedMessages)
            m_ReceivedMessages.clear();
          else
            ScheduleDecay();
          m_ReceivedMessages.insert(msg_id);
          m_Handler.PutNextMessage(msg);
        } else {
          LOG(warning)
            << "SSUData:" << m_Session.GetFormattedSessionInfo()
            << "SSU message " << msg_id << " already received";
        }
      } else {
        auto I2NP_type = msg->GetTypeID();
        // we expect DeliveryStatus
        if (I2NP_type == I2NPDeliveryStatus) {
          LOG(debug)
            << "SSUData:" << m_Session.GetFormattedSessionInfo()
            << "SSU session established";
          m_Session.Established();
        } else if (I2NP_type == I2NPDatabaseStore) {
          // we got a database store message
          LOG(debug)
            << "SSUData:" << m_Session.GetFormattedSessionInfo()
            << "Got DSM From SSU";
          m_ReceivedMessages.insert(msg_id);
          m_Handler.PutNextMessage(msg);
        } else {
          LOG(warning)
            << "SSUData:" << m_Session.GetFormattedSessionInfo()
            << "SSU unexpected message "
            << static_cast<int>(msg->GetTypeID());
        }
      }
    } else {
      SendFragmentACK(msg_id, fragment_num);
    }
    buf += fragment_size;
  }
}

void SSUData::FlushReceivedMessage() {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "flushing received message";
  m_Handler.Flush();
}

void SSUData::ProcessMessage(
    std::uint8_t* buf,
    std::size_t len) {
  // std::uint8_t* start = buf;
  std::uint8_t flag = *buf;
  buf++;
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "processing message: flags=" << static_cast<std::size_t>(flag)
    << " len=" << len;
  // process acks if presented
  if (flag &
      (SSUFlag::DataACKBitfieldsIncluded |
       SSUFlag::DataExplicitACKsIncluded))
    ProcessACKs(buf, flag);
  // extended data if presented
  if (flag & SSUFlag::DataExtendedIncluded) {
    std::uint8_t extended_data_size = *buf;
    buf++;  // size
    LOG(debug)
      << "SSUData:" << m_Session.GetFormattedSessionInfo()
      << "SSU extended data of "
      << static_cast<int>(extended_data_size) << " bytes presented";
    buf += extended_data_size;
  }
  // process data
  ProcessFragments(buf);
}

// TODO(anonimal): bytestream refactor
void SSUData::Send(
    std::shared_ptr<kovri::core::I2NPMessage> msg) {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "sending message";
  auto msg_id = msg->ToSSU();
  if (m_SentMessages.count(msg_id) > 0) {
    LOG(warning)
      << "SSUData:" << m_Session.GetFormattedSessionInfo()
      << "message " << msg_id << " was already sent";
    return;
  }
  if (m_SentMessages.empty())  // schedule resend at first message only
    ScheduleResend();
  auto ret =
    m_SentMessages.insert(
        std::make_pair(
            msg_id,
            std::unique_ptr<SentMessage>(std::make_unique<SentMessage>())));
  std::unique_ptr<SentMessage>& sent_message = ret.first->second;
  if (ret.second) {
    sent_message->next_resend_time =
      kovri::core::GetSecondsSinceEpoch()
      + SSUDuration::ResendInterval;
    sent_message->num_resends = 0;
  }
  auto& fragments = sent_message->fragments;
  // 9 = flag + #frg(1) + messageID(4) + frag info (3)
  auto payload_size = m_PacketSize - SSUSize::HeaderMin - 9;
  auto len = msg->GetLength();
  auto msg_buf = msg->GetSSUHeader();
  std::size_t fragment_num = 0;
  while (len > 0) {
    auto fragment = std::make_unique<Fragment>();
    fragment->fragment_num = fragment_num;
    auto buf = fragment->buffer.data();
    auto payload = buf + SSUSize::HeaderMin;
    *payload = SSUFlag::DataWantReply;  // for compatibility
    payload++;
    *payload = 1;  // always 1 message fragment per message
    payload++;
    core::OutputByteStream::Write<std::uint32_t>(payload, msg_id);
    payload += 4;
    bool is_last = (len <= payload_size);
    auto size = is_last ? len : payload_size;
    std::uint32_t fragment_info = (fragment_num << 17);
    if (is_last)
      fragment_info |= 0x010000;
    fragment_info |= size;
    boost::endian::native_to_big_inplace(fragment_info);
    memcpy(payload, reinterpret_cast<std::uint8_t *>((&fragment_info)) + 1, 3);
    payload += 3;
    memcpy(payload, msg_buf, size);
    size += payload - buf;
    if (size & 0x0F)  // make sure 16 bytes boundary
      size = ((size >> 4) + 1) << 4;  // (/16 + 1) * 16
    fragment->len = size;
    fragments.push_back(std::unique_ptr<Fragment>(std::move(fragment)));
    // encrypt message with session key
    m_Session.FillHeaderAndEncrypt(SSUPayloadType::Data, buf, size);
    try {
      m_Session.Send(buf, size);
    } catch (const boost::system::system_error& ec) {
      LOG(error)
        << "SSUData:" << m_Session.GetFormattedSessionInfo()
        << "can't send SSU fragment: '" << ec.what() << "'";
    }
    if (!is_last) {
      len -= payload_size;
      msg_buf += payload_size;
    } else {
      len = 0;
    }
    fragment_num++;
  }
}

void SSUData::SendMsgACK(
    std::uint32_t msg_id) {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "sending message ACK";
  // actual length is 44 = 37 + 7 but pad it to multiple of 16
  std::array<std::uint8_t, 48 + 18> buf;
  auto payload = buf.data() + SSUSize::HeaderMin;
  *payload = SSUFlag::DataExplicitACKsIncluded;  // flag
  payload++;
  *payload = 1;  // number of ACKs
  payload++;
  *(reinterpret_cast<std::uint32_t *>(payload)) = boost::endian::native_to_big(msg_id);  // msg_id
  payload += 4;
  *payload = 0;  // number of fragments
  // encrypt message with session key
  m_Session.FillHeaderAndEncrypt(SSUPayloadType::Data, buf.data(), 48);
  m_Session.Send(buf.data(), 48);
}

void SSUData::SendFragmentACK(
    std::uint32_t msg_id,
    std::size_t fragment_num) {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "sending fragment ACK";
  if (fragment_num > 64) {
    LOG(warning)
      << "SSUData:" << m_Session.GetFormattedSessionInfo()
      << "fragment number " << fragment_num << " exceeds 64";
    return;
  }
  std::array<std::uint8_t, 64 + 18> buf;  // TODO(unassigned): document values
  auto payload = buf.data() + SSUSize::HeaderMin;
  *payload = SSUFlag::DataACKBitfieldsIncluded;  // flag
  payload++;
  *payload = 1;  // number of ACK bitfields
  payload++;
  // one ack
  *(reinterpret_cast<std::uint32_t *>(payload)) = boost::endian::native_to_big(msg_id);  // msg_id
  payload += 4;
  div_t d = div(fragment_num, 7);
  memset(payload, 0x80, d.quot);  // 0x80 means non-last
  payload += d.quot;
  *payload = 0x01 << d.rem;  // set corresponding bit
  payload++;
  *payload = 0;  // number of fragments
  auto len = d.quot < 4 ? 48 : 64;  // 48 = 37 + 7 + 4 (3+1)
  // encrypt message with session key
  m_Session.FillHeaderAndEncrypt(SSUPayloadType::Data, buf.data(), len);
  m_Session.Send(buf.data(), len);
}

void SSUData::ScheduleResend() {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "scheduling resend";
  m_ResendTimer.cancel();
  m_ResendTimer.expires_from_now(
      boost::posix_time::seconds{
        static_cast<long>(SSUDuration::ResendInterval)});
  auto s = m_Session.shared_from_this();
  m_ResendTimer.async_wait(
      [s](const boost::system::error_code& ecode) {
      s->m_Data.HandleResendTimer(ecode);
      });
}

void SSUData::HandleResendTimer(
    const boost::system::error_code& ecode) {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "handling resend timer";
  if (ecode != boost::asio::error::operation_aborted) {
    auto ts = kovri::core::GetSecondsSinceEpoch();
    for (auto it = m_SentMessages.begin(); it != m_SentMessages.end();) {
      if (ts >= it->second->next_resend_time) {
        if (it->second->num_resends < SSUDuration::MaxResends) {
          for (auto& fragment : it->second->fragments)
            if (fragment) {
              try {
                m_Session.Send(fragment->buffer.data(), fragment->len);  // resend
              } catch (const boost::system::system_error& ec) {
                LOG(error)
                  << "SSUData:" << m_Session.GetFormattedSessionInfo()
                  << "can't resend SSU fragment: '" << ec.what() << "'";
              }
            }
          it->second->num_resends++;
          it->second->next_resend_time
             += it->second->num_resends * SSUDuration::ResendInterval;
          it++;
        } else {
          LOG(warning)
            << "SSUData:" << m_Session.GetFormattedSessionInfo()
            << "SSU message has not been ACKed after "
            << static_cast<std::size_t>(SSUDuration::MaxResends) << " attempts. Deleted";
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
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo() << "scheduling decay";
  m_DecayTimer.cancel();
  m_DecayTimer.expires_from_now(
      boost::posix_time::seconds{
          static_cast<long>(SSUDuration::DecayInterval)});
  auto s = m_Session.shared_from_this();
  m_ResendTimer.async_wait(
      [s](const boost::system::error_code& ecode) {
      s->m_Data.HandleDecayTimer(ecode);
      });
}

void SSUData::HandleDecayTimer(
    const boost::system::error_code& ecode) {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "handling decay";
  if (ecode != boost::asio::error::operation_aborted)
    m_ReceivedMessages.clear();
}

void SSUData::ScheduleIncompleteMessagesCleanup() {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "scheduling incomplete messages cleanup";
  m_IncompleteMessagesCleanupTimer.cancel();
  m_IncompleteMessagesCleanupTimer.expires_from_now(
      boost::posix_time::seconds{
          static_cast<long>(SSUDuration::IncompleteMessagesCleanupTimeout)});
  auto s = m_Session.shared_from_this();
  m_IncompleteMessagesCleanupTimer.async_wait(
      [s](const boost::system::error_code& ecode) {
      s->m_Data.HandleIncompleteMessagesCleanupTimer(ecode);
      });
}

void SSUData::HandleIncompleteMessagesCleanupTimer(
    const boost::system::error_code& ecode) {
  LOG(debug)
    << "SSUData:" << m_Session.GetFormattedSessionInfo()
    << "handling incomplete messages cleanup";
  if (ecode != boost::asio::error::operation_aborted) {
    auto ts = kovri::core::GetSecondsSinceEpoch();
    std::uint8_t const timeout = SSUDuration::IncompleteMessagesCleanupTimeout;
    for (auto it = m_IncompleteMessages.begin(); it != m_IncompleteMessages.end();) {
      if (ts > it->second->last_fragment_insert_time + timeout) {
        LOG(warning)
          << "SSUData:" << m_Session.GetFormattedSessionInfo()
          << "SSU message " << it->first << " was not completed in "
          << static_cast<std::uint16_t>(timeout) << " seconds. Deleted";
        it = m_IncompleteMessages.erase(it);
      } else {
        it++;
      }
    }
    ScheduleIncompleteMessagesCleanup();
  }
}

}  // namespace core
}  // namespace kovri

