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

#include "client/api/streaming.h"

#include <algorithm>

#include "client/destination.h"

#include "core/crypto/rand.h"
#include "core/crypto/util/compression.h"

#include "core/router/context.h"
#include "core/router/info.h"

#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace client {

Stream::Stream(
    boost::asio::io_service& service,
    StreamingDestination& local,
    std::shared_ptr<const kovri::core::LeaseSet> remote,
    std::uint16_t port)
    : m_Service(service),
      m_SendStreamID(0),
      m_SequenceNumber(0),
      m_LastReceivedSequenceNumber(-1),
      m_Status(eStreamStatusNew),
      m_IsAckSendScheduled(false),
      m_LocalDestination(local),
      m_RemoteLeaseSet(remote),
      m_ReceiveTimer(m_Service),
      m_ResendTimer(m_Service),
      m_AckSendTimer(m_Service),
      m_NumSentBytes(0),
      m_NumReceivedBytes(0),
      m_Port(port),
      m_WindowSize(MIN_WINDOW_SIZE),
      m_RTT(INITIAL_RTT),
      m_RTO(INITIAL_RTO),
      m_LastWindowSizeIncreaseTime(0),
      m_NumResendAttempts(0),
      m_Exception(__func__) {
        m_RecvStreamID = kovri::core::Rand<std::uint32_t>();
        m_RemoteIdentity = remote->GetIdentity();
        // TODO(unassigned):
        // This type of initialization is a friendly reminder of overall poor design.
        // Though we *should* initialize all m_CurrentRemoteLease members before use,
        // members are "updated" (not initialized) with UpdateCurrentRemoteLease() before they are used;
        // thus rendering discussion of tunnel gateway and ID initialization moot.
        // Writing this TODO instead of flagging CID 135950 as a false-positive
        if (!remote->GetLeases().empty()) {
          auto tunnel_gateway = remote->GetLeases().front().tunnel_gateway;
          if (tunnel_gateway) {
            // Lease could be expired, must update with UpdateCurrentRemoteLease()
            m_CurrentRemoteLease.tunnel_gateway = tunnel_gateway;
          }
        } else {
          // Simply use remote's ident hash, must update with UpdateCurrentRemoteLease()
          m_CurrentRemoteLease.tunnel_gateway = remote->GetIdentHash();
        }
        m_CurrentRemoteLease.tunnel_ID = 0;
        m_CurrentRemoteLease.end_date = 0;
      }

Stream::Stream(
    boost::asio::io_service& service,
    StreamingDestination& local)
    : m_Service(service),
      m_SendStreamID(0),
      m_SequenceNumber(0),
      m_LastReceivedSequenceNumber(-1),
      m_Status(eStreamStatusNew),
      m_IsAckSendScheduled(false),
      m_LocalDestination(local),
      m_CurrentRemoteLease {0, 0, 0},
      m_ReceiveTimer(m_Service),
      m_ResendTimer(m_Service),
      m_AckSendTimer(m_Service),
      m_NumSentBytes(0),
      m_NumReceivedBytes(0),
      m_Port(0),
      m_WindowSize(MIN_WINDOW_SIZE),
      m_RTT(INITIAL_RTT),
      m_RTO(INITIAL_RTO),
      m_LastWindowSizeIncreaseTime(0),
      m_NumResendAttempts(0),
      m_Exception(__func__) {
        m_RecvStreamID = kovri::core::Rand<std::uint32_t>();
      }

Stream::~Stream() {
  Terminate();
  while (!m_ReceiveQueue.empty()) {
    auto packet = m_ReceiveQueue.front();
    m_ReceiveQueue.pop();
    delete packet;
  }
  for (auto it : m_SentPackets)
    delete it;
  m_SentPackets.clear();
  for (auto it : m_SavedPackets)
    delete it;
  m_SavedPackets.clear();
  LOG(debug) << "Stream: stream deleted";
}

void Stream::Terminate() {
  m_AckSendTimer.cancel();
  m_ReceiveTimer.cancel();
  m_ResendTimer.cancel();
  if (m_SendHandler) {
    auto handler = m_SendHandler;
    m_SendHandler = nullptr;
    handler(
        boost::asio::error::make_error_code(
          boost::asio::error::operation_aborted));
  }
}

void Stream::HandleNextPacket(
    Packet* packet) {
  m_NumReceivedBytes += packet->GetLength();
  if (!m_SendStreamID)
    m_SendStreamID = packet->GetReceiveStreamID();
  if (!packet->IsNoAck())  // ack received
    ProcessAck(packet);
  int32_t received_seqn = packet->GetSeqn();
  bool is_syn = packet->IsSYN();
  if (!received_seqn && !is_syn) {
    // plain ack
    LOG(debug) << "Stream: plain ACK received";
    delete packet;
    return;
  }
  LOG(debug) << "Stream: received seqn=" << received_seqn;
  if (is_syn || received_seqn == m_LastReceivedSequenceNumber + 1) {
    // we have received next in sequence message
    ProcessPacket(packet);
    // we should also try stored messages if any
    for (auto it = m_SavedPackets.begin(); it != m_SavedPackets.end();) {
      if ((*it)->GetSeqn() == (std::uint32_t)(m_LastReceivedSequenceNumber + 1)) {
        Packet* savedPacket = *it;
        m_SavedPackets.erase(it++);
        ProcessPacket(savedPacket);
      } else {
        break;
      }
    }
    // schedule ack for last message
    if (m_Status == eStreamStatusOpen) {
      if (!m_IsAckSendScheduled) {
        m_IsAckSendScheduled = true;
        m_AckSendTimer.expires_from_now(
            boost::posix_time::milliseconds(ACK_SEND_TIMEOUT));
        m_AckSendTimer.async_wait(
            std::bind(
              &Stream::HandleAckSendTimer,
              shared_from_this(),
              std::placeholders::_1));
      }
    } else if (is_syn) {
      // we have to send SYN back to incoming connection
      SendBuffer();  // also sets m_IsOpen
    }
  } else {
    if (received_seqn <= m_LastReceivedSequenceNumber) {
      // we have received duplicate
      LOG(warning)
        << "Stream: duplicate message " << received_seqn << " received";
      SendQuickAck();  // resend ack for previous message again
      delete packet;  // packet dropped
    } else {
      LOG(warning)
        << "Stream: missing messages from "
        << m_LastReceivedSequenceNumber + 1
        << " to " << received_seqn - 1;
      // save message and wait for missing message again
      SavePacket(packet);
      if (m_LastReceivedSequenceNumber >= 0) {
        // send NACKs for missing messages ASAP
        if (m_IsAckSendScheduled) {
          m_IsAckSendScheduled = false;
          m_AckSendTimer.cancel();
        }
        SendQuickAck();
      } else {
        // wait for SYN
        m_IsAckSendScheduled = true;
        m_AckSendTimer.expires_from_now(
            boost::posix_time::milliseconds(
              ACK_SEND_TIMEOUT));
        m_AckSendTimer.async_wait(
            std::bind(
              &Stream::HandleAckSendTimer,
              shared_from_this(),
              std::placeholders::_1));
      }
    }
  }
}

void Stream::SavePacket(
    Packet* packet) {
  m_SavedPackets.insert(packet);
}

void Stream::ProcessPacket(
    Packet* packet) {
  // process flags
  std::uint32_t received_seqn = packet->GetSeqn();
  std::uint16_t flags = packet->GetFlags();
  LOG(debug) << "Stream: process seqn=" << received_seqn << " << flags=" << flags;
  const std::uint8_t* option_data = packet->GetOptionData();
  if (flags & PACKET_FLAG_SYNCHRONIZE)
    LOG(debug) << "Stream: synchronize";
  if (flags & PACKET_FLAG_DELAY_REQUESTED) {
    option_data += 2;
  }
  if (flags & PACKET_FLAG_FROM_INCLUDED) {
    option_data += m_RemoteIdentity.FromBuffer(
        option_data,
        packet->GetOptionSize());
    LOG(debug)
      << "Stream: from identity "
      << m_RemoteIdentity.GetIdentHash().ToBase64();
    if (!m_RemoteLeaseSet)
      LOG(debug)
        << "Stream: incoming stream from "
        << m_RemoteIdentity.GetIdentHash().ToBase64();
  }
  if (flags & PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED) {
    std::uint16_t const max_packet_size =
        core::InputByteStream::Read<std::uint16_t>(option_data);
    LOG(debug) << "Stream: max packet size " << max_packet_size;
    option_data += 2;
  }
  if (flags & PACKET_FLAG_SIGNATURE_INCLUDED) {
    LOG(debug) << "Stream: signature";
    // TODO(unassigned): ensure option data isn't overwritten if sig length > 256.
    //   Note: not relevant once #498 / #755 is resolved (first check if they are resolved).
    std::vector<std::uint8_t> signature(m_RemoteIdentity.GetSignatureLen());
    memcpy(signature.data(), option_data, signature.size());
    memset(const_cast<std::uint8_t*>(option_data), 0, signature.size());
    if (!m_RemoteIdentity.Verify(
          packet->GetBuffer(),
          packet->GetLength(),
          signature.data())) {
      LOG(error) << "Stream: signature verification failed";
      Close();
      flags |= PACKET_FLAG_CLOSE;
    }
    memcpy(
        const_cast<std::uint8_t*>(option_data),
        signature.data(),
        signature.size());
    option_data += signature.size();
  }
  packet->offset = packet->GetPayload() - packet->buf;
  if (packet->GetLength() > 0) {
    m_ReceiveQueue.push(packet);
    m_ReceiveTimer.cancel();
  } else {
    delete packet;
  }
  m_LastReceivedSequenceNumber = received_seqn;
  if (flags & (PACKET_FLAG_CLOSE | PACKET_FLAG_RESET)) {
    LOG(debug) << "Stream: " << ((flags & PACKET_FLAG_RESET) ? "reset" : "closed");
    m_Status = eStreamStatusReset;
    Close();
  }
}

void Stream::ProcessAck(
    Packet * packet) {
  bool acknowledged = false;
  auto ts = kovri::core::GetMillisecondsSinceEpoch();
  std::uint32_t ack_through = packet->GetAckThrough();
  int nack_count = packet->GetNACKCount();
  for (auto it = m_SentPackets.begin(); it != m_SentPackets.end();) {
    auto seqn = (*it)->GetSeqn();
    if (seqn <= ack_through) {
      if (nack_count > 0) {
        bool nacked = false;
        for (int i = 0; i < nack_count; i++)
          if (seqn == packet->GetNACK(i)) {
            nacked = true;
            break;
          }
        if (nacked) {
          LOG(debug) << "Stream: packet " << seqn << " NACK";
          it++;
          continue;
        }
      }
      auto sent_packet = *it;
      std::uint64_t rtt = ts - sent_packet->send_time;
      m_RTT = (m_RTT * seqn + rtt) / (seqn + 1);
      m_RTO = m_RTT * 1.5;  // TODO(unassigned): implement this better
      LOG(debug) << "Stream: packet " << seqn << " acknowledged rtt=" << rtt;
      m_SentPackets.erase(it++);
      delete sent_packet;
      acknowledged = true;
      if (m_WindowSize < WINDOW_SIZE) {
        m_WindowSize++;  // slow start
      } else {
        // linear growth
        if (ts > m_LastWindowSizeIncreaseTime + m_RTT) {
          m_WindowSize++;
          if (m_WindowSize > MAX_WINDOW_SIZE)
            m_WindowSize = MAX_WINDOW_SIZE;
          m_LastWindowSizeIncreaseTime = ts;
        }
      }
    } else {
      break;
    }
  }
  if (m_SentPackets.empty())
    m_ResendTimer.cancel();
  if (acknowledged) {
    m_NumResendAttempts = 0;
    SendBuffer();
  }
  if (m_Status == eStreamStatusClosing)
    Close();  // all outgoing messages have been sent
}

std::size_t Stream::Send(
    const std::uint8_t* buf,
    std::size_t len) {
  if (len > 0 && buf) {
    std::unique_lock<std::mutex> l(m_SendBufferMutex);
    m_SendBuffer.clear();
    m_SendBuffer.write((const char *)buf, len);
  }
  m_Service.post(
      std::bind(
        &Stream::SendBuffer,
        shared_from_this()));
  return len;
}

void Stream::AsyncSend(
    const std::uint8_t* buf,
    std::size_t len,
    SendHandler handler) {
  if (m_SendHandler)
    handler(
        boost::asio::error::make_error_code(
          boost::asio::error::in_progress));
  else
    m_SendHandler = handler;
  Send(buf, len);
}

// TODO(anonimal): bytestream refactor
void Stream::SendBuffer() {
  int num_msgs = m_WindowSize - m_SentPackets.size();
  if (num_msgs <= 0)
    return;  // window is full
  bool is_no_ack = m_LastReceivedSequenceNumber < 0;  // first packet
  std::vector<Packet *> packets; {
    std::unique_lock<std::mutex> l(m_SendBufferMutex);
    while ((m_Status == eStreamStatusNew) || (IsEstablished() &&
          !m_SendBuffer.eof() && num_msgs > 0)) {
      Packet* p = new Packet();
      std::uint8_t* packet = p->GetBuffer();
      // TODO(unassigned): implement setters
      std::size_t size = 0;
      core::OutputByteStream::Write<std::uint32_t>(packet + size, m_SendStreamID);
      size += 4;  // sendStreamID
      core::OutputByteStream::Write<std::uint32_t>(packet + size, m_RecvStreamID);
      size += 4;  // receiveStreamID
      core::OutputByteStream::Write<std::uint32_t>(packet + size, m_SequenceNumber++);
      size += 4;  // sequenceNum
      if (is_no_ack)
        core::OutputByteStream::Write<std::uint32_t>(packet + size, m_LastReceivedSequenceNumber);
      else
        core::OutputByteStream::Write<std::uint32_t>(packet + size, 0, false);
      size += 4;  // ack Through
      packet[size] = 0;
      size++;  // NACK count
      packet[size] = m_RTO/1000;
      size++;  // resend delay
      if (m_Status == eStreamStatusNew) {
        // initial packet
        m_Status = eStreamStatusOpen;
        std::uint16_t flags =
          PACKET_FLAG_SYNCHRONIZE        | PACKET_FLAG_FROM_INCLUDED |
          PACKET_FLAG_SIGNATURE_INCLUDED | PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED;
        if (is_no_ack)
          flags |= PACKET_FLAG_NO_ACK;
        core::OutputByteStream::Write<std::uint16_t>(packet + size, flags);
        size += 2;  // flags
        std::size_t identity_len =
          m_LocalDestination.GetOwner().GetIdentity().GetFullLen();
        std::size_t signature_len =
          m_LocalDestination.GetOwner().GetIdentity().GetSignatureLen();
        // identity + signature + packet size
        core::OutputByteStream::Write<std::uint16_t>(
            packet + size, identity_len + signature_len + 2);
        size += 2;  // options size
        m_LocalDestination.GetOwner().GetIdentity().ToBuffer(
            packet + size, identity_len);
        size += identity_len;  // from
        core::OutputByteStream::Write<std::uint16_t>(
            packet + size, STREAMING_MTU);
        size += 2;  // max packet size
        std::uint8_t* signature = packet + size;  // set it later
        // zeroes for now
        memset(signature, 0, signature_len);
        size += signature_len;  // signature
        m_SendBuffer.read(
            reinterpret_cast<char *>(packet + size),
            STREAMING_MTU - size);
        size += m_SendBuffer.gcount();  // payload
        m_LocalDestination.GetOwner().Sign(
            packet,
            size,
            signature);
      } else {
        // follow on packet
	core::OutputByteStream::Write<std::uint16_t>(packet + size, 0, false);
        size += 2;  // flags
        // no options
	core::OutputByteStream::Write<std::uint16_t>(packet + size, 0, false);
        size += 2;  // options size
        m_SendBuffer.read(
            reinterpret_cast<char *>(packet + size),
            STREAMING_MTU - size);
        size += m_SendBuffer.gcount();  // payload
      }
      p->len = size;
      packets.push_back(p);
      num_msgs--;
    }
    if (m_SendBuffer.eof() && m_SendHandler) {
      m_SendHandler(boost::system::error_code());
      m_SendHandler = nullptr;
    }
  }
  if (packets.size() > 0) {
    m_IsAckSendScheduled = false;
    m_AckSendTimer.cancel();
    bool is_empty = m_SentPackets.empty();
    auto ts = kovri::core::GetMillisecondsSinceEpoch();
    for (auto it : packets) {
      it->send_time = ts;
      m_SentPackets.insert(it);
    }
    SendPackets(packets);
    if (m_Status == eStreamStatusClosing && m_SendBuffer.eof())
      SendClose();
    if (is_empty)
      ScheduleResend();
  }
}

void Stream::SendQuickAck() {
  int32_t last_received_seqn = m_LastReceivedSequenceNumber;
  if (!m_SavedPackets.empty()) {
    int32_t seqn = (*m_SavedPackets.rbegin())->GetSeqn();
    if (seqn > last_received_seqn)
      last_received_seqn = seqn;
  }
  if (last_received_seqn < 0) {
    LOG(error) << "Stream: no packets have been received yet";
    return;
  }
  Packet p;
  std::uint8_t* packet = p.GetBuffer();
  std::size_t size = 0;
  core::OutputByteStream::Write<std::uint32_t>(packet + size, m_SendStreamID);
  size += 4;  // sendStreamID
  core::OutputByteStream::Write<std::uint32_t>(packet + size, m_RecvStreamID);
  size += 4;  // receiveStreamID
  // this is plain Ack message
  core::OutputByteStream::Write<std::uint32_t>(packet + size, 0, false);
  size += 4;  // sequenceNum
  core::OutputByteStream::Write<std::uint32_t>(packet + size, last_received_seqn);
  size += 4;  // ack Through
  std::uint8_t num_nacks = 0;
  if (last_received_seqn > m_LastReceivedSequenceNumber) {
    // fill NACKs
    std::uint8_t* nacks = packet + size + 1;
    auto next_seqn = m_LastReceivedSequenceNumber + 1;
    for (auto it : m_SavedPackets) {
      auto seqn = it->GetSeqn();
      if (num_nacks + (seqn - next_seqn) >= 256) {
        LOG(error)
          << "Stream: number of NACKs exceeds 256. seqn="
          << seqn << " next_seqn=" << next_seqn;
        core::OutputByteStream::Write<std::uint32_t>(packet + 12, next_seqn);  // change ack Through
        break;
      }
      for (std::uint32_t i = next_seqn; i < seqn; i++) {
        core::OutputByteStream::Write<std::uint32_t>(nacks, i);
        nacks += 4;
        num_nacks++;
      }
      next_seqn = seqn + 1;
    }
    packet[size] = num_nacks;
    size++;  // NACK count
    size += num_nacks*4;  // NACKs
  } else {
    // No NACKs
    packet[size] = 0;
    size++;  // NACK count
  }
  size++;  // resend delay
  // no flags set
  core::OutputByteStream::Write<std::uint16_t>(packet + size, 0, false);
  size += 2;  // flags
  // no options
  core::OutputByteStream::Write<std::uint16_t>(packet + size, 0, false);
  size += 2;  // options size
  p.len = size;
  SendPackets(std::vector<Packet *> { &p });
  LOG(debug) << "Stream: quick Ack sent. " << static_cast<int>(num_nacks) << " NACKs";
}

void Stream::Close() {
  switch (m_Status) {
    case eStreamStatusOpen:
      m_Status = eStreamStatusClosing;
      Close();  // recursion
      if (m_Status == eStreamStatusClosing)  // still closing
        LOG(debug) << "Stream: trying to send stream data before closing";
    break;
    case eStreamStatusReset:
      SendClose();
      Terminate();
      m_LocalDestination.DeleteStream(shared_from_this());
    break;
    case eStreamStatusClosing:
      if (m_SentPackets.empty() && m_SendBuffer.eof()) {  // nothing to send
        m_Status = eStreamStatusClosed;
        SendClose();
        Terminate();
        m_LocalDestination.DeleteStream(shared_from_this());
      }
    break;
    case eStreamStatusClosed:
      // already closed
      Terminate();
      m_LocalDestination.DeleteStream(shared_from_this());
    break;
    default:
      LOG(warning)
        << "Stream: unexpected stream status " << static_cast<int>(m_Status);
  }
}

// TODO(anonimal): bytestream refactor
void Stream::SendClose() {
  Packet* p = new Packet();
  std::uint8_t* packet = p->GetBuffer();
  std::size_t size = 0;
  core::OutputByteStream::Write<std::uint32_t>(
      packet + size,
      m_SendStreamID);
  size += 4;  // sendStreamID
  core::OutputByteStream::Write<std::uint32_t>(
      packet + size,
      m_RecvStreamID);
  size += 4;  // receiveStreamID
  core::OutputByteStream::Write<std::uint32_t>(
      packet + size,
      m_SequenceNumber++);
  size += 4;  // sequenceNum
  core::OutputByteStream::Write<std::uint32_t>(
      packet + size,
      m_LastReceivedSequenceNumber);
  size += 4;  // ack Through
  packet[size] = 0;
  size++;  // NACK count
  size++;  // resend delay
  core::OutputByteStream::Write<std::uint16_t>(
      packet + size,
      PACKET_FLAG_CLOSE | PACKET_FLAG_SIGNATURE_INCLUDED);
  size += 2;  // flags
  std::size_t signature_len =
    m_LocalDestination.GetOwner().GetIdentity().GetSignatureLen();
  // signature only
  core::OutputByteStream::Write<std::uint16_t>(packet + size, signature_len);
  size += 2;  // options size
  std::uint8_t* signature = packet + size;
  memset(packet + size, 0, signature_len);
  size += signature_len;  // signature
  m_LocalDestination.GetOwner().Sign(packet, size, signature);
  p->len = size;
  m_Service.post(std::bind(&Stream::SendPacket, shared_from_this(), p));
  LOG(debug) << "Stream: FIN sent";
}

std::size_t Stream::ConcatenatePackets(
    std::uint8_t* buf,
    std::size_t len) {
  std::size_t pos = 0;
  while (pos < len && !m_ReceiveQueue.empty()) {
    Packet* packet = m_ReceiveQueue.front();
    std::size_t l = std::min(packet->GetLength(), len - pos);
    memcpy(buf + pos, packet->GetBuffer(), l);
    pos += l;
    packet->offset += l;
    if (!packet->GetLength()) {
      m_ReceiveQueue.pop();
      delete packet;
    }
  }
  return pos;
}

bool Stream::SendPacket(
    Packet* packet) {
  if (packet) {
    if (m_IsAckSendScheduled) {
      m_IsAckSendScheduled = false;
      m_AckSendTimer.cancel();
    }
    SendPackets(std::vector<Packet *> { packet });
    if (m_Status == eStreamStatusOpen) {
      bool is_empty = m_SentPackets.empty();
      m_SentPackets.insert(packet);
      if (is_empty)
        ScheduleResend();
    } else {
      delete packet;
    }
    return true;
  } else {
    return false;
  }
}

void Stream::SendPackets(
    const std::vector<Packet *>& packets) {
  if (!m_RemoteLeaseSet) {
    UpdateCurrentRemoteLease();
    if (!m_RemoteLeaseSet) {
      LOG(error)
        << "Stream: can't send packets, missing remote LeaseSet";
      return;
    }
  }
  if (!m_CurrentOutboundTunnel || !m_CurrentOutboundTunnel->IsEstablished())
    m_CurrentOutboundTunnel =
      m_LocalDestination.GetOwner().GetTunnelPool()->GetNewOutboundTunnel(
          m_CurrentOutboundTunnel);
  if (!m_CurrentOutboundTunnel) {
    LOG(error) << "Stream: no outbound tunnels in the pool";
    return;
  }
  auto ts = kovri::core::GetMillisecondsSinceEpoch();
  if (!m_CurrentRemoteLease.end_date ||
      ts >= m_CurrentRemoteLease.end_date -
      kovri::core::TUNNEL_EXPIRATION_THRESHOLD * 1000)
    UpdateCurrentRemoteLease(true);
  if (ts < m_CurrentRemoteLease.end_date) {
    std::vector<kovri::core::TunnelMessageBlock> msgs;
    for (auto it : packets) {
      auto msg = m_RoutingSession->WrapSingleMessage(
          CreateDataMessage(
            it->GetBuffer(),
            it->GetLength()));
      msgs.push_back(
          kovri::core::TunnelMessageBlock {
            kovri::core::e_DeliveryTypeTunnel,
            m_CurrentRemoteLease.tunnel_gateway,
            m_CurrentRemoteLease.tunnel_ID,
            msg
          });
      m_NumSentBytes += it->GetLength();
    }
    m_CurrentOutboundTunnel->SendTunnelDataMsg(msgs);
  } else {
    LOG(warning) << "Stream: all leases are expired";
  }
}

void Stream::ScheduleResend() {
  m_ResendTimer.cancel();
  m_ResendTimer.expires_from_now(
      boost::posix_time::milliseconds(
        m_RTO));
  m_ResendTimer.async_wait(
      std::bind(
        &Stream::HandleResendTimer,
        shared_from_this(),
        std::placeholders::_1));
}

void Stream::HandleResendTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    // check for resend attempts
    if (m_NumResendAttempts >= MAX_NUM_RESEND_ATTEMPTS) {
      LOG(warning)
        << "Stream: packet was not ACKed after "
        << MAX_NUM_RESEND_ATTEMPTS << " attempts, terminating";
      m_Status = eStreamStatusReset;
      Close();
      return;
    }
    // collect packets to resend
    auto ts = kovri::core::GetMillisecondsSinceEpoch();
    std::vector<Packet *> packets;
    for (auto it : m_SentPackets) {
      if (ts >= it->send_time + m_RTO) {
        it->send_time = ts;
        packets.push_back(it);
      }
    }
    // select tunnels if necessary and send
    if (packets.size() > 0) {
      m_NumResendAttempts++;
      m_RTO *= 2;
      switch (m_NumResendAttempts) {
        case 1:  // congestion avoidance
          m_WindowSize /= 2;
          if (m_WindowSize < MIN_WINDOW_SIZE)
            m_WindowSize = MIN_WINDOW_SIZE;
        break;
        case 2:
          // drop RTO to initial upon tunnels pair change first time
          m_RTO = INITIAL_RTO;
          // fall-through
        case 4:
          UpdateCurrentRemoteLease();  // pick another lease
          LOG(warning)
            << "Stream: another remote lease has been selected for stream";
        break;
        case 3:
          // pick another outbound tunnel
          m_CurrentOutboundTunnel =
            m_LocalDestination.GetOwner().GetTunnelPool()->GetNextOutboundTunnel(
                m_CurrentOutboundTunnel);
          LOG(warning)
            << "Stream: another outbound tunnel has been selected for stream";
        break;
        default: {}
      }
      SendPackets(packets);
    }
    ScheduleResend();
  }
}

void Stream::HandleAckSendTimer(
    const boost::system::error_code&) {
  if (m_IsAckSendScheduled) {
    if (m_LastReceivedSequenceNumber < 0) {
      LOG(warning)
        << "Stream: SYN has not been received after "
        << ACK_SEND_TIMEOUT << " milliseconds after follow on, terminating";
      m_Status = eStreamStatusReset;
      Close();
      return;
    }
    if (m_Status == eStreamStatusOpen)
      SendQuickAck();
    m_IsAckSendScheduled = false;
  }
}

void Stream::UpdateCurrentRemoteLease(
    bool expired) {
  if (!m_RemoteLeaseSet) {
    m_RemoteLeaseSet =
      m_LocalDestination.GetOwner().FindLeaseSet(
        m_RemoteIdentity.GetIdentHash());
    if (!m_RemoteLeaseSet)
      LOG(debug)
        << "Stream: LeaseSet "
        << m_RemoteIdentity.GetIdentHash().ToBase64() << " not found";
  }
  if (m_RemoteLeaseSet) {
    if (!m_RoutingSession)
      m_RoutingSession =
        m_LocalDestination.GetOwner().GetRoutingSession(
          m_RemoteLeaseSet, 32);
    // try without threshold first
    auto leases = m_RemoteLeaseSet->GetNonExpiredLeases(false);
    if (leases.empty()) {
      expired = false;
      m_LocalDestination.GetOwner().RequestDestination(
          m_RemoteIdentity.GetIdentHash());  // time to re-request
      // then with threshold
      leases = m_RemoteLeaseSet->GetNonExpiredLeases(true);
    }
    if (!leases.empty()) {
      bool updated = false;
      if (expired) {
        for (auto it : leases)
          if ((it.tunnel_gateway == m_CurrentRemoteLease.tunnel_gateway) &&
              (it.tunnel_ID != m_CurrentRemoteLease.tunnel_ID)) {
            m_CurrentRemoteLease = it;
            updated = true;
            break;
          }
      }
      if (!updated) {
        std::uint32_t i =
          kovri::core::RandInRange32(
              0, leases.size() - 1);
        if (m_CurrentRemoteLease.end_date &&
            leases[i].tunnel_ID == m_CurrentRemoteLease.tunnel_ID)
          // make sure we don't select previous
          i = (i + 1) % leases.size();  // if so, pick next
        m_CurrentRemoteLease = leases[i];
      }
    } else {
      m_RemoteLeaseSet = nullptr;
      m_CurrentRemoteLease.end_date = 0;
      // re-request expired
    }
  } else {
    m_CurrentRemoteLease.end_date = 0;
  }
}

std::shared_ptr<kovri::core::I2NPMessage> Stream::CreateDataMessage(
    const std::uint8_t* payload,
    std::size_t len) {
  auto msg = kovri::core::ToSharedI2NPMessage(kovri::core::NewI2NPShortMessage());
  try {
    kovri::core::Gzip compressor;
    if (len <= kovri::client::COMPRESSION_THRESHOLD_SIZE)
      compressor.SetDeflateLevel(
          compressor.GetMinDeflateLevel());
    else
      compressor.SetDeflateLevel(
          compressor.GetDefaultDeflateLevel());
    compressor.Put(
        payload,
        len);
    int size = compressor.MaxRetrievable();
    std::uint8_t* buf = msg->GetPayload();
    // length
    core::OutputByteStream::Write<std::uint32_t>(buf, size);
    buf += 4;
    compressor.Get(buf, size);
    // source port
    core::OutputByteStream::Write<std::uint16_t>(
        buf + 4, m_LocalDestination.GetLocalPort());
    // destination port
    core::OutputByteStream::Write<std::uint16_t>(buf + 6, m_Port);
    // streaming protocol
    buf[9] = kovri::client::PROTOCOL_TYPE_STREAMING;
    msg->len += size + 4;
    msg->FillI2NPMessageHeader(kovri::core::I2NPData);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
  }
  return msg;
}

void StreamingDestination::Start() {}

void StreamingDestination::Stop() {
  ResetAcceptor(); {
    std::unique_lock<std::mutex> l(m_StreamsMutex);
    m_Streams.clear();
  }
}

void StreamingDestination::HandleNextPacket(
    Packet* packet) {
  std::uint32_t send_stream_ID = packet->GetSendStreamID();
  if (send_stream_ID) {
    auto it = m_Streams.find(
        send_stream_ID);
    if (it != m_Streams.end()) {
      it->second->HandleNextPacket(
          packet);
    } else {
      LOG(warning)
        << "StreamingDestination: unknown stream " << send_stream_ID;
      delete packet;
    }
  } else {
    if (packet->IsSYN() && !packet->GetSeqn()) {  // new incoming stream
      auto incoming_stream = CreateNewIncomingStream();
      incoming_stream->HandleNextPacket(packet);
      if (m_Acceptor != nullptr) {
        m_Acceptor(incoming_stream);
      } else {
        LOG(warning)
          << "StreamingDestination: acceptor for incoming stream is not set";
        DeleteStream(incoming_stream);
      }
    } else {  // follow on packet without SYN
      std::uint32_t receive_stream_ID = packet->GetReceiveStreamID();
      for (auto it : m_Streams)
        if (it.second->GetSendStreamID() == receive_stream_ID) {
          // found
          it.second->HandleNextPacket(packet);
          return;
        }
      // TODO(unassigned): should queue it up
      LOG(warning)
        << "StreamingDestination: Unknown stream " << receive_stream_ID;
      delete packet;
    }
  }
}

std::shared_ptr<Stream> StreamingDestination::CreateNewOutgoingStream(
    std::shared_ptr<const kovri::core::LeaseSet> remote,
    std::uint16_t port) {
  auto s = std::make_shared<Stream>(m_Owner.GetService(), *this, remote, port);
  std::unique_lock<std::mutex> l(m_StreamsMutex);
  m_Streams[s->GetReceiveStreamID()] = s;
  return s;
}

std::shared_ptr<Stream> StreamingDestination::CreateNewIncomingStream() {
  auto s = std::make_shared<Stream>(m_Owner.GetService(), *this);
  std::unique_lock<std::mutex> l(m_StreamsMutex);
  m_Streams[s->GetReceiveStreamID()] = s;
  return s;
}

void StreamingDestination::DeleteStream(
    std::shared_ptr<Stream> stream) {
  if (stream) {
    std::unique_lock<std::mutex> l(m_StreamsMutex);
    auto it = m_Streams.find(stream->GetReceiveStreamID());
    if (it != m_Streams.end())
      m_Streams.erase(it);
  }
}

void StreamingDestination::HandleDataMessagePayload(
    const std::uint8_t* buf,
    std::size_t len) {
  Packet* uncompressed = new Packet;
  try {
    kovri::core::Gunzip decompressor;
    decompressor.Put(buf, len);
    uncompressed->offset = 0;
    uncompressed->len = decompressor.MaxRetrievable();
    if (uncompressed->len > MAX_PACKET_SIZE) {
      LOG(debug)
        << "StreamingDestination: received packet size "
        << uncompressed->len << " exceeds max packet size, skipped";
      delete uncompressed;
      return;
    }
    decompressor.Get(uncompressed->buf, uncompressed->len);
    HandleNextPacket(uncompressed);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    delete uncompressed;
  }
}

}  // namespace client
}  // namespace kovri
