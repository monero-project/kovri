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

#include <algorithm>
#include <vector>

#include "router_context.h"
#include "router_info.h"
#include "streaming.h"
#include "client/destination.h"
#include "crypto/rand.h"
#include "crypto/util/compression.h"
#include "tunnel/tunnel.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace stream {

Stream::Stream(
    boost::asio::io_service& service,
    StreamingDestination& local,
    std::shared_ptr<const i2p::data::LeaseSet> remote,
    int port)
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
      m_NumResendAttempts(0) {
        m_RecvStreamID = i2p::crypto::Rand<uint32_t>();
        m_RemoteIdentity = remote->GetIdentity();
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
      m_NumResendAttempts(0) {
        m_RecvStreamID = i2p::crypto::Rand<uint32_t>();
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
  LogPrint(eLogDebug, "Stream: stream deleted");
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
  int32_t receivedSeqn = packet->GetSeqn();
  bool isSyn = packet->IsSYN();
  if (!receivedSeqn && !isSyn) {
    // plain ack
    LogPrint(eLogDebug, "Stream: plain ACK received");
    delete packet;
    return;
  }
  LogPrint(eLogDebug, "Stream: received seqn=", receivedSeqn);
  if (isSyn || receivedSeqn == m_LastReceivedSequenceNumber + 1) {
    // we have received next in sequence message
    ProcessPacket(packet);
    // we should also try stored messages if any
    for (auto it = m_SavedPackets.begin(); it != m_SavedPackets.end();) {
      if ((*it)->GetSeqn() == (uint32_t)(m_LastReceivedSequenceNumber + 1)) {
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
    } else if (isSyn) {
      // we have to send SYN back to incoming connection
      SendBuffer();  // also sets m_IsOpen
    }
  } else {
    if (receivedSeqn <= m_LastReceivedSequenceNumber) {
      // we have received duplicate
      LogPrint(eLogWarn,
          "Stream: duplicate message ", receivedSeqn, " received");
      SendQuickAck();  // resend ack for previous message again
      delete packet;  // packet dropped
    } else {
      LogPrint(eLogWarn, "Stream: missing messages from ",
          m_LastReceivedSequenceNumber + 1, " to ", receivedSeqn - 1);
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
  uint32_t receivedSeqn = packet->GetSeqn();
  uint16_t flags = packet->GetFlags();
  LogPrint(eLogDebug,
      "Stream: process seqn=", receivedSeqn, ", flags=", flags);
  const uint8_t* optionData = packet->GetOptionData();
  if (flags & PACKET_FLAG_SYNCHRONIZE)
    LogPrint(eLogDebug, "Stream: synchronize");
  if (flags & PACKET_FLAG_DELAY_REQUESTED) {
    optionData += 2;
  }
  if (flags & PACKET_FLAG_FROM_INCLUDED) {
    optionData += m_RemoteIdentity.FromBuffer(
        optionData, packet->GetOptionSize());
    LogPrint(eLogInfo,
        "Stream: from identity ",
        m_RemoteIdentity.GetIdentHash().ToBase64());
    if (!m_RemoteLeaseSet)
      LogPrint(eLogDebug,
          "Stream: incoming stream from ",
          m_RemoteIdentity.GetIdentHash().ToBase64());
  }
  if (flags & PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED) {
    uint16_t maxPacketSize = bufbe16toh(optionData);
    LogPrint(eLogDebug, "Stream: max packet size ", maxPacketSize);
    optionData += 2;
  }
  if (flags & PACKET_FLAG_SIGNATURE_INCLUDED) {
    LogPrint(eLogDebug, "Stream: signature");
    uint8_t signature[256];
    auto signatureLen = m_RemoteIdentity.GetSignatureLen();
    memcpy(signature, optionData, signatureLen);
    memset(const_cast<uint8_t *>(optionData), 0, signatureLen);
    if (!m_RemoteIdentity.Verify(
          packet->GetBuffer(),
          packet->GetLength(),
          signature)) {
      LogPrint(eLogError, "Stream: signature verification failed");
      Close();
      flags |= PACKET_FLAG_CLOSE;
    }
    memcpy(const_cast<uint8_t *>(optionData), signature, signatureLen);
    optionData += signatureLen;
  }
  packet->offset = packet->GetPayload() - packet->buf;
  if (packet->GetLength() > 0) {
    m_ReceiveQueue.push(packet);
    m_ReceiveTimer.cancel();
  } else {
    delete packet;
  }
  m_LastReceivedSequenceNumber = receivedSeqn;
  if (flags & (PACKET_FLAG_CLOSE | PACKET_FLAG_RESET)) {
    LogPrint(eLogInfo,
        "Stream: ", (flags & PACKET_FLAG_RESET) ? "reset" : "closed");
    m_Status = eStreamStatusReset;
    Close();
  }
}

void Stream::ProcessAck(
    Packet * packet) {
  bool acknowledged = false;
  auto ts = i2p::util::GetMillisecondsSinceEpoch();
  uint32_t ackThrough = packet->GetAckThrough();
  int nackCount = packet->GetNACKCount();
  for (auto it = m_SentPackets.begin(); it != m_SentPackets.end();) {
    auto seqn = (*it)->GetSeqn();
    if (seqn <= ackThrough) {
      if (nackCount > 0) {
        bool nacked = false;
        for (int i = 0; i < nackCount; i++)
          if (seqn == packet->GetNACK(i)) {
            nacked = true;
            break;
          }
        if (nacked) {
          LogPrint(eLogDebug, "Stream: packet ", seqn, " NACK");
          it++;
          continue;
        }
      }
      auto sentPacket = *it;
      uint64_t rtt = ts - sentPacket->sendTime;
      m_RTT = (m_RTT * seqn + rtt) / (seqn + 1);
      m_RTO = m_RTT * 1.5;  // TODO(unassigned): implement this better
      LogPrint(eLogDebug, "Stream: packet ", seqn, " acknowledged rtt=", rtt);
      m_SentPackets.erase(it++);
      delete sentPacket;
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

size_t Stream::Send(
    const uint8_t* buf,
    size_t len) {
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
    const uint8_t* buf,
    size_t len,
    SendHandler handler) {
  if (m_SendHandler)
    handler(
        boost::asio::error::make_error_code(
          boost::asio::error::in_progress));
  else
    m_SendHandler = handler;
  Send(buf, len);
}

void Stream::SendBuffer() {
  int numMsgs = m_WindowSize - m_SentPackets.size();
  if (numMsgs <= 0)
    return;  // window is full
  bool isNoAck = m_LastReceivedSequenceNumber < 0;  // first packet
  std::vector<Packet *> packets; {
    std::unique_lock<std::mutex> l(m_SendBufferMutex);
    while ((m_Status == eStreamStatusNew) || (IsEstablished() &&
          !m_SendBuffer.eof() && numMsgs > 0)) {
      Packet* p = new Packet();
      uint8_t* packet = p->GetBuffer();
      // TODO(unassigned): implement setters
      size_t size = 0;
      htobe32buf(packet + size, m_SendStreamID);
      size += 4;  // sendStreamID
      htobe32buf(packet + size, m_RecvStreamID);
      size += 4;  // receiveStreamID
      htobe32buf(packet + size, m_SequenceNumber++);
      size += 4;  // sequenceNum
      if (isNoAck)
        htobe32buf(packet + size, m_LastReceivedSequenceNumber);
      else
        htobuf32(packet + size, 0);
      size += 4;  // ack Through
      packet[size] = 0;
      size++;  // NACK count
      packet[size] = m_RTO/1000;
      size++;  // resend delay
      if (m_Status == eStreamStatusNew) {
        // initial packet
        m_Status = eStreamStatusOpen;
        uint16_t flags =
          PACKET_FLAG_SYNCHRONIZE        | PACKET_FLAG_FROM_INCLUDED |
          PACKET_FLAG_SIGNATURE_INCLUDED | PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED;
        if (isNoAck)
          flags |= PACKET_FLAG_NO_ACK;
        htobe16buf(packet + size, flags);
        size += 2;  // flags
        size_t identityLen =
          m_LocalDestination.GetOwner().GetIdentity().GetFullLen();
        size_t signatureLen =
          m_LocalDestination.GetOwner().GetIdentity().GetSignatureLen();
        // identity + signature + packet size
        htobe16buf(packet + size, identityLen + signatureLen + 2);
        size += 2;  // options size
        m_LocalDestination.GetOwner().GetIdentity().ToBuffer(
            packet + size, identityLen);
        size += identityLen;  // from
        htobe16buf(packet + size, STREAMING_MTU);
        size += 2;  // max packet size
        uint8_t* signature = packet + size;  // set it later
        // zeroes for now
        memset(signature, 0, signatureLen);
        size += signatureLen;  // signature
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
        htobuf16(packet + size, 0);
        size += 2;  // flags
        // no options
        htobuf16(packet + size, 0);
        size += 2;  // options size
        m_SendBuffer.read(
            reinterpret_cast<char *>(packet + size),
            STREAMING_MTU - size);
        size += m_SendBuffer.gcount();  // payload
      }
      p->len = size;
      packets.push_back(p);
      numMsgs--;
    }
    if (m_SendBuffer.eof() && m_SendHandler) {
      m_SendHandler(boost::system::error_code());
      m_SendHandler = nullptr;
    }
  }
  if (packets.size() > 0) {
    m_IsAckSendScheduled = false;
    m_AckSendTimer.cancel();
    bool isEmpty = m_SentPackets.empty();
    auto ts = i2p::util::GetMillisecondsSinceEpoch();
    for (auto it : packets) {
      it->sendTime = ts;
      m_SentPackets.insert(it);
    }
    SendPackets(packets);
    if (m_Status == eStreamStatusClosing && m_SendBuffer.eof())
      SendClose();
    if (isEmpty)
      ScheduleResend();
  }
}

void Stream::SendQuickAck() {
  int32_t lastReceivedSeqn = m_LastReceivedSequenceNumber;
  if (!m_SavedPackets.empty()) {
    int32_t seqn = (*m_SavedPackets.rbegin())->GetSeqn();
    if (seqn > lastReceivedSeqn)
      lastReceivedSeqn = seqn;
  }
  if (lastReceivedSeqn < 0) {
    LogPrint(eLogError, "Stream: no packets have been received yet");
    return;
  }
  Packet p;
  uint8_t* packet = p.GetBuffer();
  size_t size = 0;
  htobe32buf(packet + size, m_SendStreamID);
  size += 4;  // sendStreamID
  htobe32buf(packet + size, m_RecvStreamID);
  size += 4;  // receiveStreamID
  // this is plain Ack message
  htobuf32(packet + size, 0);
  size += 4;  // sequenceNum
  htobe32buf(packet + size, lastReceivedSeqn);
  size += 4;  // ack Through
  uint8_t numNacks = 0;
  if (lastReceivedSeqn > m_LastReceivedSequenceNumber) {
    // fill NACKs
    uint8_t* nacks = packet + size + 1;
    auto nextSeqn = m_LastReceivedSequenceNumber + 1;
    for (auto it : m_SavedPackets) {
      auto seqn = it->GetSeqn();
      if (numNacks + (seqn - nextSeqn) >= 256) {
        LogPrint(eLogError,
            "Stream: number of NACKs exceeds 256. seqn=",
            seqn, " nextSeqn=", nextSeqn);
        htobe32buf(packet + 12, nextSeqn);  // change ack Through
        break;
      }
      for (uint32_t i = nextSeqn; i < seqn; i++) {
        htobe32buf(nacks, i);
        nacks += 4;
        numNacks++;
      }
      nextSeqn = seqn + 1;
    }
    packet[size] = numNacks;
    size++;  // NACK count
    size += numNacks*4;  // NACKs
  } else {
    // No NACKs
    packet[size] = 0;
    size++;  // NACK count
  }
  size++;  // resend delay
  // no flags set
  htobuf16(packet + size, 0);
  size += 2;  // flags
  // no options
  htobuf16(packet + size, 0);
  size += 2;  // options size
  p.len = size;
  SendPackets(std::vector<Packet *> { &p });
  LogPrint(eLogInfo, "Stream: quick Ack sent. ", static_cast<int>(numNacks), " NACKs");
}

void Stream::Close() {
  switch (m_Status) {
    case eStreamStatusOpen:
      m_Status = eStreamStatusClosing;
      Close();  // recursion
      if (m_Status == eStreamStatusClosing)  // still closing
        LogPrint(eLogInfo, "Stream: trying to send stream data before closing");
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
      LogPrint(eLogWarn,
          "Stream: unexpected stream status ",
          static_cast<int>(m_Status));
  }
}

void Stream::SendClose() {
  Packet* p = new Packet();
  uint8_t* packet = p->GetBuffer();
  size_t size = 0;
  htobe32buf(
      packet + size,
      m_SendStreamID);
  size += 4;  // sendStreamID
  htobe32buf(
      packet + size,
      m_RecvStreamID);
  size += 4;  // receiveStreamID
  htobe32buf(
      packet + size,
      m_SequenceNumber++);
  size += 4;  // sequenceNum
  htobe32buf(
      packet + size,
      m_LastReceivedSequenceNumber);
  size += 4;  // ack Through
  packet[size] = 0;
  size++;  // NACK count
  size++;  // resend delay
  htobe16buf(
      packet + size,
      PACKET_FLAG_CLOSE | PACKET_FLAG_SIGNATURE_INCLUDED);
  size += 2;  // flags
  size_t signatureLen =
    m_LocalDestination.GetOwner().GetIdentity().GetSignatureLen();
  // signature only
  htobe16buf(packet + size, signatureLen);
  size += 2;  // options size
  uint8_t* signature = packet + size;
  memset(packet + size, 0, signatureLen);
  size += signatureLen;  // signature
  m_LocalDestination.GetOwner().Sign(packet, size, signature);
  p->len = size;
  m_Service.post(std::bind(&Stream::SendPacket, shared_from_this(), p));
  LogPrint(eLogInfo, "Stream: FIN sent");
}

size_t Stream::ConcatenatePackets(
    uint8_t* buf,
    size_t len) {
  size_t pos = 0;
  while (pos < len && !m_ReceiveQueue.empty()) {
    Packet* packet = m_ReceiveQueue.front();
    size_t l = std::min(packet->GetLength(), len - pos);
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
      bool isEmpty = m_SentPackets.empty();
      m_SentPackets.insert(packet);
      if (isEmpty)
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
      LogPrint(eLogError,
          "Stream: can't send packets, missing remote LeaseSet");
      return;
    }
  }
  if (!m_CurrentOutboundTunnel || !m_CurrentOutboundTunnel->IsEstablished())
    m_CurrentOutboundTunnel =
      m_LocalDestination.GetOwner().GetTunnelPool()->GetNewOutboundTunnel(
          m_CurrentOutboundTunnel);
  if (!m_CurrentOutboundTunnel) {
    LogPrint(eLogError, "Stream: no outbound tunnels in the pool");
    return;
  }
  auto ts = i2p::util::GetMillisecondsSinceEpoch();
  if (!m_CurrentRemoteLease.end_date ||
      ts >= m_CurrentRemoteLease.end_date -
      i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD * 1000)
    UpdateCurrentRemoteLease(true);
  if (ts < m_CurrentRemoteLease.end_date) {
    std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
    for (auto it : packets) {
      auto msg = m_RoutingSession->WrapSingleMessage(
          CreateDataMessage(
            it->GetBuffer(),
            it->GetLength()));
      msgs.push_back(
          i2p::tunnel::TunnelMessageBlock  {
          i2p::tunnel::e_DeliveryTypeTunnel,
          m_CurrentRemoteLease.tunnel_gateway,
          m_CurrentRemoteLease.tunnel_ID,
          msg});
      m_NumSentBytes += it->GetLength();
    }
    m_CurrentOutboundTunnel->SendTunnelDataMsg(msgs);
  } else {
    LogPrint(eLogWarn, "Stream: all leases are expired");
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
      LogPrint(eLogWarn,
          "Stream: packet was not ACKed after ",
          MAX_NUM_RESEND_ATTEMPTS,  " attempts. Terminate");
      m_Status = eStreamStatusReset;
      Close();
      return;
    }
    // collect packets to resend
    auto ts = i2p::util::GetMillisecondsSinceEpoch();
    std::vector<Packet *> packets;
    for (auto it : m_SentPackets) {
      if (ts >= it->sendTime + m_RTO) {
        it->sendTime = ts;
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
          // no break here
        case 4:
          UpdateCurrentRemoteLease();  // pick another lease
          LogPrint(eLogWarn,
              "Stream: another remote lease has been selected for stream");
        break;
        case 3:
          // pick another outbound tunnel
          m_CurrentOutboundTunnel =
            m_LocalDestination.GetOwner().GetTunnelPool()->GetNextOutboundTunnel(
                m_CurrentOutboundTunnel);
          LogPrint(eLogWarn,
              "Stream: another outbound tunnel has been selected for stream");
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
      LogPrint(eLogWarn,
          "Stream: SYN has not been received after ",
          ACK_SEND_TIMEOUT, " milliseconds after follow on, terminating");
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
      LogPrint(eLogInfo,
          "Stream: LeaseSet ",
          m_RemoteIdentity.GetIdentHash().ToBase64(), " not found");
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
        uint32_t i =
          i2p::crypto::RandInRange<uint32_t>(
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

std::shared_ptr<I2NPMessage> Stream::CreateDataMessage(
    const uint8_t* payload,
    size_t len) {
  auto msg = ToSharedI2NPMessage(NewI2NPShortMessage());
  i2p::crypto::util::Gzip compressor;
  if (len <= i2p::stream::COMPRESSION_THRESHOLD_SIZE)
    compressor.SetDeflateLevel(
        compressor.GetMinDeflateLevel());
  else
    compressor.SetDeflateLevel(
        compressor.GetDefaultDeflateLevel());
  compressor.Put(
      payload,
      len);
  int size = compressor.MaxRetrievable();
  uint8_t* buf = msg->GetPayload();
  // length
  htobe32buf(buf, size);
  buf += 4;
  compressor.Get(buf, size);
  // source port
  htobe16buf(buf + 4, m_LocalDestination.GetLocalPort());
  // destination port
  htobe16buf(buf + 6, m_Port);
  // streaming protocol
  buf[9] = i2p::client::PROTOCOL_TYPE_STREAMING;
  msg->len += size + 4;
  msg->FillI2NPMessageHeader(e_I2NPData);
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
  uint32_t sendStreamID = packet->GetSendStreamID();
  if (sendStreamID) {
    auto it = m_Streams.find(
        sendStreamID);
    if (it != m_Streams.end()) {
      it->second->HandleNextPacket(
          packet);
    } else {
      LogPrint(eLogWarn,
          "StreamingDestination: unknown stream ", sendStreamID);
      delete packet;
    }
  } else {
    if (packet->IsSYN() && !packet->GetSeqn()) {  // new incoming stream
      auto incomingStream = CreateNewIncomingStream();
      incomingStream->HandleNextPacket(packet);
      if (m_Acceptor != nullptr) {
        m_Acceptor(incomingStream);
      } else {
        LogPrint(eLogWarn,
            "StreamingDestination: acceptor for incoming stream is not set");
        DeleteStream(incomingStream);
      }
    } else {  // follow on packet without SYN
      uint32_t receiveStreamID = packet->GetReceiveStreamID();
      for (auto it : m_Streams)
        if (it.second->GetSendStreamID() == receiveStreamID) {
          // found
          it.second->HandleNextPacket(packet);
          return;
        }
      // TODO(unassigned): should queue it up
      LogPrint(eLogWarn,
          "StreamingDestination: Unknown stream ", receiveStreamID);
      delete packet;
    }
  }
}

std::shared_ptr<Stream> StreamingDestination::CreateNewOutgoingStream(
    std::shared_ptr<const i2p::data::LeaseSet> remote,
    int port) {
  auto s = std::make_shared<Stream>(m_Owner.GetService(), *this, remote, port);
  std::unique_lock<std::mutex> l(m_StreamsMutex);
  m_Streams[s->GetRecvStreamID()] = s;
  return s;
}

std::shared_ptr<Stream> StreamingDestination::CreateNewIncomingStream() {
  auto s = std::make_shared<Stream>(m_Owner.GetService(), *this);
  std::unique_lock<std::mutex> l(m_StreamsMutex);
  m_Streams[s->GetRecvStreamID()] = s;
  return s;
}

void StreamingDestination::DeleteStream(
    std::shared_ptr<Stream> stream) {
  if (stream) {
    std::unique_lock<std::mutex> l(m_StreamsMutex);
    auto it = m_Streams.find(stream->GetRecvStreamID());
    if (it != m_Streams.end())
      m_Streams.erase(it);
  }
}

void StreamingDestination::HandleDataMessagePayload(
    const uint8_t* buf,
    size_t len) {
  // Gunzip it
  i2p::crypto::util::Gunzip decompressor;
  decompressor.Put(buf, len);
  Packet* uncompressed = new Packet;
  uncompressed->offset = 0;
  uncompressed->len = decompressor.MaxRetrievable();
  if (uncompressed->len <= MAX_PACKET_SIZE) {
    decompressor.Get(uncompressed->buf, uncompressed->len);
    HandleNextPacket(uncompressed);
  } else {
    LogPrint(eLogInfo,
        "StreamingDestination: received packet size ",
        uncompressed->len, " exceeds max packet size. Skipped");
    delete uncompressed;
  }
}

}  // namespace stream
}  // namespace i2p
