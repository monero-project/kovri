/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
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
 */

#ifndef SRC_API_STREAMING_H_
#define SRC_API_STREAMING_H_

#include <inttypes.h>

#include <boost/asio.hpp>

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "Garlic.h"
#include "I2NPProtocol.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "tunnel/Tunnel.h"
#include "util/I2PEndian.h"

namespace i2p {
namespace client { class ClientDestination; }
namespace stream {

const uint16_t PACKET_FLAG_SYNCHRONIZE = 0x0001;
const uint16_t PACKET_FLAG_CLOSE = 0x0002;
const uint16_t PACKET_FLAG_RESET = 0x0004;
const uint16_t PACKET_FLAG_SIGNATURE_INCLUDED = 0x0008;
const uint16_t PACKET_FLAG_SIGNATURE_REQUESTED = 0x0010;
const uint16_t PACKET_FLAG_FROM_INCLUDED = 0x0020;
const uint16_t PACKET_FLAG_DELAY_REQUESTED = 0x0040;
const uint16_t PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED = 0x0080;
const uint16_t PACKET_FLAG_PROFILE_INTERACTIVE = 0x0100;
const uint16_t PACKET_FLAG_ECHO = 0x0200;
const uint16_t PACKET_FLAG_NO_ACK = 0x0400;

const size_t STREAMING_MTU = 1730;
const size_t MAX_PACKET_SIZE = 4096;
const size_t COMPRESSION_THRESHOLD_SIZE = 66;
const int ACK_SEND_TIMEOUT = 200;  // in milliseconds
const int MAX_NUM_RESEND_ATTEMPTS = 6;
const int WINDOW_SIZE = 6;  // in messages
const int MIN_WINDOW_SIZE = 1;
const int MAX_WINDOW_SIZE = 128;
const int INITIAL_RTT = 8000;  // in milliseconds
const int INITIAL_RTO = 9000;  // in milliseconds

struct Packet {
  size_t len, offset;
  uint8_t buf[MAX_PACKET_SIZE];
  uint64_t sendTime;

  Packet()
      : len(0),
        offset(0),
        sendTime(0) {}

  uint8_t* GetBuffer() {
    return buf + offset;
  }

  size_t GetLength() const {
    return len - offset;
  }

  uint32_t GetSendStreamID() const {
    return bufbe32toh(buf);
  }

  uint32_t GetReceiveStreamID() const {
    return bufbe32toh(buf + 4);
  }

  uint32_t GetSeqn() const {
    return bufbe32toh(buf + 8);
  }

  uint32_t GetAckThrough() const {
    return bufbe32toh(buf + 12);
  }

  uint8_t GetNACKCount() const {
    return buf[16];
  }

  uint32_t GetNACK(int i) const {
    return bufbe32toh(buf + 17 + 4 * i);
  }

  const uint8_t* GetOption() const {
    return buf + 17 + GetNACKCount() * 4 + 3;
  }  // 3 = resendDelay + flags

  uint16_t GetFlags() const {
    return bufbe16toh(GetOption() - 2);
  }
  uint16_t GetOptionSize() const {
    return bufbe16toh(GetOption ());
  }
  const uint8_t* GetOptionData() const {
    return GetOption() + 2;
  }
  const uint8_t* GetPayload() const {
    return GetOptionData() + GetOptionSize();
  }
  bool IsSYN() const {
    return GetFlags() & PACKET_FLAG_SYNCHRONIZE;
  }
  bool IsNoAck() const {
    return GetFlags() & PACKET_FLAG_NO_ACK;
  }
};

struct PacketCmp {
  bool operator() (const Packet * p1, const Packet * p2) const {
    return p1->GetSeqn() < p2->GetSeqn();
  }
};

enum StreamStatus {
  eStreamStatusNew = 0,
  eStreamStatusOpen,
  eStreamStatusReset,
  eStreamStatusClosing,
  eStreamStatusClosed
};

class StreamingDestination;
class Stream : public std::enable_shared_from_this<Stream> {
 public:
  typedef std::function<void (const boost::system::error_code& ecode)> SendHandler;

  // Outgoing
  Stream(
      boost::asio::io_service& service,
      StreamingDestination& local,
      std::shared_ptr<const i2p::data::LeaseSet> remote,
      int port = 0);
  // Incoming
  Stream(
      boost::asio::io_service& service,
      StreamingDestination& local);
  ~Stream();

  uint32_t GetSendStreamID() const {
    return m_SendStreamID;
  }

  uint32_t GetRecvStreamID() const {
    return m_RecvStreamID;
  }

  std::shared_ptr<const i2p::data::LeaseSet> GetRemoteLeaseSet() const {
    return m_RemoteLeaseSet;
  }

  const i2p::data::IdentityEx& GetRemoteIdentity() const {
    return m_RemoteIdentity;
  }

  bool IsOpen() const {
    return m_Status == eStreamStatusOpen;
  }

  bool IsEstablished() const {
    return m_SendStreamID;
  }

  StreamStatus GetStatus() const {
    return m_Status;
  }

  StreamingDestination& GetLocalDestination() {
    return m_LocalDestination;
  }

  void HandleNextPacket(
      Packet* packet);

  size_t Send(
      const uint8_t* buf,
      size_t len);

  void AsyncSend(
      const uint8_t* buf,
      size_t len,
      SendHandler handler);

  template<typename Buffer, typename ReceiveHandler>
  void AsyncReceive(
      const Buffer& buffer,
      ReceiveHandler handler,
      int timeout = 0);

  size_t ReadSome(
      uint8_t* buf,
      size_t len) {
    return ConcatenatePackets(buf, len);
  }
  void Close();

  void Cancel() {
    m_ReceiveTimer.cancel();
  }

  size_t GetNumSentBytes() const {
    return m_NumSentBytes;
  }

  size_t GetNumReceivedBytes() const {
    return m_NumReceivedBytes;
  }

  size_t GetSendQueueSize() const {
    return m_SentPackets.size();
  }

  size_t GetReceiveQueueSize() const {
    return m_ReceiveQueue.size();
  }

  size_t GetSendBufferSize() const {
    return m_SendBuffer.rdbuf()->in_avail();
  }

  int GetWindowSize() const {
    return m_WindowSize;
  }

  int GetRTT() const {
    return m_RTT;
  }

 private:
  void Terminate();

  void SendBuffer();

  void SendQuickAck();

  void SendClose();

  bool SendPacket(
      Packet* packet);

  void SendPackets(
      const std::vector<Packet *>& packets);

  void SavePacket(
      Packet* packet);

  void ProcessPacket(
      Packet* packet);

  void ProcessAck(
      Packet* packet);

  size_t ConcatenatePackets(
      uint8_t* buf,
      size_t len);

  void UpdateCurrentRemoteLease(bool expired = false);

  template<typename Buffer, typename ReceiveHandler>
  void HandleReceiveTimer(
      const boost::system::error_code& ecode,
      const Buffer& buffer,
      ReceiveHandler handler);

  void ScheduleResend();

  void HandleResendTimer(
      const boost::system::error_code& ecode);

  void HandleAckSendTimer(
      const boost::system::error_code& ecode);

  std::shared_ptr<I2NPMessage> CreateDataMessage(
      const uint8_t * payload, size_t len);

 private:
  boost::asio::io_service& m_Service;
  uint32_t m_SendStreamID, m_RecvStreamID, m_SequenceNumber;
  int32_t m_LastReceivedSequenceNumber;
  StreamStatus m_Status;
  bool m_IsAckSendScheduled;
  StreamingDestination& m_LocalDestination;
  i2p::data::IdentityEx m_RemoteIdentity;
  std::shared_ptr<const i2p::data::LeaseSet> m_RemoteLeaseSet;
  std::shared_ptr<i2p::garlic::GarlicRoutingSession> m_RoutingSession;
  i2p::data::Lease m_CurrentRemoteLease;
  std::shared_ptr<i2p::tunnel::OutboundTunnel> m_CurrentOutboundTunnel;
  std::queue<Packet*> m_ReceiveQueue;
  std::set<Packet*, PacketCmp> m_SavedPackets;
  std::set<Packet*, PacketCmp> m_SentPackets;
  boost::asio::deadline_timer m_ReceiveTimer, m_ResendTimer, m_AckSendTimer;
  size_t m_NumSentBytes, m_NumReceivedBytes;
  uint16_t m_Port;

  std::mutex m_SendBufferMutex;
  std::stringstream m_SendBuffer;
  int m_WindowSize, m_RTT, m_RTO;
  uint64_t m_LastWindowSizeIncreaseTime;
  int m_NumResendAttempts;
  SendHandler m_SendHandler;
};

class StreamingDestination {
 public:
  typedef std::function<void (std::shared_ptr<Stream>)> Acceptor;

  StreamingDestination(
      i2p::client::ClientDestination& owner,
      uint16_t localPort = 0)
      : m_Owner(owner),
        m_LocalPort(localPort) {}
  ~StreamingDestination() {}

  void Start();

  void Stop();

  std::shared_ptr<Stream> CreateNewOutgoingStream(
      std::shared_ptr<const i2p::data::LeaseSet> remote,
      int port = 0);

  void DeleteStream(
      std::shared_ptr<Stream> stream);

  void SetAcceptor(
      const Acceptor& acceptor) {
    m_Acceptor = acceptor;
  }

  void ResetAcceptor() {
    if (m_Acceptor)
      m_Acceptor(nullptr);
    m_Acceptor = nullptr;
  }

  bool IsAcceptorSet() const {
    return m_Acceptor != nullptr;
  }

  i2p::client::ClientDestination& GetOwner() {
    return m_Owner;
  }

  uint16_t GetLocalPort() const {
    return m_LocalPort;
  }

  void UpdateLocalPort(
      uint16_t port) {
    m_LocalPort = port;
  }

  void HandleDataMessagePayload(
      const uint8_t* buf,
      size_t len);

 private:
  void HandleNextPacket(
      Packet* packet);
  std::shared_ptr<Stream> CreateNewIncomingStream();

 private:
  i2p::client::ClientDestination& m_Owner;
  uint16_t m_LocalPort;
  std::mutex m_StreamsMutex;
  std::map<uint32_t, std::shared_ptr<Stream> > m_Streams;
  Acceptor m_Acceptor;
};

//-------------------------------------------------

template<typename Buffer, typename ReceiveHandler>
void Stream::AsyncReceive(
    const Buffer& buffer, ReceiveHandler handler, int timeout) {
  auto s = shared_from_this();
  m_Service.post([=](void) {
    if (!m_ReceiveQueue.empty() || m_Status == eStreamStatusReset) {
    s->HandleReceiveTimer(
        boost::asio::error::make_error_code(
          boost::asio::error::operation_aborted),
        buffer,
        handler);
      } else {
      s->m_ReceiveTimer.expires_from_now(
          boost::posix_time::seconds(
            timeout));
      s->m_ReceiveTimer.async_wait([=](
            const boost::system::error_code& ecode) {
          s->HandleReceiveTimer(
              ecode,
              buffer,
              handler); });
    }
  });
}

template<typename Buffer, typename ReceiveHandler>
void Stream::HandleReceiveTimer(
    const boost::system::error_code& ecode,
    const Buffer& buffer, ReceiveHandler handler) {
  size_t received = ConcatenatePackets(
      boost::asio::buffer_cast<uint8_t *>(buffer),
      boost::asio::buffer_size(buffer));
  if (received > 0) {
    handler(boost::system::error_code(), received);
  } else if (ecode == boost::asio::error::operation_aborted) {
    // timeout not expired
    if (m_Status == eStreamStatusReset)
      handler(boost::asio::error::make_error_code(
            boost::asio::error::connection_reset), 0);
    else
      handler(boost::asio::error::make_error_code(
            boost::asio::error::operation_aborted), 0);
  } else {
    // timeout expired
    handler(boost::asio::error::make_error_code(
          boost::asio::error::timed_out), received);
  }
}

}  // namespace stream
}  // namespace i2p

#endif  // SRC_API_STREAMING_H_
