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

#ifndef SRC_CLIENT_API_STREAMING_H_
#define SRC_CLIENT_API_STREAMING_H_

#include <boost/asio.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "core/router/garlic.h"
#include "core/router/i2np.h"
#include "core/router/identity.h"
#include "core/router/lease_set.h"
#include "core/router/tunnel/impl.h"

#include "core/util/exception.h"
#include "core/util/i2p_endian.h"

namespace kovri {
namespace client {

class ClientDestination;  // TODO(unassigned): remove forward declaration

const std::uint16_t PACKET_FLAG_SYNCHRONIZE = 0x0001;
const std::uint16_t PACKET_FLAG_CLOSE = 0x0002;
const std::uint16_t PACKET_FLAG_RESET = 0x0004;
const std::uint16_t PACKET_FLAG_SIGNATURE_INCLUDED = 0x0008;
const std::uint16_t PACKET_FLAG_SIGNATURE_REQUESTED = 0x0010;
const std::uint16_t PACKET_FLAG_FROM_INCLUDED = 0x0020;
const std::uint16_t PACKET_FLAG_DELAY_REQUESTED = 0x0040;
const std::uint16_t PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED = 0x0080;
const std::uint16_t PACKET_FLAG_PROFILE_INTERACTIVE = 0x0100;
const std::uint16_t PACKET_FLAG_ECHO = 0x0200;
const std::uint16_t PACKET_FLAG_NO_ACK = 0x0400;

const std::size_t STREAMING_MTU = 1730;
const std::size_t MAX_PACKET_SIZE = 4096;
const std::size_t COMPRESSION_THRESHOLD_SIZE = 66;
const int ACK_SEND_TIMEOUT = 200;  // in milliseconds
const int MAX_NUM_RESEND_ATTEMPTS = 6;
const int WINDOW_SIZE = 6;  // in messages
const int MIN_WINDOW_SIZE = 1;
const int MAX_WINDOW_SIZE = 128;
const int INITIAL_RTT = 8000;  // in milliseconds
const int INITIAL_RTO = 9000;  // in milliseconds

struct Packet {
  std::size_t len, offset;
  std::uint8_t buf[MAX_PACKET_SIZE];
  std::uint64_t send_time;

  Packet()
      : len(0),
        offset(0),
        send_time(0) {}

  std::uint8_t* GetBuffer() {
    return buf + offset;
  }

  std::size_t GetLength() const {
    return len - offset;
  }

  std::uint32_t GetSendStreamID() const {
    return bufbe32toh(buf);
  }

  std::uint32_t GetReceiveStreamID() const {
    return bufbe32toh(buf + 4);
  }

  std::uint32_t GetSeqn() const {
    return bufbe32toh(buf + 8);
  }

  std::uint32_t GetAckThrough() const {
    return bufbe32toh(buf + 12);
  }

  std::uint8_t GetNACKCount() const {
    return buf[16];
  }

  std::uint32_t GetNACK(int i) const {
    return bufbe32toh(buf + 17 + 4 * i);
  }

  const std::uint8_t* GetOption() const {
    return buf + 17 + GetNACKCount() * 4 + 3;
  }  // 3 = resendDelay + flags

  std::uint16_t GetFlags() const {
    return bufbe16toh(GetOption() - 2);
  }
  std::uint16_t GetOptionSize() const {
    return bufbe16toh(GetOption ());
  }
  const std::uint8_t* GetOptionData() const {
    return GetOption() + 2;
  }
  const std::uint8_t* GetPayload() const {
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
      std::shared_ptr<const kovri::core::LeaseSet> remote,
      std::uint16_t port = 0);
  // Incoming
  Stream(
      boost::asio::io_service& service,
      StreamingDestination& local);
  ~Stream();

  std::uint32_t GetSendStreamID() const {
    return m_SendStreamID;
  }

  std::uint32_t GetReceiveStreamID() const {
    return m_RecvStreamID;
  }

  std::shared_ptr<const kovri::core::LeaseSet> GetRemoteLeaseSet() const {
    return m_RemoteLeaseSet;
  }

  const kovri::core::IdentityEx& GetRemoteIdentity() const {
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

  std::size_t Send(
      const std::uint8_t* buf,
      std::size_t len);

  void AsyncSend(
      const std::uint8_t* buf,
      std::size_t len,
      SendHandler handler);

  template<typename Buffer, typename ReceiveHandler>
  void AsyncReceive(
      const Buffer& buffer,
      ReceiveHandler handler,
      int timeout = 0);

  std::size_t ReadSome(
      std::uint8_t* buf,
      std::size_t len) {
    return ConcatenatePackets(buf, len);
  }
  void Close();

  void Cancel() {
    m_ReceiveTimer.cancel();
  }

  std::size_t GetNumSentBytes() const {
    return m_NumSentBytes;
  }

  std::size_t GetNumReceivedBytes() const {
    return m_NumReceivedBytes;
  }

  std::size_t GetSendQueueSize() const {
    return m_SentPackets.size();
  }

  std::size_t GetReceiveQueueSize() const {
    return m_ReceiveQueue.size();
  }

  std::size_t GetSendBufferSize() const {
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

  std::size_t ConcatenatePackets(
      std::uint8_t* buf,
      std::size_t len);

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

  std::shared_ptr<kovri::core::I2NPMessage> CreateDataMessage(
      const std::uint8_t * payload, std::size_t len);

 private:
  boost::asio::io_service& m_Service;
  std::uint32_t m_SendStreamID, m_RecvStreamID, m_SequenceNumber;
  std::int32_t m_LastReceivedSequenceNumber;
  StreamStatus m_Status;
  bool m_IsAckSendScheduled;
  StreamingDestination& m_LocalDestination;
  kovri::core::IdentityEx m_RemoteIdentity;
  std::shared_ptr<const kovri::core::LeaseSet> m_RemoteLeaseSet;
  std::shared_ptr<kovri::core::GarlicRoutingSession> m_RoutingSession;
  kovri::core::Lease m_CurrentRemoteLease;
  std::shared_ptr<kovri::core::OutboundTunnel> m_CurrentOutboundTunnel;
  std::queue<Packet*> m_ReceiveQueue;
  std::set<Packet*, PacketCmp> m_SavedPackets;
  std::set<Packet*, PacketCmp> m_SentPackets;
  boost::asio::deadline_timer m_ReceiveTimer, m_ResendTimer, m_AckSendTimer;
  std::size_t m_NumSentBytes, m_NumReceivedBytes;
  std::uint16_t m_Port;

  std::mutex m_SendBufferMutex;
  std::stringstream m_SendBuffer;
  int m_WindowSize, m_RTT, m_RTO;
  std::uint64_t m_LastWindowSizeIncreaseTime;
  int m_NumResendAttempts;
  SendHandler m_SendHandler;

  kovri::core::Exception m_Exception;
};

class StreamingDestination {
 public:
  typedef std::function<void (std::shared_ptr<Stream>)> Acceptor;

  StreamingDestination(
      kovri::client::ClientDestination& owner,
      std::uint16_t local_port = 0)
      : m_Owner(owner),
        m_LocalPort(local_port),
        m_Exception(__func__) {}

  ~StreamingDestination() {}

  void Start();

  void Stop();

  std::shared_ptr<Stream> CreateNewOutgoingStream(
      std::shared_ptr<const kovri::core::LeaseSet> remote,
      std::uint16_t port = 0);

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

  kovri::client::ClientDestination& GetOwner() {
    return m_Owner;
  }

  std::uint16_t GetLocalPort() const {
    return m_LocalPort;
  }

  void UpdateLocalPort(
      std::uint16_t port) {
    m_LocalPort = port;
  }

  void HandleDataMessagePayload(
      const std::uint8_t* buf,
      std::size_t len);

 private:
  void HandleNextPacket(
      Packet* packet);
  std::shared_ptr<Stream> CreateNewIncomingStream();

 private:
  kovri::client::ClientDestination& m_Owner;
  std::uint16_t m_LocalPort;
  std::mutex m_StreamsMutex;
  std::map<std::uint32_t, std::shared_ptr<Stream> > m_Streams;
  Acceptor m_Acceptor;
  kovri::core::Exception m_Exception;
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
  std::size_t received = ConcatenatePackets(
      boost::asio::buffer_cast<std::uint8_t *>(buffer),
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

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_API_STREAMING_H_
