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

#ifndef SRC_CORE_TRANSPORT_NTCPSESSION_H_
#define SRC_CORE_TRANSPORT_NTCPSESSION_H_

#include <boost/asio.hpp>

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

#include <inttypes.h>

#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "I2NPProtocol.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "TransportSession.h"
#include "crypto/AES.h"

namespace i2p {
namespace transport {

#pragma pack(1)
struct NTCPPhase1 {
  uint8_t pubKey[256];
  uint8_t HXxorHI[32];
};

struct NTCPPhase2 {
  uint8_t pubKey[256];
  struct {
    uint8_t hxy[32];
    uint32_t timestamp;
    uint8_t filler[12];
  } encrypted;
};

#pragma pack()

const size_t NTCP_MAX_MESSAGE_SIZE = 16384;
const size_t NTCP_BUFFER_SIZE = 4160;  // fits 4 tunnel messages (4 * 1028)
const int NTCP_TERMINATION_TIMEOUT = 120;  // 2 minutes

// Total == 448
// TODO(unassigned): replace raw numbers with constants
const size_t NTCP_DEFAULT_PHASE3_SIZE =
  2 +   // size
  i2p::data::DEFAULT_IDENTITY_SIZE +  // 387
  4 +   // ts
  15 +  // padding
  40;   // signature

const int NTCP_BAN_EXPIRATION_TIMEOUT = 70;  // in second

class NTCPServer;
class NTCPSession
    : public TransportSession,
      public std::enable_shared_from_this<NTCPSession> {
 public:
  NTCPSession(
      NTCPServer& server,
      std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter = nullptr);
  ~NTCPSession();

  void Terminate();

  void Done();

  boost::asio::ip::tcp::socket& GetSocket() {
    return m_Socket;
  }

  bool IsEstablished() const {
    return m_IsEstablished;
  }

  void ClientLogin();

  void ServerLogin();

  void SendI2NPMessages(
      const std::vector<std::shared_ptr<I2NPMessage> >& msgs);

 private:
  void PostI2NPMessages(
      std::vector<std::shared_ptr<I2NPMessage> > msgs);

  void Connected();

  void SendTimeSyncMessage();

  void SetIsEstablished(
      bool isEstablished) {
    m_IsEstablished = isEstablished;
  }

  void CreateAESKey(
      uint8_t* pubKey,
      i2p::crypto::AESKey& key);

  // client
  void SendPhase3();

  void HandlePhase1Sent(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  void HandlePhase2Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  void HandlePhase3Sent(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      uint32_t tsA);

  void HandlePhase4Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      uint32_t tsA);
  // end client

  // server
  void SendPhase2();

  void SendPhase4(
      uint32_t tsA,
      uint32_t tsB);

  void HandlePhase1Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  void HandlePhase2Sent(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      uint32_t tsB);

  void HandlePhase3Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      uint32_t tsB);

  void HandlePhase3ExtraReceived(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      uint32_t tsB,
      size_t paddingLen);

  void HandlePhase3(
      uint32_t tsB,
      size_t paddingLen);

  void HandlePhase4Sent(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);
  // end server

  // common
  void Receive();

  void HandleReceived(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  bool DecryptNextBlock(
      const uint8_t* encrypted);
  // end common

  void Send(
      std::shared_ptr<i2p::I2NPMessage> msg);
  void Send(
      const std::vector<std::shared_ptr<I2NPMessage> >& msgs);

  boost::asio::const_buffers_1 CreateMsgBuffer(
      std::shared_ptr<I2NPMessage> msg);

  void HandleSent(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::vector<std::shared_ptr<I2NPMessage> > msgs);

  // timer
  void ScheduleTermination();

  void HandleTerminationTimer(
      const boost::system::error_code& ecode);
  // end timer

 private:
  NTCPServer& m_Server;
  boost::asio::ip::tcp::socket m_Socket;
  boost::asio::deadline_timer m_TerminationTimer;
  bool m_IsEstablished, m_IsTerminated;

  i2p::crypto::CBCDecryption m_Decryption;
  i2p::crypto::CBCEncryption m_Encryption;

  struct Establisher {
    NTCPPhase1 phase1;
    NTCPPhase2 phase2;
  } * m_Establisher;

  i2p::crypto::AESAlignedBuffer<NTCP_BUFFER_SIZE + 16> m_ReceiveBuffer;
  i2p::crypto::AESAlignedBuffer<16> m_TimeSyncBuffer;
  int m_ReceiveBufferOffset;

  std::shared_ptr<I2NPMessage> m_NextMessage;
  size_t m_NextMessageOffset;
  i2p::I2NPMessagesHandler m_Handler;

  bool m_IsSending;
  std::vector<std::shared_ptr<I2NPMessage> > m_SendQueue;

  boost::asio::ip::address m_ConnectedFrom;  // for ban
};

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_NTCPSESSION_H_
