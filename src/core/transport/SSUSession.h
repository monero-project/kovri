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

#ifndef SRC_CORE_TRANSPORT_SSUSESSION_H_
#define SRC_CORE_TRANSPORT_SSUSESSION_H_

#include <inttypes.h>

#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <vector>

#include "I2NPProtocol.h"
#include "SSUData.h"
#include "TransportSession.h"
#include "crypto/AES.h"
#include "crypto/HMAC.h"

namespace i2p {
namespace transport {

class SSUPacket;

enum PayloadType {
  ePayloadTypeSessionRequest = 0,
  ePayloadTypeSessionCreated,
  ePayloadTypeSessionConfirmed,
  ePayloadTypeRelayRequest,
  ePayloadTypeRelayResponse,
  ePayloadTypeRelayIntro,
  ePayloadTypeData,
  ePayloadTypePeerTest,
  ePayloadTypeSessionDestroyed
};

// SSU Header extended options
struct SSUExtendedOptions {
  uint8_t * dataptr;
  size_t datalen;
};

struct SSUSessionPacket {
  uint8_t* dataptr;  // pointer to beginning of packet header
  size_t datalen;    // how big is the total packet including header
  size_t headerlen;  // how big is the header
  uint8_t* bodyptr;  // pointer to begining of packet body
  size_t bodylen;    // how big the packet body is

  SSUSessionPacket()
      : dataptr(nullptr),
        datalen(0),
        headerlen(0),
        bodyptr(nullptr),
        bodylen(0) {}
  SSUSessionPacket(
      uint8_t* buf,
      size_t len)
      : dataptr(buf),
        datalen(len),
        headerlen(0),
        bodyptr(nullptr),
        bodylen(0) {}

  /// @brief How many bytes long is the header (includes Extended options)
  /// @return n bytes denoting size of header
  size_t ComputeHeaderSize() const;

  /// @brief Do we have extended options?
  /// @return true if we have extended options
  bool HasExtendedOptions() const;

  /// @brief Extract the extended options from the SSUHeader
  /// @return true if successful otherwise false
  bool ExtractExtendedOptions(SSUExtendedOptions & opts) const;

  /// @brief Obtain the SSU payload type
  /// @return what type of ssu packet are we?
  uint8_t GetPayloadType() const;

  /// @return true if the rekey flag is set
  bool Rekey() const;

  /// @brief Used for rekey and extended options
  uint8_t Flag() const;

  /// @brief Sets flag byte
  void PutFlag(
      uint8_t f) const;

  /// @brief Packet timestamp
  /// @return a four byte sending timestamp (seconds since the unix epoch).
  uint32_t Time() const;

  /// @brief Puts timestamp into packet header
  void PutTime(uint32_t t) const;

  /// @brief Gets pointer to MAC
  uint8_t* MAC() const;

  /// @brief Gets pointer to begining of encrypted section
  uint8_t* Encrypted() const;

  /// @brief Gets pointer to IV
  uint8_t* IV() const;

  /// @brief Parses SSU header
  /// @return true if valid header format otherwise false
  bool ParseHeader();
};

const int SSU_CONNECT_TIMEOUT = 5;  // 5 seconds
const int SSU_TERMINATION_TIMEOUT = 330;  // 5.5 minutes

// Messages (payload types) (4 bits)
const uint8_t PAYLOAD_TYPE_SESSION_REQUEST = 0;
const uint8_t PAYLOAD_TYPE_SESSION_CREATED = 1;
const uint8_t PAYLOAD_TYPE_SESSION_CONFIRMED = 2;
const uint8_t PAYLOAD_TYPE_RELAY_REQUEST = 3;
const uint8_t PAYLOAD_TYPE_RELAY_RESPONSE = 4;
const uint8_t PAYLOAD_TYPE_RELAY_INTRO = 5;
const uint8_t PAYLOAD_TYPE_DATA = 6;
const uint8_t PAYLOAD_TYPE_PEER_TEST = 7;
const uint8_t PAYLOAD_TYPE_SESSION_DESTROYED = 8;

enum SessionState {
  eSessionStateUnknown,
  eSessionStateIntroduced,
  eSessionStateEstablished,
  eSessionStateClosed,
  eSessionStateFailed
};

enum PeerTestParticipant {
  ePeerTestParticipantUnknown = 0,
  ePeerTestParticipantAlice1,
  ePeerTestParticipantAlice2,
  ePeerTestParticipantBob,
  ePeerTestParticipantCharlie
};

class SSUServer;
class SSUSession
    : public TransportSession,
      public std::enable_shared_from_this<SSUSession> {
 public:
  SSUSession(
      SSUServer& server,
      boost::asio::ip::udp::endpoint& remoteEndpoint,
      std::shared_ptr<const i2p::data::RouterInfo> router = nullptr,
      bool peerTest = false);
  ~SSUSession();

  void ProcessNextMessage(
      uint8_t* buf,
      size_t len,
      const boost::asio::ip::udp::endpoint& senderEndpoint);

  void Connect();

  void WaitForConnect();

  void Introduce(
      uint32_t iTag,
      const uint8_t * iKey);

  void WaitForIntroduction();

  void Close();

  void Done();

  bool IsV6() const {
    return m_RemoteEndpoint.address().is_v6();
  }

  void SendI2NPMessages(
      const std::vector<std::shared_ptr<I2NPMessage>>& msgs);

  void SendPeerTest();  // Alice

  SessionState GetState() const {
    return m_State;
  }

  size_t GetNumSentBytes() const {
    return m_NumSentBytes;
  }

  size_t GetNumReceivedBytes() const {
    return m_NumReceivedBytes;
  }

  void SendKeepAlive();

  uint32_t GetRelayTag() const {
    return m_RelayTag;
  }

  uint32_t GetCreationTime() const {
    return m_CreationTime;
  }

  /// @brief Sets peer abbreviated ident hash
  void SetRemoteIdentHashAbbreviation() {
    m_RemoteIdentHashAbbreviation =
      GetRemoteRouter()->GetIdentHashAbbreviation();
  }

  /// @brief Set current session's endpoint address/port
  void SetRemoteEndpoint(
      const boost::asio::ip::udp::endpoint& ep) {
    m_RemoteEndpoint = ep;
  }

  /// @return Log-formatted string of session info
  const std::string GetFormattedSessionInfo() {
    std::ostringstream info;
    info << " [" << GetRemoteIdentHashAbbreviation() << "] "
         << GetRemoteEndpoint() << " ";
    return info.str();
  }

  /// @return Current session's peer's ident hash
  const std::string& GetRemoteIdentHashAbbreviation() {
    return m_RemoteIdentHashAbbreviation;
  }

  /// @return Current session's endpoint address/port
  const boost::asio::ip::udp::endpoint& GetRemoteEndpoint() {
    return m_RemoteEndpoint;
  }

  void FlushData();

 private:
  boost::asio::io_service& GetService();

  void CreateAESandMacKey(
      const uint8_t* pubKey);

  void PostI2NPMessages(
      std::vector<std::shared_ptr<I2NPMessage>> msgs);

  /// @brief Call for established session
  void ProcessDecryptedMessage(
      uint8_t* buf,
      size_t len,
      const boost::asio::ip::udp::endpoint& senderEndpoint);

  // Payload type 0: SessionRequest

  void ProcessSessionRequest(
      SSUPacket* pkt,
      const boost::asio::ip::udp::endpoint& senderEndpoint);

  void SendSessionRequest();

  // Payload type 1: SessionCreated

  void ProcessSessionCreated(SSUPacket* pkt);

  void SendSessionCreated(const uint8_t* x);

  // Payload type 2: SessionConfirmed

  void ProcessSessionConfirmed(SSUPacket* pkt);

  void SendSessionConfirmed(
      const uint8_t* y,
      const uint8_t* ourAddress,
      size_t ourAddressLen);

  // Payload type 3: RelayRequest

  void ProcessRelayRequest(
      SSUPacket* pkt,
      const boost::asio::ip::udp::endpoint& from);

  void SendRelayRequest(
      uint32_t iTag,
      const uint8_t* iKey);

  // Payload type 4: RelayResponse

  void ProcessRelayResponse(SSUPacket* pkt);

  void SendRelayResponse(
      uint32_t nonce,
      const boost::asio::ip::udp::endpoint& from,
      const uint8_t* introKey,
      const boost::asio::ip::udp::endpoint& to);

  // Payload type 5: RelayIntro

  void ProcessRelayIntro(SSUPacket* pkt);

  void SendRelayIntro(
      SSUSession* session,
      const boost::asio::ip::udp::endpoint& from);

  // Payload type 6: Data

  void ProcessData(SSUPacket* pkt);

  // Payload type 7: PeerTest

  void ProcessPeerTest(
      SSUPacket* pkt,
      const boost::asio::ip::udp::endpoint& senderEndpoint);

  void SendPeerTest(
      uint32_t nonce,
      uint32_t address,
      uint16_t port,
      const uint8_t* introKey,
      bool toAddress = true,
      bool sendAddress = true);

  // Payload type 8: SessionDestroyed

  void SendSesionDestroyed();

  // End payload types

  void Established();

  void Failed();

  void ScheduleConnectTimer();

  void HandleConnectTimer(
      const boost::system::error_code& ecode);

  void Send(
      const uint8_t* buf,
      size_t size);

  // With session key
  void Send(
      uint8_t type,
      const uint8_t* payload,
      size_t len);

  void FillHeaderAndEncrypt(
      uint8_t payloadType,
      uint8_t* buf,
      size_t len,
      const uint8_t* aesKey,
      const uint8_t* iv,
      const uint8_t* macKey,
      uint8_t flag = 0);

  // With session key
  void FillHeaderAndEncrypt(
      uint8_t payloadType,
      uint8_t* buf,
      size_t len);

  void Decrypt(
      uint8_t* buf,
      size_t len,
      const uint8_t* aesKey);

  void DecryptSessionKey(
      uint8_t* buf,
      size_t len);

  bool Validate(
      uint8_t* buf,
      size_t len,
      const uint8_t* macKey);

  const uint8_t* GetIntroKey() const;

  void ScheduleTermination();

  void HandleTerminationTimer(
      const boost::system::error_code& ecode);

 private:
  friend class SSUData;  // TODO(unassigned): change in later
  std::string m_RemoteIdentHashAbbreviation;
  SSUServer& m_Server;
  boost::asio::ip::udp::endpoint m_RemoteEndpoint;
  boost::asio::deadline_timer m_Timer;
  bool m_PeerTest;
  SessionState m_State;
  bool m_IsSessionKey;
  uint32_t m_RelayTag;
  i2p::crypto::CBCEncryption m_SessionKeyEncryption;
  i2p::crypto::CBCDecryption m_SessionKeyDecryption;
  i2p::crypto::AESKey m_SessionKey;
  i2p::crypto::MACKey m_MacKey;
  uint32_t m_CreationTime;  // seconds since epoch
  SSUData m_Data;
  std::unique_ptr<SignedData> m_SessionConfirmData;
  bool m_IsDataReceived;
};

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_SSUSESSION_H_

