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

#ifndef SRC_CORE_TRANSPORT_SSU_SESSION_H_
#define SRC_CORE_TRANSPORT_SSU_SESSION_H_

#include <cstdint>
#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <vector>

#include "i2np_protocol.h"
#include "ssu_data.h"
#include "transport_session.h"
#include "crypto/aes.h"
#include "crypto/hmac.h"

namespace i2p {
namespace transport {

enum SessionState {
  SessionStateUnknown,
  SessionStateIntroduced,
  SessionStateEstablished,
  SessionStateClosed,
  SessionStateFailed
};

enum PeerTestParticipant {
  PeerTestParticipantUnknown = 0,
  PeerTestParticipantAlice1,
  PeerTestParticipantAlice2,
  PeerTestParticipantBob,
  PeerTestParticipantCharlie
};

class SSUPacket;
struct SSUSessionPacket {
  /// @var data
  /// @brief pointer to beginning of packet header
  std::uint8_t* data;
  /// @var data_len
  /// @brief how big is the total packet including header
  std::size_t data_len;
  /// @var body
  /// @brief pointer to begining of packet body
  std::uint8_t* body;

  SSUSessionPacket()
      : data(nullptr),
        data_len(0),
        body(nullptr) {}

  SSUSessionPacket(
      std::uint8_t* buf,
      std::size_t len)
      : data(buf),
        data_len(len),
        body(nullptr) {}

  /// @brief Sets flag byte
  /// @param f Flag byte
  void PutFlag(
      std::uint8_t flag) const;

  /// @brief Puts timestamp into packet header
  /// @param t Timestamp
  void PutTime(
      std::uint32_t time) const;

  /// @brief Gets pointer to MAC
  std::uint8_t* MAC() const;

  /// @brief Gets pointer to begining of encrypted section
  std::uint8_t* Encrypted() const;

  /// @brief Gets pointer to IV
  std::uint8_t* IV() const;
};

class SSUServer;
class SSUSession
    : public TransportSession,
      public std::enable_shared_from_this<SSUSession> {
 public:
  SSUSession(
      SSUServer& server,
      boost::asio::ip::udp::endpoint& remote_endpoint,
      std::shared_ptr<const i2p::data::RouterInfo> router = nullptr,
      bool peer_test = false);

  ~SSUSession();

  void ProcessNextMessage(
      std::uint8_t* buf,
      std::size_t len,
      const boost::asio::ip::udp::endpoint& sender_endpoint);

  void Connect();

  void WaitForConnect();

  void Introduce(
      std::uint32_t introducer_tag,
      const std::uint8_t * introducer_key);

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

  std::size_t GetNumSentBytes() const {
    return m_NumSentBytes;
  }

  std::size_t GetNumReceivedBytes() const {
    return m_NumReceivedBytes;
  }

  void SendKeepAlive();

  std::uint32_t GetRelayTag() const {
    return m_RelayTag;
  }

  std::uint32_t GetCreationTime() const {
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

  void CreateAESandMACKey(
      const std::uint8_t* pub_key);

  void PostI2NPMessages(
      std::vector<std::shared_ptr<I2NPMessage>> msgs);

  /// @brief Call for established session
  void ProcessDecryptedMessage(
      std::uint8_t* buf,
      std::size_t len,
      const boost::asio::ip::udp::endpoint& sender_endpoint);

  // Payload type 0: SessionRequest

  void ProcessSessionRequest(
      SSUPacket* pkt,
      const boost::asio::ip::udp::endpoint& sender_endpoint);

  void SendSessionRequest();

  // Payload type 1: SessionCreated

  void ProcessSessionCreated(
      SSUPacket* pkt);

  void SendSessionCreated(
      const std::uint8_t* x);

  // Payload type 2: SessionConfirmed

  void ProcessSessionConfirmed(
      SSUPacket* pkt);

  void SendSessionConfirmed(
      const std::uint8_t* y,
      const std::uint8_t* our_address,
      std::size_t our_address_len);

  // Payload type 3: RelayRequest

  void ProcessRelayRequest(
      SSUPacket* pkt,
      const boost::asio::ip::udp::endpoint& from);

  void SendRelayRequest(
      std::uint32_t introducer_tag,
      const std::uint8_t* introducer_key);

  // Payload type 4: RelayResponse

  void ProcessRelayResponse(
      SSUPacket* pkt);

  void SendRelayResponse(
      std::uint32_t nonce,
      const boost::asio::ip::udp::endpoint& from,
      const std::uint8_t* intro_key,
      const boost::asio::ip::udp::endpoint& to);

  // Payload type 5: RelayIntro

  void ProcessRelayIntro(
      SSUPacket* pkt);

  void SendRelayIntro(
      SSUSession* session,
      const boost::asio::ip::udp::endpoint& from);

  // Payload type 6: Data

  void ProcessData(
      SSUPacket* pkt);

  // Payload type 7: PeerTest

  void ProcessPeerTest(
      SSUPacket* pkt,
      const boost::asio::ip::udp::endpoint& sender_endpoint);

  void SendPeerTest(
      std::uint32_t nonce,
      std::uint32_t address,
      std::uint16_t port,
      const std::uint8_t* intro_key,
      bool to_address = true,
      bool send_address = true);

  // Payload type 8: SessionDestroyed

  void SendSesionDestroyed();

  // End payload types

  void Established();

  void Failed();

  void ScheduleConnectTimer();

  void HandleConnectTimer(
      const boost::system::error_code& ecode);

  void Send(
      const std::uint8_t* buf,
      std::size_t size);

  // With session key
  void Send(
      std::uint8_t type,
      const std::uint8_t* payload,
      std::size_t len);

  void WriteAndEncrypt(
    SSUPacket* packet,
    std::uint8_t* buffer,
    const std::uint8_t* aes_key,
    const std::uint8_t* mac_key);

  void FillHeaderAndEncrypt(
      std::uint8_t payload_type,
      std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* aes_key,
      const std::uint8_t* iv,
      const std::uint8_t* mac_key,
      std::uint8_t flag = 0);

  // With session key
  void FillHeaderAndEncrypt(
      std::uint8_t payload_type,
      std::uint8_t* buf,
      std::size_t len);

  void Decrypt(
      std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* aes_key);

  void DecryptSessionKey(
      std::uint8_t* buf,
      std::size_t len);

  bool Validate(
      std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* mac_key);

  const std::uint8_t* GetIntroKey() const;

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
  std::uint32_t m_RelayTag;
  SSUData m_Data;
  i2p::crypto::CBCEncryption m_SessionKeyEncryption;
  i2p::crypto::CBCDecryption m_SessionKeyDecryption;
  i2p::crypto::AESKey m_SessionKey;
  i2p::crypto::MACKey m_MACKey;
  std::uint32_t m_CreationTime;  // seconds since epoch
  std::unique_ptr<SignedData> m_SessionConfirmData;
  bool m_IsDataReceived;
};

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_SSU_SESSION_H_
