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

#ifndef SRC_CORE_ROUTER_TRANSPORTS_SSU_SESSION_H_
#define SRC_CORE_ROUTER_TRANSPORTS_SSU_SESSION_H_

#include <cstdint>
#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <vector>

#include "core/crypto/aes.h"
#include "core/crypto/hmac.h"

#include "core/router/i2np.h"
#include "core/router/transports/session.h"
#include "core/router/transports/ssu/data.h"

#include "core/util/exception.h"

namespace kovri {
namespace core {

/// @enum SessionState
/// @brief SSU session states
enum struct SessionState : std::uint8_t {
  Unknown = 0,
  Introduced,
  Established,
  Closed,
  Failed
};

/// @enum PeerTestParticipant
/// @brief Defined peer test participants
enum struct PeerTestParticipant : std::uint8_t {
  Unknown = 0,
  Alice1,
  Alice2,
  Bob,
  Charlie
};

class SSUPacket;
/// @brief A session packet "sliding-window" of the given buffer
struct SSUSessionPacket  // TODO(unassigned): finish
{
  SSUSessionPacket() : data(nullptr) /*, body(nullptr), data_len(0)*/ {}

  SSUSessionPacket(std::uint8_t* buf, const std::size_t len)
      : data(buf) /*, body(nullptr), data_len(len)*/
  {
    // TODO(anonimal): assert valid length
  }

  /// @brief Sets flag byte
  /// @param flag Flag byte
  void PutFlag(const std::uint8_t flag) noexcept
  {
    data[32] = flag;
  }

  /// @brief Puts timestamp into packet header
  /// @param time Timestamp
  void PutTime(const std::uint32_t time)
  {
    return core::OutputByteStream::Write<std::uint32_t>(&data[33], time);
  }

  /// @brief Gets pointer to MAC
  std::uint8_t* MAC() noexcept
  {
    return data;
  }

  /// @brief Gets pointer to begining of encrypted section
  std::uint8_t* Encrypted() noexcept
  {
    return data + std::size_t(32);
  }

  /// @brief Gets pointer to IV
  std::uint8_t* IV() noexcept
  {
    return data + std::size_t(16);
  }

  std::uint8_t* data;  ///< Pointer to beginning of packet header
  //std::uint8_t* body;  ///< Pointer to begining of packet body
  //std::size_t data_len;  ///< How big is the total packet including header
};

class SSUServer;
class SSUSession
    : public TransportSession,
      public std::enable_shared_from_this<SSUSession> {
 public:
  SSUSession(
      SSUServer& server,
      boost::asio::ip::udp::endpoint& remote_endpoint,
      std::shared_ptr<const kovri::core::RouterInfo> router = nullptr,
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
  const std::string GetFormattedSessionInfo() const
  {
    std::ostringstream info;
    info << " [" << GetRemoteIdentHashAbbreviation() << "] "
         << GetRemoteEndpoint() << " ";
    return info.str();
  }

  /// @return Current session's peer's ident hash
  const std::string& GetRemoteIdentHashAbbreviation() const
  {
    return m_RemoteIdentHashAbbreviation;
  }

  /// @return Current session's endpoint address/port
  const boost::asio::ip::udp::endpoint& GetRemoteEndpoint() const
  {
    return m_RemoteEndpoint;
  }

  void FlushData();

 private:
  boost::asio::io_service& GetService();

  bool CreateAESandMACKey(
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

  /// @brief We are Alice, sending Bob a SessionRequest message
  void SendSessionRequest();

  // Payload type 1: SessionCreated

  /// @brief We are Alice, processing Bob's SessionCreated message
  /// @param packet Bob's message (header + payload)
  void ProcessSessionCreated(const SSUPacket* packet);

  /// @brief We are Bob, creating and sending SessionCreated message
  /// @param dh_x Diffie-Hellman X as created by Alice
  void SendSessionCreated(const std::uint8_t* dh_x);

  // Payload type 2: SessionConfirmed

  void ProcessSessionConfirmed(
      SSUPacket* pkt);

  /// @brief We are Alice, creating and sending SessionConfirmed message
  /// @param dh_y Diffie-Hellman Y as created by Bob
  /// @param our_address Our IP address
  /// @param our_address Our IP size (4 or 16 bytes)
  /// @param our_port Our port number
  void SendSessionConfirmed(
      const std::uint8_t* y,
      const std::uint8_t* our_address,
      std::size_t our_address_len,
      std::uint16_t our_port);

  // Payload type 3: RelayRequest

  void ProcessRelayRequest(
      SSUPacket* pkt,
      const boost::asio::ip::udp::endpoint& from);

  void SendRelayRequest(
      const std::uint32_t introducer_tag,
      const std::uint8_t* introducer_key);

  // Payload type 4: RelayResponse

  void ProcessRelayResponse(
      SSUPacket* pkt);

  void SendRelayResponse(
      const std::uint32_t nonce,
      const boost::asio::ip::udp::endpoint& from,
      const std::uint8_t* intro_key,
      const boost::asio::ip::udp::endpoint& to);

  // Payload type 5: RelayIntro

  /// @brief We are Charlie, receiving Bob's RelayIntro - then sending Alice a RelayResponse
  /// @param packet Bob's RelayIntro packet containing Alice's IP and port
  void ProcessRelayIntro(SSUPacket* packet);

  void SendRelayIntro(
      const SSUSession* session,
      const boost::asio::ip::udp::endpoint& from);

  // Payload type 6: Data

  void ProcessData(
      SSUPacket* pkt);

  // Payload type 7: PeerTest

  void ProcessPeerTest(
      SSUPacket* pkt,
      const boost::asio::ip::udp::endpoint& sender_endpoint);

  void SendPeerTest(
      const std::uint32_t nonce,
      const boost::asio::ip::address& address,
      const std::uint16_t port,
      const std::uint8_t* intro_key,
      const bool to_address = true,
      const bool send_address = true);

  // Payload type 8: SessionDestroyed

  void SendSessionDestroyed();

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
    std::size_t buffer_size,
    const std::uint8_t* aes_key,
    const std::uint8_t* mac_key);

  void FillHeaderAndEncrypt(
      std::uint8_t payload_type,
      std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* aes_key,
      const std::uint8_t* mac_key,
      std::uint8_t flag = 0);

  // With session key
  void FillHeaderAndEncrypt(
      std::uint8_t payload_type,
      std::uint8_t* buf,
      std::size_t len);

  /// @brief Decrypt message
  /// @param buf Message to decrypt + decrypt to existing buffer
  /// @param len Message length
  /// @param key Decrypt with given key (implies not using session's AES key)
  /// @param is_session Decrypt using session's AES key (implies not using given AES key)
  void Decrypt(
      std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* aes_key,
      const bool is_session = false);

  bool Validate(
      std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* mac_key);

  const std::uint8_t* GetIntroKey() const;

  void ScheduleTermination();

  void HandleTerminationTimer(
      const boost::system::error_code& ecode);

 private:
  /// @brief Calculates exchanged session dataset size used in
  ///   SessionRequest/SessionCreated/SessionConfirmed
  /// @param alice_and_bob Alice + Bob's address sizes in bytes (concatenated size)
  // TODO(anonimal): this will most likely be removed when sequence containers are implemented
  // TODO(anonimal): by this point, why would we allow mix-and-match IPv6 to send to IPv4 - or vice versa...
  std::uint16_t get_signed_data_size(const std::uint8_t alice_and_bob) const
      noexcept
  {
    // TODO(anonimal): this doesn't ensure 4 or 16 byte sizes per host but that
    //   check should be done elsewhere, in a caller.
    assert(alice_and_bob <= (16 * 2));  // No larger than 2 IPv6 addresses

    return DHKeySize::PubKey * 2  // DH X+Y
           + alice_and_bob  // Alice + Bob's address size
           + 2  // Alice's port
           + 2  // Bob's port
           + 4  // Alice's relay tag
           + 4;  // Alice or Bob's signed-on time
  }

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
  kovri::core::CBCEncryption m_SessionKeyEncryption;
  kovri::core::CBCDecryption m_SessionKeyDecryption;
  kovri::core::AESKey m_SessionKey;
  kovri::core::MACKey m_MACKey;
  std::uint32_t m_CreationTime;  // seconds since epoch

  /// @brief The unsigned SessionCreated data for SessionConfirmed processing
  // TODO(anonimal): data should be separated from session class
  // TODO(anonimal): mutex lock if we ever expand member usage across threads (unlikely)
  std::vector<std::uint8_t> m_SessionConfirmData;

  bool m_IsDataReceived;
  kovri::core::Exception m_Exception;
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_TRANSPORTS_SSU_SESSION_H_
