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

#ifndef SRC_CORE_TRANSPORT_NTCP_SESSION_H_
#define SRC_CORE_TRANSPORT_NTCP_SESSION_H_

#include <boost/asio.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <string>
#include <thread>
#include <vector>

#include "i2np_protocol.h"
#include "identity.h"
#include "router_info.h"
#include "transport_session.h"
#include "crypto/aes.h"

namespace i2p {
namespace transport {

enum struct NTCPSize : const std::size_t {
  pub_key     = 256,  // DH (X, Y)
  hash        = 32,
  padding     = 12,
  session_key = 32,
  iv          = 16,
  adler32     = 4,
  // TODO(unassigned):
  // Through release of java 0.9.15, the router identity was always 387 bytes,
  // the signature was always a 40 byte DSA signature, and the padding was always 15 bytes.
  // As of release java 0.9.16, the router identity may be longer than 387 bytes,
  // and the signature type and length are implied by the type of the Signing Public Key in Alice's Router Identity.
  // The padding is as necessary to a multiple of 16 bytes for the entire unencrypted contents.
  phase3_alice_ri  = 2,
  phase3_alice_ts  = 4,
  phase3_padding   = 15,
  phase3_signature = 40,
  phase3_unencrypted =
    phase3_alice_ri +
    i2p::data::DEFAULT_IDENTITY_SIZE +  // 387
    phase3_alice_ts +
    phase3_padding +
    phase3_signature,  // Total = 448
  max_message = 16384,
  buffer = 4160,  // fits 4 tunnel messages (4 * 1028)
};

enum struct NTCPTimeoutLength : const std::size_t {
  termination = 120,  // 2 minutes
  ban_expiration = 70,  // in seconds
};

// TODO(unassigned): is packing really necessary?
// If so, should we not be consistent with other protocols?
#pragma pack(1)
struct NTCPPhase1 {
  std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::pub_key)> pub_key;
  std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::hash)> HXxorHI;
};

struct NTCPPhase2 {
  std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::pub_key)> pub_key;
  struct {
    std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::hash)> hxy;
    std::uint32_t timestamp;
    std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::padding)> padding;
  } encrypted;
};
#pragma pack()

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
      const std::vector<std::shared_ptr<I2NPMessage>>& msgs);

  std::size_t GetNumSentBytes() const {
    return m_NumSentBytes;
  }

  std::size_t GetNumReceivedBytes() const {
    return m_NumReceivedBytes;
  }

  /// @brief Sets peer abbreviated ident hash
  void SetRemoteIdentHashAbbreviation() {
    m_RemoteIdentHashAbbreviation =
      GetRemoteRouter()->GetIdentHashAbbreviation();
  }

  /// @brief Sets peer endpoint address/port
  /// @note Requires socket to be initialized before call
  const boost::system::error_code SetRemoteEndpoint() {
    boost::system::error_code ec;
    m_RemoteEndpoint = m_Socket.remote_endpoint(ec);
    return ec;
  }

  /// @return Log-formatted string of session info
  const std::string GetFormattedSessionInfo() {
    std::ostringstream info;
    info << " [" << GetRemoteIdentHashAbbreviation()
         << "] " << GetRemoteEndpoint() << " ";
    return info.str();
  }

  /// @return Current session's peer's ident hash
  const std::string& GetRemoteIdentHashAbbreviation() {
    return m_RemoteIdentHashAbbreviation;
  }

  /// @return Current session's endpoint address/port
  const boost::asio::ip::tcp::endpoint& GetRemoteEndpoint() {
    return m_RemoteEndpoint;
  }

 private:
  void PostI2NPMessages(
      std::vector<std::shared_ptr<I2NPMessage>> msgs);

  void Connected();

  void SendTimeSyncMessage();

  void SetIsEstablished(
      bool isEstablished) {
    m_IsEstablished = isEstablished;
  }

  void CreateAESKey(
      std::uint8_t* pubKey,
      i2p::crypto::AESKey& key);

  // Client
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
      std::uint32_t tsA);

  void HandlePhase4Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::uint32_t tsA);

  // Server
  void SendPhase2();

  void SendPhase4(
      std::uint32_t tsA,
      std::uint32_t tsB);

  void HandlePhase1Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  void HandlePhase2Sent(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::uint32_t tsB);

  void HandlePhase3Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::uint32_t tsB);

  void HandlePhase3ExtraReceived(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::uint32_t tsB,
      std::size_t padding_len);

  void HandlePhase3(
      std::uint32_t tsB,
      std::size_t padding_len);

  void HandlePhase4Sent(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  // Client/Server
  void ReceivePayload();

  void HandleReceivedPayload(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  bool DecryptNextBlock(
      const std::uint8_t* encrypted);

  /// @brief Send payload (I2NP message)
  /// @param msg shared pointer to payload (I2NPMessage)
  void SendPayload(
      std::shared_ptr<i2p::I2NPMessage> msg);

  /// @brief Send payload (I2NP messages)
  /// @param msg shared pointer to payload (I2NPMessages)
  void SendPayload(
      const std::vector<std::shared_ptr<I2NPMessage>>& msgs);

  boost::asio::const_buffers_1 CreateMsgBuffer(
      std::shared_ptr<I2NPMessage> msg);

  void HandleSentPayload(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::vector<std::shared_ptr<I2NPMessage>> msgs);

  // Timer
  void ScheduleTermination();

  void HandleTerminationTimer(
      const boost::system::error_code& ecode);

 private:
  std::string m_RemoteIdentHashAbbreviation;

  NTCPServer& m_Server;
  boost::asio::ip::tcp::socket m_Socket;
  boost::asio::ip::tcp::endpoint m_RemoteEndpoint;
  boost::asio::deadline_timer m_TerminationTimer;
  bool m_IsEstablished, m_IsTerminated;

  i2p::crypto::CBCDecryption m_Decryption;
  i2p::crypto::CBCEncryption m_Encryption;

  struct Establisher {
    NTCPPhase1 phase1;
    NTCPPhase2 phase2;
  };

  std::unique_ptr<Establisher> m_Establisher;

  i2p::crypto::AESAlignedBuffer<
    static_cast<std::size_t>(NTCPSize::buffer) +
    static_cast<std::size_t>(NTCPSize::iv)> m_ReceiveBuffer;

  i2p::crypto::AESAlignedBuffer<
    static_cast<std::size_t>(NTCPSize::iv)> m_TimeSyncBuffer;

  std::size_t m_ReceiveBufferOffset;

  std::shared_ptr<I2NPMessage> m_NextMessage;
  std::size_t m_NextMessageOffset;
  i2p::I2NPMessagesHandler m_Handler;

  bool m_IsSending;
  std::vector<std::shared_ptr<I2NPMessage>> m_SendQueue;
};

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_NTCP_SESSION_H_
