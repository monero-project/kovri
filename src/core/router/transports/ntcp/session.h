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

#ifndef SRC_CORE_ROUTER_TRANSPORTS_NTCP_SESSION_H_
#define SRC_CORE_ROUTER_TRANSPORTS_NTCP_SESSION_H_

#include <boost/asio.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <ostream>
#include <string>
#include <thread>
#include <vector>

#include "core/crypto/aes.h"

#include "core/router/i2np.h"
#include "core/router/identity.h"
#include "core/router/info.h"
#include "core/router/transports/session.h"

#include "core/util/exception.h"

namespace kovri {
namespace core {

/// @enum NTCPTimeoutLength
/// @brief Timeout lenghts used in NTCP
/// @notes Time is measured in seconds
enum struct NTCPTimeoutLength : std::uint16_t {
  Termination = 120,
  BanExpiration = 70,
};

class NTCPServer;
class NTCPSession
    : public TransportSession,
      public std::enable_shared_from_this<NTCPSession> {
 public:
  NTCPSession(
      NTCPServer& server,
      std::shared_ptr<const kovri::core::RouterInfo> remote_router = nullptr);

  ~NTCPSession();

  void Terminate();

  void Done();

  boost::asio::ip::tcp::socket& GetSocket() {
    return m_Socket;
  }

  bool IsEstablished() const {
    return m_IsEstablished;
  }

  /// @brief Starts client NTCP session (local router -> external router)
  void StartClientSession();

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
  const std::string GetFormattedSessionInfo() const {
    std::ostringstream info;
    info << " [" << GetRemoteIdentHashAbbreviation() << "] ";
    // Only display the endpoint if it is available
    // TODO: is there a better way to check if the endpoint is initialized?
    if (m_RemoteEndpoint.port())
      info << GetRemoteEndpoint() << ' ';

    return info.str();
  }

  /// @return Current session's peer's ident hash
  const std::string& GetRemoteIdentHashAbbreviation() const {
    return m_RemoteIdentHashAbbreviation;
  }

  /// @return Current session's endpoint address/port
  const boost::asio::ip::tcp::endpoint& GetRemoteEndpoint() const {
    return m_RemoteEndpoint;
  }

 private:
  void PostI2NPMessages(
      std::vector<std::shared_ptr<I2NPMessage>> msgs);

  void Connected();

  void SendTimeSyncMessage();

  void SetIsEstablished(
      bool is_established) {
    m_IsEstablished = is_established;
  }

  void CreateAESKey(
      std::uint8_t* pub_key,
      kovri::core::AESKey& key);

  // TODO(anonimal): simplify phase impl/handler

  void SendPhase1();

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
      std::uint32_t ts_A);

  void HandlePhase4Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::uint32_t ts_A);

  // Server
  void SendPhase2();

  void SendPhase4(
      std::uint32_t ts_A,
      std::uint32_t ts_B);

  void HandlePhase1Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred);

  void HandlePhase2Sent(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::uint32_t ts_B);

  void HandlePhase3Received(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::uint32_t ts_B);

  void HandlePhase3ExtraReceived(
      const boost::system::error_code& ecode,
      std::size_t bytes_transferred,
      std::uint32_t ts_B,
      std::size_t padding_len);

  void HandlePhase3(
      std::uint32_t ts_B,
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
      std::shared_ptr<kovri::core::I2NPMessage> msg);

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

  /// @enum Phase
  /// @brief Phases for NTCP session
  enum struct Phase : std::uint8_t { One, Two, Three, Four };

  /// @brief Returns phase info
  const std::string GetFormattedPhaseInfo(Phase num);

 private:
  std::string m_RemoteIdentHashAbbreviation;

  NTCPServer& m_Server;
  boost::asio::ip::tcp::socket m_Socket;
  boost::asio::ip::tcp::endpoint m_RemoteEndpoint;
  boost::asio::deadline_timer m_TerminationTimer;
  bool m_IsEstablished, m_IsTerminated;

  kovri::core::CBCDecryption m_Decryption;
  kovri::core::CBCEncryption m_Encryption;

  /// @enum NTCPSize
  enum NTCPSize : std::uint16_t {
    PubKey     = DHKeySize::PubKey,  // DH (X, Y)
    Hash        = 32,
    Padding     = 12,
    SessionKey = 32,
    IV          = 16,
    Adler32     = 4,
    // TODO(unassigned):
    // Through release of java 0.9.15, the router identity was always 387 bytes,
    // the signature was always a 40 byte DSA signature, and the padding was always 15 bytes.
    // As of release java 0.9.16, the router identity may be longer than 387 bytes,
    // and the signature type and length are implied by the type of the Signing Public Key in Alice's Router Identity.
    // The padding is as necessary to a multiple of 16 bytes for the entire unencrypted contents.
    Phase3AliceRI  = 2,
    Phase3AliceTS  = 4,
    Phase3Padding   = 15,
    Phase3Signature = 40,
    Phase3Unencrypted =
      Phase3AliceRI +
      kovri::core::DEFAULT_IDENTITY_SIZE +  // 387
      Phase3AliceTS +
      Phase3Padding +
      Phase3Signature,  // Total = 448
    MaxMessage = 16378,  // Spec defined as 16 KB - 6 (16378 bytes)
    Buffer = 4160,  // fits 4 tunnel messages (4 * 1028)
  };

  // TODO(unassigned): is packing necessary?
  // If so, should we not be consistent with other protocols?
  #pragma pack(1)
  struct NTCPPhase1 {
    // @brief Diffie-Hellman X
    std::array<std::uint8_t, NTCPSize::PubKey> pub_key;

    /// @brief Hash of DH-X XOR'd with Bob's Ident Hash
    std::array<std::uint8_t, NTCPSize::Hash> HXxorHI;
  };

  struct NTCPPhase2 {
    std::array<std::uint8_t, NTCPSize::PubKey> pub_key;
    struct {
      std::array<std::uint8_t, NTCPSize::Hash> hxy;
      std::uint32_t timestamp;
      std::array<std::uint8_t, NTCPSize::Padding> padding;
    } encrypted;
  };
  #pragma pack()

  struct Establisher {
    NTCPPhase1 phase1;
    NTCPPhase2 phase2;
  };

  std::unique_ptr<Establisher> m_Establisher;

  /// @brief Hash of Diffie-Hellman X
  std::array<std::uint8_t, NTCPSize::Hash> m_HX;

  kovri::core::AESAlignedBuffer<NTCPSize::Buffer + NTCPSize::IV> m_ReceiveBuffer;
  kovri::core::AESAlignedBuffer<NTCPSize::IV> m_TimeSyncBuffer;

  std::size_t m_ReceiveBufferOffset;

  std::shared_ptr<I2NPMessage> m_NextMessage;
  std::size_t m_NextMessageOffset;
  kovri::core::I2NPMessagesHandler m_Handler;

  bool m_IsSending;
  std::vector<std::shared_ptr<I2NPMessage>> m_SendQueue;

  kovri::core::Exception m_Exception;
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_TRANSPORTS_NTCP_SESSION_H_
