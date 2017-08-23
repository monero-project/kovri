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

#include "core/router/transports/ntcp/session.h"

#include <stdlib.h>
#include <string.h>

#include <vector>

#include "core/crypto/diffie_hellman.h"
#include "core/crypto/hash.h"
#include "core/crypto/rand.h"
#include "core/crypto/util/checksum.h"

#include "core/router/context.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/ntcp/server.h"
#include "core/router/transports/impl.h"

#include "core/util/base64.h"
#include "core/util/byte_stream.h"
#include "core/util/i2p_endian.h"
#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {

NTCPSession::NTCPSession(
    NTCPServer& server,
    std::shared_ptr<const kovri::core::RouterInfo> remote_router)
    : TransportSession(remote_router),
      m_Server(server),
      m_Socket(m_Server.GetService()),
      m_TerminationTimer(m_Server.GetService()),
      m_IsEstablished(false),
      m_IsTerminated(false),
      m_ReceiveBufferOffset(0),
      m_NextMessage(nullptr),
      m_NextMessageOffset(0),
      m_IsSending(false),
      m_Exception(__func__) {
  m_DHKeysPair = transports.GetNextDHKeysPair();
  m_Establisher = std::make_unique<Establisher>();
  if (remote_router) {
    // Set shortened ident hash and remote endpoint for logging
    SetRemoteIdentHashAbbreviation();
  }
}

NTCPSession::~NTCPSession() {}

/**
 *
 * Client (local router -> external router)
 *
 */

void NTCPSession::StartClientSession()
{
  // Set endpoint
  const auto& ecode = SetRemoteEndpoint();
  if (ecode)
    {
      LOG(error) << "NTCPSession:" << GetFormattedSessionInfo() << "!!! "
                 << __func__ << ": '" << ecode.message() << "'";
      return;
    }
  try
    {
      SendPhase1();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      // TODO(anonimal): ensure exception handling by caller
      throw;
    }
}

// Phase1: SessionRequest

void NTCPSession::SendPhase1()
{
  LOG(debug) << "NTCPSession:" << GetFormattedSessionInfo()
             << "*** Phase1, preparing";

  if (!m_DHKeysPair)
    {
      LOG(debug) << "NTCPSession:" << GetFormattedSessionInfo()
                 << "*** Phase1, acquiring DH keys pair";
      m_DHKeysPair = transports.GetNextDHKeysPair();
      if (!m_DHKeysPair)
        throw std::runtime_error("acquired null DH keypair");
    }

  // X as calculated from Diffie-Hellman
  m_Establisher->phase1.pub_key = m_DHKeysPair->public_key;

  // SHA256 hash(X)
  kovri::core::SHA256().CalculateDigest(
      m_HX.data(),
      m_Establisher->phase1.pub_key.data(),
      m_Establisher->phase1.pub_key.size());

  // HXxorHI: get SHA256 hash(Bob's ident) and XOR against SHA256 hash(X)
  for (std::size_t i = 0; i < m_HX.size(); i++)
    m_Establisher->phase1.HXxorHI.at(i) =
        m_HX.at(i) ^ m_RemoteIdentity.GetIdentHash()[i];

  LOG(trace) << "NTCPSession:" << GetFormattedSessionInfo()
             << GetFormattedPhaseInfo(Phase::One);

  // Send phase1
  LOG(debug) << "NTCPSession:" << GetFormattedSessionInfo()
             << "<-- Phase1, sending";

  boost::asio::async_write(
      m_Socket,
      boost::asio::buffer(
          &m_Establisher->phase1, sizeof(m_Establisher->phase1)),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase1Sent,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));

  ScheduleTermination();
}

void NTCPSession::HandlePhase1Sent(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/) {
  if (ecode) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! couldn't send Phase1 '" << ecode.message() << "'";
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
    return;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "--> Phase1 sent, receiving";
  boost::asio::async_read(
      m_Socket,
      boost::asio::buffer(
          &m_Establisher->phase2,
          sizeof(m_Establisher->phase2)),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase2Received,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
}

// Phase2: SessionCreated

void NTCPSession::HandlePhase2Received(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/) {
  if (ecode) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! Phase2 read error '" << ecode.message() << "'";
    if (ecode != boost::asio::error::operation_aborted) {
      LOG(error)
        << "NTCPSession:" << GetFormattedSessionInfo()
        << "!!! Phase2 error, RI is not valid";
      LOG(trace)
        << "NTCPSession:" << GetFormattedSessionInfo()
        << GetFormattedPhaseInfo(Phase::Two);
      kovri::core::netdb.SetUnreachable(
          GetRemoteIdentity().GetIdentHash(),
          true);
      transports.ReuseDHKeysPair(std::move(m_DHKeysPair));
      m_DHKeysPair.reset(nullptr);
      Terminate();
    }
    return;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** Phase2 received, processing";
  LOG(trace)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "Encrypted " << GetFormattedPhaseInfo(Phase::Two);
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    kovri::core::AESKey aes_key;
    CreateAESKey(m_Establisher->phase2.pub_key.data(), aes_key);
    m_Decryption.SetKey(aes_key);
    m_Decryption.SetIV(m_Establisher->phase2.pub_key.data() + NTCPSize::Phase2BobIVOffset);
    m_Encryption.SetKey(aes_key);
    m_Encryption.SetIV(m_Establisher->phase1.HXxorHI.data() + NTCPSize::IV);
    m_Decryption.Decrypt(
        reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted),
        sizeof(m_Establisher->phase2.encrypted),
        reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted));
    // Verify
    std::array<std::uint8_t, NTCPSize::PubKey * 2> xy;
    memcpy(
        xy.data(),
        m_DHKeysPair->public_key.data(),
        NTCPSize::PubKey);
    memcpy(
        xy.data() + NTCPSize::PubKey,
        m_Establisher->phase2.pub_key.data(),
        NTCPSize::PubKey);
    if (!kovri::core::SHA256().VerifyDigest(
          m_Establisher->phase2.encrypted.hxy.data(),
          xy.data(),
          NTCPSize::PubKey * 2)) {
      LOG(error)
        << "NTCPSession:" << GetFormattedSessionInfo()
        << "!!! Phase2 << incorrect hash";
      LOG(trace)
        << "NTCPSession:" << GetFormattedSessionInfo()
        << "Decrypted " << GetFormattedPhaseInfo(Phase::Two);
      transports.ReuseDHKeysPair(std::move(m_DHKeysPair));
      m_DHKeysPair.reset(nullptr);
      Terminate();
      return;
    }
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  LOG(trace)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "Decrypted " << GetFormattedPhaseInfo(Phase::Two);
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** Phase2 successful, proceeding to Phase3";
  SendPhase3();
}

void NTCPSession::CreateAESKey(
    std::uint8_t* pub_key,
    kovri::core::AESKey& key) {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "*** creating shared key";
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    kovri::core::DiffieHellman dh;
    std::array<std::uint8_t, NTCPSize::PubKey> shared_key;
    if (!dh.Agree(shared_key.data(), m_DHKeysPair->private_key.data(), pub_key)) {
      LOG(error)
        << "NTCPSession:" << GetFormattedSessionInfo()
        << "!!! couldn't create shared key";
      Terminate();
      return;
    }
    std::uint8_t* aes_key = key;
    if (shared_key.at(0) & 0x80) {
      aes_key[0] = 0;
      memcpy(
          aes_key + 1,
          shared_key.data(),
          NTCPSize::SessionKey - 1);
    } else if (shared_key.at(0)) {
      memcpy(
          aes_key,
          shared_key.data(),
          NTCPSize::SessionKey);
    } else {
      // Find first non-zero byte
      std::uint8_t* non_zero = shared_key.data() + 1;
      while (!*non_zero) {
        non_zero++;
        if (non_zero - shared_key.data() > NTCPSize::PubKey) {
          LOG(warning) <<
              "NTCPSession:" << GetFormattedSessionInfo()
              << "*** first 32 bytes of shared key is all zeros. Ignored";
          return;
        }
      }
      memcpy(aes_key, non_zero, NTCPSize::SessionKey);
    }
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

// Phase3: SessionConfirm A

void NTCPSession::SendPhase3() {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "*** Phase3, preparing";
  auto keys = kovri::context.GetPrivateKeys();
  std::uint8_t* buf = m_ReceiveBuffer;
  htobe16buf(buf, keys.GetPublic().GetFullLen());
  buf += NTCPSize::Phase3AliceRI;
  buf += kovri::context.GetIdentity().ToBuffer(buf, NTCPSize::Buffer);
  std::uint32_t ts_A = htobe32(kovri::core::GetSecondsSinceEpoch());
  htobuf32(buf, ts_A);
  buf += NTCPSize::Phase3AliceTS;
  std::size_t signature_len = keys.GetPublic().GetSignatureLen();
  std::size_t len = (buf - m_ReceiveBuffer) + signature_len;
  std::size_t padding_size = len & 0x0F;  // %16
  if (padding_size) {
    padding_size = NTCPSize::IV - padding_size;
    kovri::core::RandBytes(buf, padding_size);
    buf += padding_size;
    len += padding_size;
  }
  SignedData s;
  s.Insert(m_Establisher->phase1.pub_key.data(), NTCPSize::PubKey);  // X
  s.Insert(m_Establisher->phase2.pub_key.data(), NTCPSize::PubKey);  // Y
  s.Insert(m_RemoteIdentity.GetIdentHash(), NTCPSize::Hash);
  s.Insert(ts_A);  // timestamp Alice
  s.Insert(m_Establisher->phase2.encrypted.timestamp);  // timestamp Bob
  s.Sign(keys, buf);
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    m_Encryption.Encrypt(m_ReceiveBuffer, len, m_ReceiveBuffer);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "<-- Phase3, sending";
  boost::asio::async_write(
      m_Socket,
      boost::asio::buffer(
          m_ReceiveBuffer,
          len),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase3Sent,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2,
          ts_A));
}

void NTCPSession::HandlePhase3Sent(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/,
    std::uint32_t ts_A) {
  if (ecode) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! couldn't send Phase3 '" << ecode.message() << "'";
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
    return;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "--> Phase3 sent, receiving Phase4";
  auto signature_len = m_RemoteIdentity.GetSignatureLen();
  std::size_t padding_size = signature_len & 0x0F;  // %16
  if (padding_size)
    signature_len += (NTCPSize::IV - padding_size);
  boost::asio::async_read(
      m_Socket,
      boost::asio::buffer(
          m_ReceiveBuffer,
          signature_len),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase4Received,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2,
          ts_A));
}

// Phase4: SessionConfirm B

void NTCPSession::HandlePhase4Received(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::uint32_t ts_A) {
  if (ecode) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! Phase4 read error '" << ecode.message() << "',  check your clock";  // TODO(anonimal): error message
    if (ecode != boost::asio::error::operation_aborted) {
      LOG(error)
        << "NTCPSession:" << GetFormattedSessionInfo()
        << "!!! Phase4, remote router does not like us";
      kovri::core::netdb.SetUnreachable(GetRemoteIdentity().GetIdentHash(), true);
      Terminate();
    }
    return;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** Phase4 received << processing " << bytes_transferred << " bytes";
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    m_Decryption.Decrypt(m_ReceiveBuffer, bytes_transferred, m_ReceiveBuffer);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  // Verify signature
  SignedData s;
  s.Insert(m_Establisher->phase1.pub_key.data(), NTCPSize::PubKey);  // x
  s.Insert(m_Establisher->phase2.pub_key.data(), NTCPSize::PubKey);  // y
  s.Insert(kovri::context.GetRouterInfo().GetIdentHash(), NTCPSize::Hash);
  s.Insert(ts_A);  // Timestamp Alice
  s.Insert(m_Establisher->phase2.encrypted.timestamp);  // Timestamp Bob
  if (!s.Verify(m_RemoteIdentity, m_ReceiveBuffer)) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! Phase4 signature verification failed";
    Terminate();
    return;
  }
  m_RemoteIdentity.DropVerifier();
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** Phase4, session connected";
  Connected();
  m_ReceiveBufferOffset = 0;
  m_NextMessage = nullptr;
  ReceivePayload();
}

// TODO(unassigned): fix / review
/**
 *
 * Server (external router -> local router)
 *
 */

// Phase1: SessionRequest

void NTCPSession::ServerLogin() {
  const auto& ecode = SetRemoteEndpoint();
  if (ecode) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! " << __func__ << ": '" << ecode.message() << "'";
    LOG(trace)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << GetFormattedPhaseInfo(Phase::One);
    return;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "--> Phase1, receiving";
  boost::asio::async_read(
      m_Socket,
      boost::asio::buffer(
          &m_Establisher->phase1,
          sizeof(m_Establisher->phase1)),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase1Received,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
  ScheduleTermination();
}

void NTCPSession::HandlePhase1Received(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/) {
  if (ecode) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! Phase1 receive error '" << ecode.message() << "'";
    if (ecode != boost::asio::error::operation_aborted) {
      LOG(trace)
        << "NTCPSession:" << GetFormattedSessionInfo()
        << GetFormattedPhaseInfo(Phase::One);
      Terminate();
    }
    return;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** Phase1 received, verifying ident";
  std::array<std::uint8_t, NTCPSize::Hash> digest;
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    kovri::core::SHA256().CalculateDigest(
        digest.data(),
        m_Establisher->phase1.pub_key.data(),
        NTCPSize::PubKey);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  const std::uint8_t* ident = kovri::context.GetRouterInfo().GetIdentHash();
  for (std::size_t i = 0; i < NTCPSize::Hash; i++) {
    if ((m_Establisher->phase1.HXxorHI.at(i) ^ ident[i]) != digest.at(i)) {
      LOG(error)
        << "NTCPSession:" << GetFormattedSessionInfo()
        << "!!! " << __func__ << ": wrong ident";
      LOG(trace)
        << "NTCPSession:" << GetFormattedSessionInfo()
        << GetFormattedPhaseInfo(Phase::One);
      Terminate();
      return;
    }
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** Phase1 successful, proceeding to Phase2";
  SendPhase2();
}

// Phase2: SessionCreated

void NTCPSession::SendPhase2() {
  LOG(debug) <<
      "NTCPSession:" << GetFormattedSessionInfo() << "*** Phase2, preparing";
  if (!m_DHKeysPair) {
    LOG(debug)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "*** Phase2, acquiring DH keys pair";
    m_DHKeysPair = transports.GetNextDHKeysPair();
  }
  // Y from Diffie Hellman
  const std::uint8_t* y = m_DHKeysPair->public_key.data();
  memcpy(
      m_Establisher->phase2.pub_key.data(),
      y,
      NTCPSize::PubKey);
  // Combine DH key size for hxy
  std::array<std::uint8_t, NTCPSize::PubKey * 2> xy;
  memcpy(
      xy.data(),
      m_Establisher->phase1.pub_key.data(),
      NTCPSize::PubKey);
  memcpy(
      xy.data() + NTCPSize::PubKey,
      y,
      NTCPSize::PubKey);
  // Timestamp B
  std::uint32_t ts_B{};
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    // Hash of XY
    kovri::core::SHA256().CalculateDigest(
        m_Establisher->phase2.encrypted.hxy.data(),
        xy.data(),
        NTCPSize::PubKey * 2);
    // Set timestamp B
    ts_B = htobe32(kovri::core::GetSecondsSinceEpoch());
    m_Establisher->phase2.encrypted.timestamp = ts_B;
    // Random padding
    kovri::core::RandBytes(
        m_Establisher->phase2.encrypted.padding.data(),
        NTCPSize::Padding);
    // AES key
    kovri::core::AESKey aes_key;
    CreateAESKey(m_Establisher->phase1.pub_key.data(), aes_key);
    m_Encryption.SetKey(aes_key);
    m_Encryption.SetIV(y + NTCPSize::Phase2BobIVOffset);
    m_Decryption.SetKey(aes_key);
    m_Decryption.SetIV(m_Establisher->phase1.HXxorHI.data() + NTCPSize::IV);
    m_Encryption.Encrypt(
        reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted),
        sizeof(m_Establisher->phase2.encrypted),
        reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted));
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "<-- Phase2, sending";
  boost::asio::async_write(
      m_Socket,
      boost::asio::buffer(
          &m_Establisher->phase2,
          sizeof(m_Establisher->phase2)),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase2Sent,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2,
          ts_B));
}

void NTCPSession::HandlePhase2Sent(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/,
    std::uint32_t ts_B) {
  if (ecode) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "*** couldn't send Phase2: '" << ecode.message() << "'";
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
    return;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "--> Phase2 sent, receiving Phase3";
  boost::asio::async_read(
      m_Socket,
      boost::asio::buffer(
          m_ReceiveBuffer,
          NTCPSize::Phase3Unencrypted),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase3Received,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2,
          ts_B));
}

// Phase3: SessionConfirm A

void NTCPSession::HandlePhase3Received(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::uint32_t ts_B) {
  if (ecode) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! Phase3 read error '" << ecode.message() << "'";
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
    return;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** Phase3 received, processing";
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    m_Decryption.Decrypt(m_ReceiveBuffer, bytes_transferred, m_ReceiveBuffer);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  std::uint8_t* buf = m_ReceiveBuffer;
  std::uint16_t size = bufbe16toh(buf);
  m_RemoteIdentity.FromBuffer(buf + NTCPSize::Phase3AliceRI, size);
  if (m_Server.FindNTCPSession(m_RemoteIdentity.GetIdentHash())) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! Phase3, session already exists";
    Terminate();
    // TODO(unassigned): return?
  }
  std::size_t expected_size = size
    + NTCPSize::Phase3AliceRI
    + NTCPSize::Phase3AliceTS
    + m_RemoteIdentity.GetSignatureLen();
  std::size_t padding_len = expected_size & 0x0F;
  if (padding_len)
    padding_len = (16 - padding_len);
  if (expected_size > NTCPSize::Phase3Unencrypted) {
    LOG(debug)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "*** Phase3, we need more bytes, reading more";
    expected_size += padding_len;
    boost::asio::async_read(
        m_Socket,
        boost::asio::buffer(
            m_ReceiveBuffer + NTCPSize::Phase3Unencrypted,
            expected_size),
        boost::asio::transfer_all(),
        std::bind(
            &NTCPSession::HandlePhase3ExtraReceived,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2,
            ts_B,
            padding_len));
  } else {
    HandlePhase3(ts_B, padding_len);
  }
}

void NTCPSession::HandlePhase3ExtraReceived(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::uint32_t ts_B,
    std::size_t padding_len) {
  if (ecode) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! Phase3 << extra read error '" << ecode.message() << "'";
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
    return;
  }
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    m_Decryption.Decrypt(
        m_ReceiveBuffer + NTCPSize::Phase3Unencrypted,
        bytes_transferred,
        m_ReceiveBuffer + NTCPSize::Phase3Unencrypted);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  HandlePhase3(ts_B, padding_len);
}

void NTCPSession::HandlePhase3(
    std::uint32_t ts_B,
    std::size_t padding_len) {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "*** Phase3, handling";
  std::uint8_t* buf = m_ReceiveBuffer
    + m_RemoteIdentity.GetFullLen()
    + NTCPSize::Phase3AliceRI;
  std::uint32_t ts_A = buf32toh(buf);
  buf += NTCPSize::Phase3AliceTS;
  buf += padding_len;
  SignedData s;
  s.Insert(m_Establisher->phase1.pub_key.data(), NTCPSize::PubKey);  // X
  s.Insert(m_Establisher->phase2.pub_key.data(), NTCPSize::PubKey);  // Y
  s.Insert(kovri::context.GetRouterInfo().GetIdentHash(), NTCPSize::Hash);
  s.Insert(ts_A);
  s.Insert(ts_B);
  if (!s.Verify(m_RemoteIdentity, buf)) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! Phase3, signature verification failed";
    Terminate();
    return;
  }
  m_RemoteIdentity.DropVerifier();
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** Phase3 successful, proceeding to Phase4";
  SendPhase4(ts_A, ts_B);
}

// Phase4: SessionConfirm B

void NTCPSession::SendPhase4(
    std::uint32_t ts_A,
    std::uint32_t ts_B) {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "*** Phase4, preparing";
  SignedData s;
  s.Insert(m_Establisher->phase1.pub_key.data(), NTCPSize::PubKey);  // X
  s.Insert(m_Establisher->phase2.pub_key.data(), NTCPSize::PubKey);  // Y
  s.Insert(m_RemoteIdentity.GetIdentHash(), NTCPSize::Hash);
  s.Insert(ts_A);
  s.Insert(ts_B);
  auto keys = kovri::context.GetPrivateKeys();
  auto signature_len = keys.GetPublic().GetSignatureLen();
  s.Sign(keys, m_ReceiveBuffer);
  std::size_t padding_size = signature_len & 0x0F;  // %16
  if (padding_size)
    signature_len += (NTCPSize::IV - padding_size);
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    m_Encryption.Encrypt(m_ReceiveBuffer, signature_len, m_ReceiveBuffer);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "<-- Phase4, sending";
  boost::asio::async_write(
      m_Socket,
      boost::asio::buffer(
          m_ReceiveBuffer,
          signature_len),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase4Sent,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
}

void NTCPSession::HandlePhase4Sent(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/) {
  if (ecode) {
    LOG(warning)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! couldn't send Phase4 '" << ecode.message() << "'";
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
    return;
  }
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "*** Phase4 sent";
  m_Server.AddNTCPSession(shared_from_this());
  Connected();
  m_ReceiveBufferOffset = 0;
  m_NextMessage = nullptr;
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "--> Phase4, receiving";
  ReceivePayload();
}

/**
 *
 * SessionEstablished
 *
 */

void NTCPSession::Connected() {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** processing connected session";
  m_IsEstablished = true;
  m_Establisher.reset(nullptr);
  m_DHKeysPair.reset(nullptr);
  SendTimeSyncMessage();
  // We tell immediately who we are
  m_SendQueue.push_back(CreateDatabaseStoreMsg());
  transports.PeerConnected(shared_from_this());
}

// Send

void NTCPSession::SendTimeSyncMessage() {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "<-- sending TimeSyncMessage";
  SendPayload(nullptr);
}

void NTCPSession::SendPayload(
    std::shared_ptr<kovri::core::I2NPMessage> msg) {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "<-- sending I2NP message";
  m_IsSending = true;
  boost::asio::async_write(
      m_Socket,
      CreateMsgBuffer(msg),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandleSentPayload,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2,
          std::vector<std::shared_ptr<I2NPMessage> >{ msg }));
}

void NTCPSession::HandleSentPayload(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::vector<std::shared_ptr<I2NPMessage>> /*msgs*/) {
  m_IsSending = false;
  if (ecode) {
    LOG(warning)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! couldn't send I2NP messages: '" << ecode.message() << "'";
    // TODO(unassigned):
    // we shouldn't call Terminate () here, because HandleReceive takes care
    // 'delete this' statement in Terminate() must be eliminated later
    //Terminate();
    return;
  }
  m_NumSentBytes += bytes_transferred;
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "<-- " << bytes_transferred << " bytes transferred << "
    << GetNumSentBytes() << " total bytes sent";
  kovri::core::transports.UpdateSentBytes(bytes_transferred);
  if (!m_SendQueue.empty()) {
    SendPayload(m_SendQueue);
    m_SendQueue.clear();
  } else {
    ScheduleTermination();  // Reset termination timer
  }
}

void NTCPSession::SendPayload(
    const std::vector<std::shared_ptr<I2NPMessage>>& msgs) {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "<-- sending I2NP messages";
  m_IsSending = true;
  std::vector<boost::asio::const_buffer> bufs;
  for (auto it : msgs)
    bufs.push_back(CreateMsgBuffer(it));
  boost::asio::async_write(
      m_Socket,
      bufs,
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandleSentPayload,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2,
          msgs));
}

boost::asio::const_buffers_1 NTCPSession::CreateMsgBuffer(
    std::shared_ptr<I2NPMessage> msg) {
  std::uint8_t* send_buffer;
  // TODO(anonimal): no signed integers
  int len{}, encrypted_len{};
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    if (msg) {
      // Regular I2NP
      if (msg->offset < NTCPSize::Phase3AliceRI) {
        LOG(error)
          << "NTCPSession:" << GetFormattedSessionInfo()
          << "!!! malformed I2NP message";  // TODO(unassigned): Error handling
      }
      send_buffer = msg->GetBuffer() - NTCPSize::Phase3AliceRI;
      len = msg->GetLength();
      htobe16buf(send_buffer, len);
    } else {
      // Prepare timestamp
      send_buffer = m_TimeSyncBuffer;
      len = NTCPSize::Phase3AliceTS;
      htobuf16(send_buffer, 0);
      htobe32buf(send_buffer + NTCPSize::Phase3AliceTS, time(0));
    }
    int rem = (len + 6) & 0x0F;  // %16
    int padding = 0;
    if (rem) {
      padding = NTCPSize::IV - rem;
      kovri::core::RandBytes(
          send_buffer + len + NTCPSize::Phase3AliceTS,
          padding);
    }
    kovri::core::Adler32().CalculateDigest(
        send_buffer + len + NTCPSize::Phase3AliceRI + padding,
        send_buffer,
        len + NTCPSize::Phase3AliceRI + padding);
    encrypted_len = len + padding + 6;
    m_Encryption.Encrypt(send_buffer, encrypted_len, send_buffer);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  return boost::asio::buffer(static_cast<const std::uint8_t *>(send_buffer), encrypted_len);
}

// Receive

void NTCPSession::ReceivePayload() {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "--> receiving payload";
  boost::asio::async_read(
      m_Socket,
      boost::asio::buffer(
          m_ReceiveBuffer + m_ReceiveBufferOffset,
          NTCPSize::Buffer - m_ReceiveBufferOffset),
      boost::asio::transfer_at_least(NTCPSize::IV),
      std::bind(
          &NTCPSession::HandleReceivedPayload,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
}

void NTCPSession::HandleReceivedPayload(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred) {
  // EOF and zero bytes transferred implies that everything has been read and
  //  the remote has closed to connnection
  if (ecode == boost::asio::error::eof && bytes_transferred == 0) {
    Terminate();
    return;
  }
  // EOF errors are expected for short messages, so ignoring them here is fine
  if (ecode && (ecode != boost::asio::error::eof)) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! " << __func__ << ": '" << ecode.message() << "'";
    if (!m_NumReceivedBytes) {
      // Ban peer
      LOG(warning) << "NTCPSession:" << GetFormattedSessionInfo() << "!!! banning";
      m_Server.Ban(shared_from_this());
    }
    Terminate();
    return;
  }
  const std::size_t block_size = NTCPSize::IV;
  m_NumReceivedBytes += bytes_transferred;
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "--> " << bytes_transferred << " bytes transferred << "
    << GetNumReceivedBytes() << " total bytes received";
  kovri::core::transports.UpdateReceivedBytes(bytes_transferred);
  m_ReceiveBufferOffset += bytes_transferred;
  // Decrypt as many 16 byte blocks as possible
  std::uint8_t* next_block = m_ReceiveBuffer;
  while(m_ReceiveBufferOffset >= block_size) {
    // Try to decrypt one block
    if (!DecryptNextBlock(next_block)) {
      Terminate();
      return;
    }
    next_block += block_size;
    m_ReceiveBufferOffset -= block_size;
  }
  if (m_ReceiveBufferOffset) // Do we have an incomplete block?
    std::memcpy(m_ReceiveBuffer, next_block, m_ReceiveBufferOffset);
  // Flush and reset termination timer if a full message was read
  if (m_NextMessage == nullptr) {
    m_Handler.Flush();
    // EOF will terminate immediately, no need to reschedule
    if (ecode != boost::asio::error::eof)
      ScheduleTermination();
  }
  // Stop reading data if there was an EOF error (connection closed by remote).
  if (ecode == boost::asio::error::eof)
    Terminate();
  else
    ReceivePayload();
}

bool NTCPSession::DecryptNextBlock(
    const std::uint8_t* encrypted) {  // 16 bytes
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    // New message, header expected
    if (!m_NextMessage) {
      // Decrypt header and extract length
      std::array<std::uint8_t, NTCPSize::IV> buf;
      m_Decryption.Decrypt(encrypted, buf.data());
      std::uint16_t data_size = bufbe16toh(buf.data());
      if (data_size) {
        // New message
        if (data_size > NTCPSize::MaxMessage) {
          LOG(error)
            << "NTCPSession:" << GetFormattedSessionInfo()
            << "!!! data block size '" << data_size << "' exceeds max size";
          return false;
        }
        auto msg =
          data_size <=
            I2NP_MAX_SHORT_MESSAGE_SIZE -
            NTCPSize::Phase3AliceRI
              ? NewI2NPShortMessage()
              : NewI2NPMessage();
        m_NextMessage = ToSharedI2NPMessage(std::move(msg));
        memcpy(m_NextMessage->buf, buf.data(), NTCPSize::IV);
        m_NextMessageOffset = NTCPSize::IV;
        m_NextMessage->offset = NTCPSize::Phase3AliceRI;  // size field
        m_NextMessage->len = data_size + NTCPSize::Phase3AliceRI;
      } else {
        // Timestamp
        LOG(debug)
          << "NTCPSession:" << GetFormattedSessionInfo() << "*** timestamp";
        return true;
      }
    } else {  // Message continues
      m_Decryption.Decrypt(encrypted, m_NextMessage->buf + m_NextMessageOffset);
      m_NextMessageOffset += NTCPSize::IV;
    }
    if (m_NextMessageOffset >=
        m_NextMessage->len + NTCPSize::Adler32) {
      // We have a complete I2NP message
      if (kovri::core::Adler32().VerifyDigest(
            m_NextMessage->buf + m_NextMessageOffset - NTCPSize::Adler32,
            m_NextMessage->buf,
            m_NextMessageOffset - NTCPSize::Adler32))
        m_Handler.PutNextMessage(m_NextMessage);
      else
        LOG(warning)
          << "NTCPSession:" << GetFormattedSessionInfo()
          << "!!! incorrect Adler checksum of NTCP message, dropped";
      m_NextMessage = nullptr;
    }
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  return true;
}

// For transports impl

void NTCPSession::SendI2NPMessages(
    const std::vector<std::shared_ptr<I2NPMessage>>& msgs) {
  m_Server.GetService().post(
      std::bind(
          &NTCPSession::PostI2NPMessages,
          shared_from_this(),
          msgs));
}

void NTCPSession::PostI2NPMessages(
    std::vector<std::shared_ptr<I2NPMessage>> msgs) {
  if (m_IsTerminated)
    return;
  if (m_IsSending) {
    for (auto it : msgs)
      m_SendQueue.push_back(it);
  } else {
    SendPayload(msgs);
  }
}

/**
 *
 * SessionEnd
 *
 */

void NTCPSession::ScheduleTermination() {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "*** scheduling termination";
  m_TerminationTimer.cancel();
  m_TerminationTimer.expires_from_now(
      boost::posix_time::seconds(
          GetType(NTCPTimeoutLength::Termination)));
  m_TerminationTimer.async_wait(
      std::bind(
          &NTCPSession::HandleTerminationTimer,
          shared_from_this(),
          std::placeholders::_1));
}

void NTCPSession::HandleTerminationTimer(
    const boost::system::error_code& ecode) {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo()
    << "*** handling termination timer";
  if (ecode != boost::asio::error::operation_aborted) {
    LOG(error)
      << "NTCPSession:" << GetFormattedSessionInfo()
      << "!!! no activity for '"
      << GetType(NTCPTimeoutLength::Termination) << "' seconds";
    // Terminate();
    m_Socket.close();  // invoke Terminate() from HandleReceive
  }
}

void NTCPSession::Done() {
  LOG(debug)
    << "NTCPSession:" << GetFormattedSessionInfo() << "*** done with session";
  m_Server.GetService().post(
      std::bind(
          &NTCPSession::Terminate,
          shared_from_this()));
}

void NTCPSession::Terminate() {
  if (!m_IsTerminated) {
    LOG(debug)
       << "NTCPSession:" << GetFormattedSessionInfo() << "*** terminating session";
    m_IsTerminated = true;
    m_IsEstablished = false;
    boost::system::error_code ec;
    m_Socket.close(ec);
    transports.PeerDisconnected(shared_from_this());
    m_Server.RemoveNTCPSession(shared_from_this());
    m_SendQueue.clear();
    m_NextMessage = nullptr;
    m_TerminationTimer.cancel();
    LOG(debug)
      << "NTCPSession:" << GetFormattedSessionInfo() << "*** session terminated";
  }
}

// Utilities

const std::string NTCPSession::GetFormattedPhaseInfo(Phase num)
{
  if (!m_Establisher)
    return "*** null establisher";
  std::string info;
  switch (num)
    {
      case Phase::One:
        {
          info += "*** Phase1:\n";

          // X as calculated from Diffie-Hellman
          info += "\tDH X: ";
          const auto& pub_key = m_Establisher->phase1.pub_key;
          info += GetFormattedHex(pub_key.data(), pub_key.size());

          // SHA256 hash(X)
          info += "\tHash(X): ";
          info += GetFormattedHex(m_HX.data(), m_HX.size());

          // SHA256 hash(Bob's RouterIdentity)
          info += "\tHash(I): ";
          info +=
              GetFormattedHex(m_RemoteIdentity.GetIdentHash(), NTCPSize::Hash);

          // SHA256 hash(X) XOR'd with SHA256 hash(Bob's RouterIdentity)
          info += "\tHXxorHI: ";
          const auto& HXxorHI = m_Establisher->phase1.HXxorHI;
          info += GetFormattedHex(HXxorHI.data(), HXxorHI.size());
          break;
        }
      case Phase::Two:
        {
          // TODO(anonimal): finish

          info += "Phase2:\n";

          // Y as calculated from Diffie-Hellman
          const auto& pub_key = m_Establisher->phase2.pub_key;
          info += "\tDH Y: ";
          info += GetFormattedHex(pub_key.data(), pub_key.size());

          // TODO(anonimal): whether encrypted or not depends on placement of call

          // Hash of X concat with Y
          const auto& hxy = m_Establisher->phase2.encrypted.hxy;
          info += "\tHash(X+Y): ";
          info += GetFormattedHex(hxy.data(), hxy.size());

          // Bob's timestamp
          const auto ts_B = m_Establisher->phase2.encrypted.timestamp;
          info += "\tTimestamp B: ";
          info += GetFormattedHex(
              reinterpret_cast<const std::uint8_t*>(&ts_B), sizeof(ts_B));

          // Random padding
          const auto& rand = m_Establisher->phase2.encrypted.padding;
          info += "\tRandom padding: ";
          info += GetFormattedHex(rand.data(), rand.size());
          break;
        }
      // TODO(anonimal): finish
      case Phase::Three:
      case Phase::Four:
      default:
        break;
    };
  return info;
}

}  // namespace core
}  // namespace kovri
