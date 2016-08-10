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

#include "ntcp_session.h"

#include <stdlib.h>
#include <string.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "i2np_protocol.h"
#include "ntcp.h"
#include "net_db.h"
#include "router_context.h"
#include "transports.h"
#include "crypto/diffie_hellman.h"
#include "crypto/hash.h"
#include "crypto/rand.h"
#include "crypto/util/checksum.h"
#include "util/base64.h"
#include "util/i2p_endian.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace transport {

NTCPSession::NTCPSession(
    NTCPServer& server,
    std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter)
    : TransportSession(in_RemoteRouter),
      m_Server(server),
      m_Socket(m_Server.GetService()),
      m_TerminationTimer(m_Server.GetService()),
      m_IsEstablished(false),
      m_IsTerminated(false),
      m_ReceiveBufferOffset(0),
      m_NextMessage(nullptr),
      m_NextMessageOffset(0),
      m_IsSending(false) {
  m_DHKeysPair = transports.GetNextDHKeysPair();
  m_Establisher = std::make_unique<Establisher>();
}

NTCPSession::~NTCPSession() {}

// TODO(unassigned): unfinished
void NTCPSession::ServerLogin() {
  auto error_code = SetRemoteEndpoint();
  if (!error_code) {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(), "--> Phase1, receiving");
    boost::asio::async_read(
        m_Socket,
        boost::asio::buffer(
            &m_Establisher->phase1,
            sizeof(NTCPPhase1)),
        boost::asio::transfer_all(),
        std::bind(
            &NTCPSession::HandlePhase1Received,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2));
    ScheduleTermination();
  } else {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! ServerLogin(): '", error_code.message(), "'");
  }
}

/**
 *
 * Phase1: SessionRequest
 *
 */

void NTCPSession::ClientLogin() {
  // Set shortened ident hash for logging
  SetRemoteIdentHashAbbreviation();
  // Set endpoint
  auto ecode = SetRemoteEndpoint();
  if (!ecode) {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(), "*** Phase1, preparing");
    if (!m_DHKeysPair) {
      LogPrint(eLogDebug,
          "NTCPSession:", GetFormattedSessionInfo(),
          "*** Phase1, acquiring DH keys pair");
      m_DHKeysPair = transports.GetNextDHKeysPair();
    }
    const std::uint8_t* x = m_DHKeysPair->public_key.data();
    memcpy(
        m_Establisher->phase1.pub_key.data(),
        x,
        static_cast<std::size_t>(NTCPSize::pub_key));
    i2p::crypto::SHA256().CalculateDigest(
        m_Establisher->phase1.HXxorHI.data(),
        x,
        static_cast<std::size_t>(NTCPSize::pub_key));
    const std::uint8_t* ident = m_RemoteIdentity.GetIdentHash();
    for (std::size_t i = 0; i < static_cast<std::size_t>(NTCPSize::hash); i++)
      m_Establisher->phase1.HXxorHI.at(i) ^= ident[i];
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(), "<-- Phase1, sending");
    boost::asio::async_write(
        m_Socket,
        boost::asio::buffer(
            &m_Establisher->phase1,
            sizeof(NTCPPhase1)),
        boost::asio::transfer_all(),
        std::bind(
            &NTCPSession::HandlePhase1Sent,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2));
    ScheduleTermination();
  } else {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! ClientLogin(): '", ecode.message(), "'");
  }
}

void NTCPSession::HandlePhase1Sent(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/) {
  if (ecode) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! couldn't send Phase1 '", ecode.message(), "'");
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "--> Phase1 sent, receiving");
    boost::asio::async_read(
        m_Socket,
        boost::asio::buffer(
            &m_Establisher->phase2,
            sizeof(NTCPPhase2)),
        boost::asio::transfer_all(),
        std::bind(
            &NTCPSession::HandlePhase2Received,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2));
  }
}

void NTCPSession::HandlePhase1Received(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/) {
  if (ecode) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! Phase1 receive error '", ecode.message(), "'");
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "*** Phase1 received, verifying ident");
    std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::hash)> digest;
    i2p::crypto::SHA256().CalculateDigest(
        digest.data(),
        m_Establisher->phase1.pub_key.data(),
        static_cast<std::size_t>(NTCPSize::pub_key));
    const std::uint8_t* ident = i2p::context.GetRouterInfo().GetIdentHash();
    for (std::size_t i = 0; i < static_cast<std::size_t>(NTCPSize::hash); i++) {
      if ((m_Establisher->phase1.HXxorHI.at(i) ^ ident[i]) != digest.at(i)) {
        LogPrint(eLogError,
            "NTCPSession:", GetFormattedSessionInfo(),
            "!!! HandlePhase1Received(): wrong ident");
        Terminate();
        return;
      }
    }
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "*** Phase1 successful, proceeding to Phase2");
    SendPhase2();
  }
}

/**
 *
 * Phase2: SessionCreated
 *
 */

void NTCPSession::SendPhase2() {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "*** Phase2, preparing");
  if (!m_DHKeysPair) {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "*** Phase2, acquiring DH keys pair");
    m_DHKeysPair = transports.GetNextDHKeysPair();
  }
  const std::uint8_t* y = m_DHKeysPair->public_key.data();
  memcpy(
      m_Establisher->phase2.pub_key.data(),
      y,
      static_cast<std::size_t>(NTCPSize::pub_key));
  // Combine DH key size for hxy
  std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::pub_key) * 2> xy;
  memcpy(
      xy.data(),
      m_Establisher->phase1.pub_key.data(),
      static_cast<std::size_t>(NTCPSize::pub_key));
  memcpy(
      xy.data() + static_cast<std::size_t>(NTCPSize::pub_key),
      y,
      static_cast<std::size_t>(NTCPSize::pub_key));
  i2p::crypto::SHA256().CalculateDigest(
      m_Establisher->phase2.encrypted.hxy.data(),
      xy.data(),
      static_cast<std::size_t>(NTCPSize::pub_key) * 2);
  std::uint32_t tsB = htobe32(i2p::util::GetSecondsSinceEpoch());
  m_Establisher->phase2.encrypted.timestamp = tsB;
  i2p::crypto::RandBytes(
      m_Establisher->phase2.encrypted.padding.data(),
      static_cast<std::size_t>(NTCPSize::padding));
  i2p::crypto::AESKey aesKey;
  CreateAESKey(m_Establisher->phase1.pub_key.data(), aesKey);
  m_Encryption.SetKey(aesKey);
  m_Encryption.SetIV(y + 240);
  m_Decryption.SetKey(aesKey);
  m_Decryption.SetIV(
      m_Establisher->phase1.HXxorHI.data() +
        static_cast<std::size_t>(NTCPSize::iv));
  m_Encryption.Encrypt(
      reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted),
      sizeof(m_Establisher->phase2.encrypted),
      reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted));
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "<-- Phase2, sending");
  boost::asio::async_write(
      m_Socket,
      boost::asio::buffer(
          &m_Establisher->phase2,
          sizeof(NTCPPhase2)),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase2Sent,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2,
          tsB));
}

void NTCPSession::HandlePhase2Sent(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/,
    std::uint32_t tsB) {
  if (ecode) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "*** couldn't send Phase2: '", ecode.message(), "'");
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "--> Phase2 sent, receiving Phase3");
    boost::asio::async_read(
        m_Socket,
        boost::asio::buffer(
            m_ReceiveBuffer,
            static_cast<std::size_t>(NTCPSize::phase3_unencrypted)),
        boost::asio::transfer_all(),
        std::bind(
            &NTCPSession::HandlePhase3Received,
            shared_from_this(),
            std::placeholders::_1,
            std::placeholders::_2,
            tsB));
  }
}

void NTCPSession::HandlePhase2Received(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/) {
  if (ecode) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! Phase2 read error '", ecode.message(), "'");
    if (ecode != boost::asio::error::operation_aborted) {
      LogPrint(eLogError,
          "NTCPSession:", GetFormattedSessionInfo(),
          "!!! Phase2 error, RI is not valid");
      i2p::data::netdb.SetUnreachable(
          GetRemoteIdentity().GetIdentHash(),
          true);
      transports.ReuseDHKeysPair(std::move(m_DHKeysPair));
      m_DHKeysPair.reset(nullptr);
      Terminate();
    }
  } else {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "*** Phase2 received, processing");
    i2p::crypto::AESKey aes_key;
    CreateAESKey(m_Establisher->phase2.pub_key.data(), aes_key);
    m_Decryption.SetKey(aes_key);
    // TODO(unassigned): document 240
    m_Decryption.SetIV(m_Establisher->phase2.pub_key.data() + 240);
    m_Encryption.SetKey(aes_key);
    m_Encryption.SetIV(
        m_Establisher->phase1.HXxorHI.data() +
          static_cast<std::size_t>(NTCPSize::iv));
    m_Decryption.Decrypt(
        reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted),
        sizeof(m_Establisher->phase2.encrypted),
        reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted));
    // Verify
    std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::pub_key) * 2> xy;
    memcpy(
        xy.data(),
        m_DHKeysPair->public_key.data(),
        static_cast<std::size_t>(NTCPSize::pub_key));
    memcpy(
        xy.data() + static_cast<std::size_t>(NTCPSize::pub_key),
        m_Establisher->phase2.pub_key.data(),
        static_cast<std::size_t>(NTCPSize::pub_key));
    if (!i2p::crypto::SHA256().VerifyDigest(
          m_Establisher->phase2.encrypted.hxy.data(),
          xy.data(),
          static_cast<std::size_t>(NTCPSize::pub_key) * 2)) {
      LogPrint(eLogError,
          "NTCPSession:", GetFormattedSessionInfo(),
          "!!! Phase2, incorrect hash");
      transports.ReuseDHKeysPair(std::move(m_DHKeysPair));
      m_DHKeysPair.reset(nullptr);
      Terminate();
      return;
    }
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "*** Phase2 successful, proceeding to Phase3");
    SendPhase3();
  }
}

void NTCPSession::CreateAESKey(
    std::uint8_t* pub_key,
    i2p::crypto::AESKey& key) {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "*** creating shared key");
  i2p::crypto::DiffieHellman dh;
  std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::pub_key)> shared_key;
  if (!dh.Agree(shared_key.data(), m_DHKeysPair->private_key.data(), pub_key)) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! couldn't create shared key");
    Terminate();
    return;
  }
  std::uint8_t* aes_key = key;
  if (shared_key.at(0) & 0x80) {
    aes_key[0] = 0;
    memcpy(
        aes_key + 1,
        shared_key.data(),
        static_cast<std::size_t>(NTCPSize::session_key) - 1);
  } else if (shared_key.at(0)) {
    memcpy(
        aes_key,
        shared_key.data(),
        static_cast<std::size_t>(NTCPSize::session_key));
  } else {
    // Find first non-zero byte
    std::uint8_t* non_zero = shared_key.data() + 1;
    while (!*non_zero) {
      non_zero++;
      if (non_zero - shared_key.data() >
          static_cast<std::uint8_t>(NTCPSize::pub_key)) {
        LogPrint(eLogWarn,
            "NTCPSession:", GetFormattedSessionInfo(),
            "*** first 32 bytes of shared key is all zeros. Ignored");
        return;
      }
    }
    memcpy(aes_key, non_zero, static_cast<std::size_t>(NTCPSize::session_key));
  }
}

/**
 *
 * Phase3: SessionConfirm A
 *
 */

void NTCPSession::SendPhase3() {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "*** Phase3, preparing");
  auto keys = i2p::context.GetPrivateKeys();
  std::uint8_t* buf = m_ReceiveBuffer;
  htobe16buf(buf, keys.GetPublic().GetFullLen());
  buf += static_cast<std::size_t>(NTCPSize::phase3_alice_ri);
  buf +=
    i2p::context.GetIdentity().ToBuffer(
        buf,
        static_cast<std::size_t>(NTCPSize::buffer));
  std::uint32_t tsA = htobe32(i2p::util::GetSecondsSinceEpoch());
  htobuf32(buf, tsA);
  buf += static_cast<std::size_t>(NTCPSize::phase3_alice_ts);
  std::size_t signature_len = keys.GetPublic().GetSignatureLen();
  std::size_t len = (buf - m_ReceiveBuffer) + signature_len;
  std::size_t padding_size = len & 0x0F;  // %16
  if (padding_size > 0) {
    padding_size = static_cast<std::size_t>(NTCPSize::iv) - padding_size;
    i2p::crypto::RandBytes(buf, padding_size);
    buf += padding_size;
    len += padding_size;
  }
  SignedData s;
  s.Insert(
      m_Establisher->phase1.pub_key.data(),
      static_cast<std::size_t>(NTCPSize::pub_key));  // x
  s.Insert(
      m_Establisher->phase2.pub_key.data(),
      static_cast<std::size_t>(NTCPSize::pub_key));  // y
  s.Insert(
      m_RemoteIdentity.GetIdentHash(),
      static_cast<std::size_t>(NTCPSize::hash));
  s.Insert(tsA);  // timestamp Alice
  s.Insert(m_Establisher->phase2.encrypted.timestamp);  // timestamp Bob
  s.Sign(keys, buf);
  m_Encryption.Encrypt(
      m_ReceiveBuffer,
      len,
      m_ReceiveBuffer);
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "<-- Phase3, sending");
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
          tsA));
}

void NTCPSession::HandlePhase3Sent(
    const boost::system::error_code& ecode,
    std::size_t /*bytes_transferred*/,
    std::uint32_t tsA) {
  if (ecode) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! couldn't send Phase3 '", ecode.message(), "'");
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "--> Phase3 sent, receiving Phase4");
    auto signature_len = m_RemoteIdentity.GetSignatureLen();
    std::size_t padding_size = signature_len & 0x0F;  // %16
    if (padding_size > 0)
      signature_len += (static_cast<std::size_t>(NTCPSize::iv) - padding_size);
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
            tsA));
  }
}

void NTCPSession::HandlePhase3Received(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::uint32_t tsB) {
  if (ecode) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! Phase3 read error '", ecode.message(), "'");
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "*** Phase3 received, processing");
    m_Decryption.Decrypt(
        m_ReceiveBuffer,
        bytes_transferred,
        m_ReceiveBuffer);
    std::uint8_t* buf = m_ReceiveBuffer;
    std::uint16_t size = bufbe16toh(buf);
    m_RemoteIdentity.FromBuffer(
        buf + static_cast<std::size_t>(NTCPSize::phase3_alice_ri),
        size);
    if (m_Server.FindNTCPSession(m_RemoteIdentity.GetIdentHash())) {
      LogPrint(eLogError,
          "NTCPSession:", GetFormattedSessionInfo(),
          "!!! Phase3, session already exists");
      Terminate();
    }
    std::size_t expected_size =
      size +
      static_cast<std::size_t>(NTCPSize::phase3_alice_ri) +
      static_cast<std::size_t>(NTCPSize::phase3_alice_ts) +
      m_RemoteIdentity.GetSignatureLen();
    std::size_t padding_len = expected_size & 0x0F;
    if (padding_len)
      padding_len = (16 - padding_len);
    if (expected_size > static_cast<std::size_t>(NTCPSize::phase3_unencrypted)) {
      LogPrint(eLogDebug,
          "NTCPSession:", GetFormattedSessionInfo(),
          "*** Phase3, we need more bytes, reading more");
      expected_size += padding_len;
      boost::asio::async_read(
          m_Socket,
          boost::asio::buffer(
              m_ReceiveBuffer +
                static_cast<std::size_t>(NTCPSize::phase3_unencrypted),
              expected_size),
          boost::asio::transfer_all(),
          std::bind(
              &NTCPSession::HandlePhase3ExtraReceived,
              shared_from_this(),
              std::placeholders::_1,
              std::placeholders::_2,
              tsB,
              padding_len));
    } else {
      HandlePhase3(tsB, padding_len);
    }
  }
}

void NTCPSession::HandlePhase3ExtraReceived(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::uint32_t tsB,
    std::size_t padding_len) {
  if (ecode) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! Phase3, extra read error '", ecode.message(), "'");
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    m_Decryption.Decrypt(
        m_ReceiveBuffer +
          static_cast<std::size_t>(NTCPSize::phase3_unencrypted),
        bytes_transferred,
        m_ReceiveBuffer +
          static_cast<std::size_t>(NTCPSize::phase3_unencrypted));
    HandlePhase3(tsB, padding_len);
  }
}

void NTCPSession::HandlePhase3(
    std::uint32_t tsB,
    std::size_t padding_len) {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "*** Phase3, handling");
  std::uint8_t* buf =
    m_ReceiveBuffer +
    m_RemoteIdentity.GetFullLen() +
    static_cast<std::size_t>(NTCPSize::phase3_alice_ri);
  std::uint32_t tsA = buf32toh(buf);
  buf += static_cast<std::size_t>(NTCPSize::phase3_alice_ts);
  buf += padding_len;
  SignedData s;
  s.Insert(
      m_Establisher->phase1.pub_key.data(),
      static_cast<std::size_t>(NTCPSize::pub_key));  // x
  s.Insert(
      m_Establisher->phase2.pub_key.data(),
      static_cast<std::size_t>(NTCPSize::pub_key));  // y
  s.Insert(
      i2p::context.GetRouterInfo().GetIdentHash(),
      static_cast<std::size_t>(NTCPSize::hash));
  s.Insert(tsA);
  s.Insert(tsB);
  if (!s.Verify(m_RemoteIdentity, buf)) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! Phase3, signature verification failed");
    Terminate();
    return;
  }
  m_RemoteIdentity.DropVerifier();
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(),
      "*** Phase3 successful, proceeding to Phase4");
  SendPhase4(tsA, tsB);
}

/**
 *
 * Phase4: SessionConfirm B
 *
 */

void NTCPSession::SendPhase4(
    std::uint32_t tsA,
    std::uint32_t tsB) {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "*** Phase4, preparing");
  SignedData s;
  s.Insert(
      m_Establisher->phase1.pub_key.data(),
      static_cast<std::size_t>(NTCPSize::pub_key));  // x
  s.Insert(
      m_Establisher->phase2.pub_key.data(),
      static_cast<std::size_t>(NTCPSize::pub_key));  // y
  s.Insert(
      m_RemoteIdentity.GetIdentHash(),
      static_cast<std::size_t>(NTCPSize::hash));
  s.Insert(tsA);
  s.Insert(tsB);
  auto keys = i2p::context.GetPrivateKeys();
  auto signature_len = keys.GetPublic().GetSignatureLen();
  s.Sign(keys, m_ReceiveBuffer);
  std::size_t padding_size = signature_len & 0x0F;  // %16
  if (padding_size > 0)
    signature_len += (static_cast<std::size_t>(NTCPSize::iv) - padding_size);
  m_Encryption.Encrypt(
      m_ReceiveBuffer,
      signature_len,
      m_ReceiveBuffer);
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "<-- Phase4, sending");
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
    LogPrint(eLogWarn,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! couldn't send Phase4 '", ecode.message(), "'");
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(), "*** Phase4 sent");
    m_Server.AddNTCPSession(shared_from_this());
    Connected();
    m_ReceiveBufferOffset = 0;
    m_NextMessage = nullptr;
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(), "--> Phase4, receiving");
    ReceivePayload();
  }
}

void NTCPSession::HandlePhase4Received(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::uint32_t tsA) {
  if (ecode) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! Phase4 read error '", ecode.message(), "', check your clock");
    if (ecode != boost::asio::error::operation_aborted) {
      LogPrint(eLogError,
          "NTCPSession:", GetFormattedSessionInfo(),
          "!!! Phase4, remote router does not like us");
      i2p::data::netdb.SetUnreachable(GetRemoteIdentity().GetIdentHash(), true);
      Terminate();
    }
  } else {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "*** Phase4 received, processing ", bytes_transferred, " bytes");
    m_Decryption.Decrypt(m_ReceiveBuffer, bytes_transferred, m_ReceiveBuffer);
    // Verify signature
    SignedData s;
    s.Insert(
        m_Establisher->phase1.pub_key.data(),
        static_cast<std::size_t>(NTCPSize::pub_key));  // x
    s.Insert(
        m_Establisher->phase2.pub_key.data(),
        static_cast<std::size_t>(NTCPSize::pub_key));  // y
    s.Insert(
        i2p::context.GetRouterInfo().GetIdentHash(),
        static_cast<std::size_t>(NTCPSize::hash));
    s.Insert(tsA);  // Timestamp Alice
    s.Insert(m_Establisher->phase2.encrypted.timestamp);  // Timestamp Bob
    if (!s.Verify(m_RemoteIdentity, m_ReceiveBuffer)) {
      LogPrint(eLogError,
          "NTCPSession:", GetFormattedSessionInfo(),
          "!!! Phase4 signature verification failed");
      Terminate();
      return;
    }
    m_RemoteIdentity.DropVerifier();
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "*** Phase4, session connected");
    Connected();
    m_ReceiveBufferOffset = 0;
    m_NextMessage = nullptr;
    ReceivePayload();
  }
}

/**
 *
 * SessionEstablished
 *
 */

void NTCPSession::Connected() {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(),
      "*** processing connected session");
  m_IsEstablished = true;
  m_Establisher.reset(nullptr);
  m_DHKeysPair.reset(nullptr);
  SendTimeSyncMessage();
  // We tell immediately who we are
  m_SendQueue.push_back(CreateDatabaseStoreMsg());
  transports.PeerConnected(shared_from_this());
}

void NTCPSession::ReceivePayload() {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(),
      "--> receiving payload");
  boost::asio::async_read(
      m_Socket,
      boost::asio::buffer(
          m_ReceiveBuffer + m_ReceiveBufferOffset,
          static_cast<std::size_t>(NTCPSize::buffer) - m_ReceiveBufferOffset),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandleReceivedPayload,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
}

void NTCPSession::HandleReceivedPayload(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred) {
  if (ecode) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! HandleReceivedPayload(): '", ecode.message(), "'");
    if (!m_NumReceivedBytes) {
      // Ban peer
      LogPrint(eLogInfo,
          "NTCPSession:", GetFormattedSessionInfo(), "!!! banning");
      m_Server.Ban(shared_from_this());
    }
    // if (ecode != boost::asio::error::operation_aborted)
    Terminate();
  } else {
    m_NumReceivedBytes += bytes_transferred;
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "--> ", bytes_transferred, " bytes transferred, ",
        GetNumReceivedBytes(), " total bytes received");
    i2p::transport::transports.UpdateReceivedBytes(bytes_transferred);
    m_ReceiveBufferOffset += bytes_transferred;
    if (m_ReceiveBufferOffset >= static_cast<std::size_t>(NTCPSize::iv)) {
      std::size_t num_reloads = 0;
      do {
        std::uint8_t* next_block = m_ReceiveBuffer;
        while (m_ReceiveBufferOffset >= static_cast<std::size_t>(NTCPSize::iv)) {
          if (!DecryptNextBlock(next_block)) {  // 16 bytes
            Terminate();
            return;
          }
          next_block += static_cast<std::size_t>(NTCPSize::iv);
          m_ReceiveBufferOffset -= static_cast<std::size_t>(NTCPSize::iv);
        }
        if (m_ReceiveBufferOffset > 0)
          memcpy(m_ReceiveBuffer, next_block, m_ReceiveBufferOffset);
        // Try to read more
        if (num_reloads < 5) {  // TODO(unassigned): document 5
          boost::system::error_code ec;
          std::size_t more_bytes = m_Socket.available(ec);
          if (more_bytes) {
            if (more_bytes >
                static_cast<std::size_t>(NTCPSize::buffer) - m_ReceiveBufferOffset)
              more_bytes =
                static_cast<std::size_t>(NTCPSize::buffer) - m_ReceiveBufferOffset;
            more_bytes = m_Socket.read_some(
                boost::asio::buffer(
                  m_ReceiveBuffer + m_ReceiveBufferOffset,
                  more_bytes));
            if (ec) {
              LogPrint(eLogError,
                  "NTCPSession:", GetFormattedSessionInfo(),
                  "!!! HandleReceivedPayload(): read more bytes error '",
                  ec.message(), "'");
              Terminate();
              return;
            }
            m_NumReceivedBytes += more_bytes;
            m_ReceiveBufferOffset += more_bytes;
            num_reloads++;
          }
        }
      }
      while (m_ReceiveBufferOffset >= static_cast<std::size_t>(NTCPSize::iv));
      m_Handler.Flush();
    }
    ScheduleTermination();  // Reset termination timer
    ReceivePayload();
  }
}

bool NTCPSession::DecryptNextBlock(
    const std::uint8_t* encrypted) {  // 16 bytes
  // New message, header expected
  if (!m_NextMessage) {
    // Decrypt header and extract length
    std::array<std::uint8_t, static_cast<std::size_t>(NTCPSize::iv)> buf;
    m_Decryption.Decrypt(encrypted, buf.data());
    std::uint16_t data_size = bufbe16toh(buf.data());
    if (data_size) {
      // New message
      if (data_size > static_cast<std::size_t>(NTCPSize::max_message)) {
        LogPrint(eLogError,
            "NTCPSession:", GetFormattedSessionInfo(),
            "!!! data block size '", data_size, "' exceeds max size");
        return false;
      }
      auto msg =
        data_size <=
          I2NP_MAX_SHORT_MESSAGE_SIZE -
          static_cast<std::size_t>(NTCPSize::phase3_alice_ri) ?
            NewI2NPShortMessage() :
            NewI2NPMessage();
      m_NextMessage = ToSharedI2NPMessage(msg);
      memcpy(
          m_NextMessage->buf,
          buf.data(),
          static_cast<std::size_t>(NTCPSize::iv));
      m_NextMessageOffset =
        static_cast<std::size_t>(NTCPSize::iv);
      m_NextMessage->offset =
        static_cast<std::size_t>(NTCPSize::phase3_alice_ri);  // size field
      m_NextMessage->len =
        data_size + static_cast<std::size_t>(NTCPSize::phase3_alice_ri);
    } else {
      // Timestamp
      LogPrint(eLogDebug,
          "NTCPSession:", GetFormattedSessionInfo(), "*** timestamp");
      return true;
    }
  } else {  // Message continues
    m_Decryption.Decrypt(
        encrypted,
        m_NextMessage->buf + m_NextMessageOffset);
    m_NextMessageOffset += static_cast<std::size_t>(NTCPSize::iv);
  }
  if (m_NextMessageOffset >=
      m_NextMessage->len + static_cast<std::size_t>(NTCPSize::adler32)) {
    // We have a complete I2NP message
    if (i2p::crypto::util::Adler32().VerifyDigest(
          m_NextMessage->buf +
            m_NextMessageOffset - static_cast<std::size_t>(NTCPSize::adler32),
          m_NextMessage->buf,
          m_NextMessageOffset - static_cast<std::size_t>(NTCPSize::adler32)))
      m_Handler.PutNextMessage(m_NextMessage);
    else
      LogPrint(eLogWarn,
          "NTCPSession:", GetFormattedSessionInfo(),
          "!!! incorrect Adler checksum of NTCP message, dropped");
    m_NextMessage = nullptr;
  }
  return true;
}

void NTCPSession::SendPayload(
    std::shared_ptr<i2p::I2NPMessage> msg) {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "<-- sending I2NP message");
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

boost::asio::const_buffers_1 NTCPSession::CreateMsgBuffer(
    std::shared_ptr<I2NPMessage> msg) {
  std::uint8_t* send_buffer;
  int len;
  if (msg) {
    // Regular I2NP
    if (msg->offset < static_cast<std::size_t>(NTCPSize::phase3_alice_ri))
      LogPrint(eLogError,
          "NTCPSession:", GetFormattedSessionInfo(),
          "!!! malformed I2NP message");  // TODO(unassigned): Error handling
    send_buffer =
      msg->GetBuffer() - static_cast<std::size_t>(NTCPSize::phase3_alice_ri);
    len = msg->GetLength();
    htobe16buf(send_buffer, len);
  } else {
    // Prepare timestamp
    send_buffer = m_TimeSyncBuffer;
    len = static_cast<std::size_t>(NTCPSize::phase3_alice_ts);
    htobuf16(send_buffer, 0);
    htobe32buf(
        send_buffer + static_cast<std::size_t>(NTCPSize::phase3_alice_ts),
        time(0));
  }
  int rem = (len + 6) & 0x0F;  // %16
  int padding = 0;
  if (rem > 0) {
    padding = static_cast<std::size_t>(NTCPSize::iv) - rem;
    i2p::crypto::RandBytes(
        send_buffer + len + static_cast<std::size_t>(NTCPSize::phase3_alice_ts),
        padding);
  }
  i2p::crypto::util::Adler32().CalculateDigest(
      send_buffer + len +
        static_cast<std::size_t>(NTCPSize::phase3_alice_ri) + padding,
      send_buffer,
      len + static_cast<std::size_t>(NTCPSize::phase3_alice_ri) + padding);
  int l = len + padding + 6;
  m_Encryption.Encrypt(send_buffer, l, send_buffer);
  return boost::asio::buffer(static_cast<const std::uint8_t *>(send_buffer), l);
}

void NTCPSession::SendTimeSyncMessage() {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "<-- sending TimeSyncMessage");
  SendPayload(nullptr);
}

void NTCPSession::SendPayload(
    const std::vector<std::shared_ptr<I2NPMessage>>& msgs) {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "<-- sending I2NP messages");
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

void NTCPSession::HandleSentPayload(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::vector<std::shared_ptr<I2NPMessage>> /*msgs*/) {
  m_IsSending = false;
  if (ecode) {
    LogPrint(eLogWarn,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! couldn't send I2NP messages, error '", ecode.message(), "'");
    // TODO(unassigned):
    // we shouldn't call Terminate () here, because HandleReceive takes care
    // 'delete this' statement in Terminate() must be eliminated later
    //Terminate();
  } else {
    m_NumSentBytes += bytes_transferred;
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(),
        "<-- ", bytes_transferred, " bytes transferred, ",
        GetNumSentBytes(), " total bytes sent");
    i2p::transport::transports.UpdateSentBytes(bytes_transferred);
    if (!m_SendQueue.empty()) {
      SendPayload(m_SendQueue);
      m_SendQueue.clear();
    } else {
      ScheduleTermination();  // Reset termination timer
    }
  }
}

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
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "*** scheduling termination");
  m_TerminationTimer.cancel();
  m_TerminationTimer.expires_from_now(
      boost::posix_time::seconds(
          static_cast<std::size_t>(NTCPTimeoutLength::termination)));
  m_TerminationTimer.async_wait(
      std::bind(
          &NTCPSession::HandleTerminationTimer,
          shared_from_this(),
          std::placeholders::_1));
}

void NTCPSession::HandleTerminationTimer(
    const boost::system::error_code& ecode) {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(),
      "*** handling termination timer");
  if (ecode != boost::asio::error::operation_aborted) {
    LogPrint(eLogError,
        "NTCPSession:", GetFormattedSessionInfo(),
        "!!! no activity for '",
        static_cast<std::size_t>(NTCPTimeoutLength::termination), "' seconds");
    // Terminate();
    m_Socket.close();  // invoke Terminate() from HandleReceive
  }
}

void NTCPSession::Done() {
  LogPrint(eLogDebug,
      "NTCPSession:", GetFormattedSessionInfo(), "*** done with session");
  m_Server.GetService().post(
      std::bind(
          &NTCPSession::Terminate,
          shared_from_this()));
}

void NTCPSession::Terminate() {
  if (!m_IsTerminated) {
    LogPrint(eLogDebug,
        "NTCPSession:", GetFormattedSessionInfo(), "*** terminating session");
    m_IsTerminated = true;
    m_IsEstablished = false;
    m_Socket.close();
    transports.PeerDisconnected(shared_from_this());
    m_Server.RemoveNTCPSession(shared_from_this());
    m_SendQueue.clear();
    m_NextMessage = nullptr;
    m_TerminationTimer.cancel();
    LogPrint(eLogInfo,
        "NTCPSession:", GetFormattedSessionInfo(), "*** session terminated");
  }
}

}  // namespace transport
}  // namespace i2p
