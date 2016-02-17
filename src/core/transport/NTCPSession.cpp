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

#include "NTCPSession.h"

#include <cryptopp/adler32.h>
#include <cryptopp/dh.h>

#include <stdlib.h>
#include <string.h>

#include <vector>

#include "I2NPProtocol.h"
#include "NTCP.h"
#include "NetworkDatabase.h"
#include "RouterContext.h"
#include "Transports.h"
#include "crypto/Rand.h"
#include "crypto/CryptoConst.h"
#include "util/Base64.h"
#include "util/I2PEndian.h"
#include "util/Log.h"
#include "util/Timestamp.h"

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
      m_IsSending(false) {
  m_DHKeysPair = transports.GetNextDHKeysPair();
  m_Establisher = new Establisher;
}

NTCPSession::~NTCPSession() {
  delete m_Establisher;
}

void NTCPSession::CreateAESKey(
    std::uint8_t* pubKey,
    i2p::crypto::AESKey& key) {
  CryptoPP::DH dh(
      i2p::crypto::elgp,
      i2p::crypto::elgg);
  std::uint8_t sharedKey[NTCP_PUBKEY_SIZE];
  if (!dh.Agree(sharedKey, m_DHKeysPair->privateKey, pubKey)) {
    LogPrint(eLogError, "Couldn't create shared key");
    Terminate();
    return;
  }
  std::uint8_t* aesKey = key;
  if (sharedKey[0] & 0x80) {
    aesKey[0] = 0;
    memcpy(aesKey + 1, sharedKey, NTCP_SESSIONKEY_SIZE - 1);
  } else if (sharedKey[0]) {
    memcpy(aesKey, sharedKey, NTCP_SESSIONKEY_SIZE);
  } else {
    // find first non-zero byte
    std::uint8_t* nonZero = sharedKey + 1;
    while (!*nonZero) {
      nonZero++;
      if (nonZero - sharedKey > (std::uint8_t)NTCP_SESSIONKEY_SIZE) {
        LogPrint(eLogWarning,
            "First 32 bytes of shared key is all zeros. Ignored");
        return;
      }
    }
    memcpy(aesKey, nonZero, NTCP_SESSIONKEY_SIZE);
  }
}

void NTCPSession::Done() {
  m_Server.GetService().post(
      std::bind(
          &NTCPSession::Terminate,
          shared_from_this()));
}

void NTCPSession::Terminate() {
  if (!m_IsTerminated) {
    m_IsTerminated = true;
    m_IsEstablished = false;
    m_Socket.close();
    transports.PeerDisconnected(shared_from_this());
    m_Server.RemoveNTCPSession(shared_from_this());
    m_SendQueue.clear();
    m_NextMessage = nullptr;
    m_TerminationTimer.cancel();
    LogPrint(eLogInfo, "NTCP session terminated");
  }
}

void NTCPSession::Connected() {
  m_IsEstablished = true;
  delete m_Establisher;
  m_Establisher = nullptr;
  delete m_DHKeysPair;
  m_DHKeysPair = nullptr;
  SendTimeSyncMessage();
  // we tell immediately who we are
  m_SendQueue.push_back(CreateDatabaseStoreMsg());
  transports.PeerConnected(shared_from_this());
}

void NTCPSession::ClientLogin() {
  if (!m_DHKeysPair)
    m_DHKeysPair = transports.GetNextDHKeysPair();
  // send Phase1
  const std::uint8_t* x = m_DHKeysPair->publicKey;
  memcpy(
      m_Establisher->phase1.pubKey,
      x,
      NTCP_PUBKEY_SIZE);
  CryptoPP::SHA256().CalculateDigest(
      m_Establisher->phase1.HXxorHI,
      x,
      NTCP_PUBKEY_SIZE);
  const std::uint8_t* ident = m_RemoteIdentity.GetIdentHash();
  for (std::size_t i = 0; i < NTCP_HASH_SIZE; i++)
    m_Establisher->phase1.HXxorHI[i] ^= ident[i];
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
}

void NTCPSession::ServerLogin() {
  boost::system::error_code ec;
  auto ep = m_Socket.remote_endpoint(ec);
  if (!ec) {
    m_ConnectedFrom = ep.address();
    // receive Phase1
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
  }
}

void NTCPSession::HandlePhase1Sent(
    const boost::system::error_code& ecode,
    std::size_t) {
  if (ecode) {
    LogPrint(eLogError,
        "Couldn't send Phase 1 message: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
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
    std::size_t) {
  if (ecode) {
    LogPrint(eLogError,
        "Phase 1 read error: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    // verify ident
    std::uint8_t digest[NTCP_HASH_SIZE];
    CryptoPP::SHA256().CalculateDigest(
        digest,
        m_Establisher->phase1.pubKey,
        NTCP_PUBKEY_SIZE);
    const std::uint8_t* ident = i2p::context.GetRouterInfo().GetIdentHash();
    for (std::size_t i = 0; i < NTCP_HASH_SIZE; i++) {
      if ((m_Establisher->phase1.HXxorHI[i] ^ ident[i]) != digest[i]) {
        LogPrint(eLogError, "Wrong ident");
        Terminate();
        return;
      }
    }
    SendPhase2();
  }
}

void NTCPSession::SendPhase2() {
  if (!m_DHKeysPair)
    m_DHKeysPair = transports.GetNextDHKeysPair();
  const std::uint8_t* y = m_DHKeysPair->publicKey;
  memcpy(m_Establisher->phase2.pubKey, y, NTCP_PUBKEY_SIZE);
  std::uint8_t xy[NTCP_PUBKEY_SIZE * 2];  // Combined DH key size for hxy
  memcpy(xy, m_Establisher->phase1.pubKey, NTCP_PUBKEY_SIZE);
  memcpy(xy + NTCP_PUBKEY_SIZE, y, NTCP_PUBKEY_SIZE);
  CryptoPP::SHA256().CalculateDigest(
      m_Establisher->phase2.encrypted.hxy,
      xy,
      NTCP_PUBKEY_SIZE * 2);
  std::uint32_t tsB = htobe32(i2p::util::GetSecondsSinceEpoch());
  m_Establisher->phase2.encrypted.timestamp = tsB;
  i2p::crypto::RandBytes(
      m_Establisher->phase2.encrypted.padding,
      NTCP_PADDING_SIZE);
  i2p::crypto::AESKey aesKey;
  CreateAESKey(m_Establisher->phase1.pubKey, aesKey);
  m_Encryption.SetKey(aesKey);
  m_Encryption.SetIV(y + 240);
  m_Decryption.SetKey(aesKey);
  m_Decryption.SetIV(m_Establisher->phase1.HXxorHI + NTCP_IV_SIZE);
  m_Encryption.Encrypt(
      reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted),
      sizeof(m_Establisher->phase2.encrypted),
      reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted));
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
    std::size_t,
    std::uint32_t tsB) {
  if (ecode) {
    LogPrint(eLogError,
        "Couldn't send Phase 2 message: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    boost::asio::async_read(
        m_Socket,
        boost::asio::buffer(
            m_ReceiveBuffer,
            NTCP_PHASE3_UNENCRYPTED_SIZE),
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
    std::size_t) {
  if (ecode) {
    LogPrint(eLogError,
        "Phase 2 read error: ", ecode.message(), ". Wrong ident assumed");
    if (ecode != boost::asio::error::operation_aborted) {
      // this RI is not valid
      i2p::data::netdb.SetUnreachable(
          GetRemoteIdentity().GetIdentHash(),
          true);
      transports.ReuseDHKeysPair(m_DHKeysPair);
      m_DHKeysPair = nullptr;
      Terminate();
    }
  } else {
    i2p::crypto::AESKey aesKey;
    CreateAESKey(m_Establisher->phase2.pubKey, aesKey);
    m_Decryption.SetKey(aesKey);
    m_Decryption.SetIV(m_Establisher->phase2.pubKey + 240);
    m_Encryption.SetKey(aesKey);
    m_Encryption.SetIV(m_Establisher->phase1.HXxorHI + NTCP_IV_SIZE);
    m_Decryption.Decrypt(
        reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted),
        sizeof(m_Establisher->phase2.encrypted),
        reinterpret_cast<std::uint8_t *>(&m_Establisher->phase2.encrypted));
    // verify
    std::uint8_t xy[NTCP_PUBKEY_SIZE * 2];
    memcpy(
        xy,
        m_DHKeysPair->publicKey,
        NTCP_PUBKEY_SIZE);
    memcpy(
        xy + NTCP_PUBKEY_SIZE,
        m_Establisher->phase2.pubKey,
        NTCP_PUBKEY_SIZE);
    if (!CryptoPP::SHA256().VerifyDigest(
          m_Establisher->phase2.encrypted.hxy,
          xy,
          NTCP_PUBKEY_SIZE * 2)) {
      LogPrint(eLogError, "Incorrect hash");
      transports.ReuseDHKeysPair(m_DHKeysPair);
      m_DHKeysPair = nullptr;
      Terminate();
      return;
    }
    SendPhase3();
  }
}

void NTCPSession::SendPhase3() {
  auto keys = i2p::context.GetPrivateKeys();
  std::uint8_t* buf = m_ReceiveBuffer;
  htobe16buf(buf, keys.GetPublic().GetFullLen());
  buf += NTCP_PHASE3_ALICE_RI_SIZE;
  buf += i2p::context.GetIdentity().ToBuffer(buf, NTCP_BUFFER_SIZE);
  std::uint32_t tsA = htobe32(i2p::util::GetSecondsSinceEpoch());
  htobuf32(buf, tsA);
  buf += NTCP_PHASE3_ALICE_TS_SIZE;
  std::size_t signatureLen = keys.GetPublic().GetSignatureLen();
  std::size_t len = (buf - m_ReceiveBuffer) + signatureLen;
  std::size_t paddingSize = len & 0x0F;  // %16
  if (paddingSize > 0) {
    paddingSize = NTCP_IV_SIZE - paddingSize;
    i2p::crypto::RandBytes(buf, paddingSize);
    buf += paddingSize;
    len += paddingSize;
  }
  SignedData s;
  s.Insert(m_Establisher->phase1.pubKey, NTCP_PUBKEY_SIZE);  // x
  s.Insert(m_Establisher->phase2.pubKey, NTCP_PUBKEY_SIZE);  // y
  s.Insert(m_RemoteIdentity.GetIdentHash(), NTCP_HASH_SIZE);
  s.Insert(tsA);  // timestamp Alice
  s.Insert(m_Establisher->phase2.encrypted.timestamp);  // timestamp Bob
  s.Sign(keys, buf);
  m_Encryption.Encrypt(
      m_ReceiveBuffer,
      len,
      m_ReceiveBuffer);
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
    std::size_t,
    std::uint32_t tsA) {
  if (ecode) {
    LogPrint(eLogError,
        "Couldn't send Phase 3 message: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    // wait for phase4
    auto signatureLen = m_RemoteIdentity.GetSignatureLen();
    std::size_t paddingSize = signatureLen & 0x0F;  // %16
    if (paddingSize > 0)
      signatureLen += (NTCP_IV_SIZE - paddingSize);
    boost::asio::async_read(
        m_Socket,
        boost::asio::buffer(
            m_ReceiveBuffer,
            signatureLen),
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
    LogPrint(eLogError, "Phase 3 read error: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    m_Decryption.Decrypt(
        m_ReceiveBuffer,
        bytes_transferred,
        m_ReceiveBuffer);
    std::uint8_t* buf = m_ReceiveBuffer;
    uint16_t size = bufbe16toh(buf);
    m_RemoteIdentity.FromBuffer(buf + NTCP_PHASE3_ALICE_RI_SIZE, size);
    if (m_Server.FindNTCPSession(m_RemoteIdentity.GetIdentHash())) {
      LogPrint(eLogError, "NTCP session already exists");
      Terminate();
    }
    size_t expectedSize = size +
                          NTCP_PHASE3_ALICE_RI_SIZE +
                          NTCP_PHASE3_ALICE_TS_SIZE +
                          m_RemoteIdentity.GetSignatureLen();
    size_t paddingLen = expectedSize & 0x0F;
    if (paddingLen)
      paddingLen = (16 - paddingLen);
    if (expectedSize > NTCP_PHASE3_UNENCRYPTED_SIZE) {
      // we need more bytes for Phase3
      expectedSize += paddingLen;
      boost::asio::async_read(
          m_Socket,
          boost::asio::buffer(
              m_ReceiveBuffer + NTCP_PHASE3_UNENCRYPTED_SIZE,
              expectedSize),
          boost::asio::transfer_all(),
          std::bind(
              &NTCPSession::HandlePhase3ExtraReceived,
              shared_from_this(),
              std::placeholders::_1,
              std::placeholders::_2,
              tsB,
              paddingLen));
    } else {
      HandlePhase3(tsB, paddingLen);
    }
  }
}

void NTCPSession::HandlePhase3ExtraReceived(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::uint32_t tsB,
    std::size_t paddingLen) {
  if (ecode) {
    LogPrint(eLogError,
        "Phase 3 extra read error: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    m_Decryption.Decrypt(
        m_ReceiveBuffer + NTCP_PHASE3_UNENCRYPTED_SIZE,
        bytes_transferred,
        m_ReceiveBuffer+ NTCP_PHASE3_UNENCRYPTED_SIZE);
    HandlePhase3(tsB, paddingLen);
  }
}

void NTCPSession::HandlePhase3(
    std::uint32_t tsB,
    std::size_t paddingLen) {
  std::uint8_t* buf =
    m_ReceiveBuffer +
    m_RemoteIdentity.GetFullLen() +
    NTCP_PHASE3_ALICE_RI_SIZE;
  std::uint32_t tsA = buf32toh(buf);
  buf += NTCP_PHASE3_ALICE_TS_SIZE;
  buf += paddingLen;
  SignedData s;
  s.Insert(m_Establisher->phase1.pubKey, NTCP_PUBKEY_SIZE);  // x
  s.Insert(m_Establisher->phase2.pubKey, NTCP_PUBKEY_SIZE);  // y
  s.Insert(i2p::context.GetRouterInfo().GetIdentHash(), NTCP_HASH_SIZE);
  s.Insert(tsA);
  s.Insert(tsB);
  if (!s.Verify(m_RemoteIdentity, buf)) {
    LogPrint(eLogError, "signature verification failed");
    Terminate();
    return;
  }
  m_RemoteIdentity.DropVerifier();
  SendPhase4(tsA, tsB);
}

void NTCPSession::SendPhase4(
    std::uint32_t tsA,
    std::uint32_t tsB) {
  SignedData s;
  s.Insert(m_Establisher->phase1.pubKey, NTCP_PUBKEY_SIZE);  // x
  s.Insert(m_Establisher->phase2.pubKey, NTCP_PUBKEY_SIZE);  // y
  s.Insert(m_RemoteIdentity.GetIdentHash(), NTCP_HASH_SIZE);
  s.Insert(tsA);
  s.Insert(tsB);
  auto keys = i2p::context.GetPrivateKeys();
  auto signatureLen = keys.GetPublic().GetSignatureLen();
  s.Sign(keys, m_ReceiveBuffer);
  size_t paddingSize = signatureLen & 0x0F;  // %16
  if (paddingSize > 0)
    signatureLen += (NTCP_IV_SIZE - paddingSize);
  m_Encryption.Encrypt(
      m_ReceiveBuffer,
      signatureLen,
      m_ReceiveBuffer);
  boost::asio::async_write(
      m_Socket,
      boost::asio::buffer(
          m_ReceiveBuffer,
          signatureLen),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandlePhase4Sent,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
}

void NTCPSession::HandlePhase4Sent(
    const boost::system::error_code& ecode,
    std::size_t) {
  if (ecode) {
    LogPrint(eLogWarning,
        "Couldn't send Phase 4 message: ", ecode.message());
    if (ecode != boost::asio::error::operation_aborted)
      Terminate();
  } else {
    LogPrint(eLogInfo,
        "NTCP server session from ", m_Socket.remote_endpoint(), " connected");
    m_Server.AddNTCPSession(shared_from_this());
    Connected();
    m_ReceiveBufferOffset = 0;
    m_NextMessage = nullptr;
    Receive();
  }
}

void NTCPSession::HandlePhase4Received(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::uint32_t tsA) {
  if (ecode) {
    LogPrint(eLogError,
        "Phase 4 read error: ", ecode.message(), ". Check your clock");
    if (ecode != boost::asio::error::operation_aborted) {
       // this router doesn't like us
      i2p::data::netdb.SetUnreachable(GetRemoteIdentity().GetIdentHash(), true);
      Terminate();
    }
  } else {
    m_Decryption.Decrypt(m_ReceiveBuffer, bytes_transferred, m_ReceiveBuffer);
    // verify signature
    SignedData s;
    s.Insert(m_Establisher->phase1.pubKey, NTCP_PUBKEY_SIZE);  // x
    s.Insert(m_Establisher->phase2.pubKey, NTCP_PUBKEY_SIZE);  // y
    s.Insert(i2p::context.GetRouterInfo().GetIdentHash(), NTCP_HASH_SIZE);
    s.Insert(tsA);  // timestamp Alice
    s.Insert(m_Establisher->phase2.encrypted.timestamp);  // timestamp Bob
    if (!s.Verify(m_RemoteIdentity, m_ReceiveBuffer)) {
      LogPrint(eLogError, "signature verification failed");
      Terminate();
      return;
    }
    m_RemoteIdentity.DropVerifier();
    LogPrint(eLogInfo,
        "NTCP session to ", m_Socket.remote_endpoint(), " connected");
    Connected();
    m_ReceiveBufferOffset = 0;
    m_NextMessage = nullptr;
    Receive();
  }
}

void NTCPSession::Receive() {
  m_Socket.async_read_some(
      boost::asio::buffer(
          m_ReceiveBuffer + m_ReceiveBufferOffset,
          NTCP_BUFFER_SIZE - m_ReceiveBufferOffset),
      std::bind(
          &NTCPSession::HandleReceived,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2));
}

void NTCPSession::HandleReceived(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred) {
  if (ecode) {
    LogPrint(eLogError, "Read error: ", ecode.message());
    if (!m_NumReceivedBytes)
      m_Server.Ban(m_ConnectedFrom);
    // if (ecode != boost::asio::error::operation_aborted)
    Terminate();
  } else {
    m_NumReceivedBytes += bytes_transferred;
    i2p::transport::transports.UpdateReceivedBytes(bytes_transferred);
    m_ReceiveBufferOffset += bytes_transferred;
    if (m_ReceiveBufferOffset >= NTCP_IV_SIZE) {
      int numReloads = 0;
      do {
        std::uint8_t* nextBlock = m_ReceiveBuffer;
        while (m_ReceiveBufferOffset >= NTCP_IV_SIZE) {
          if (!DecryptNextBlock(nextBlock)) {  // 16 bytes
            Terminate();
            return;
          }
          nextBlock += NTCP_IV_SIZE;
          m_ReceiveBufferOffset -= NTCP_IV_SIZE;
        }
        if (m_ReceiveBufferOffset > 0)
          memcpy(m_ReceiveBuffer, nextBlock, m_ReceiveBufferOffset);
        // try to read more
        if (numReloads < 5) {
          boost::system::error_code ec;
          std::size_t moreBytes = m_Socket.available(ec);
          if (moreBytes) {
            if (moreBytes > NTCP_BUFFER_SIZE - m_ReceiveBufferOffset)
              moreBytes = NTCP_BUFFER_SIZE - m_ReceiveBufferOffset;
            moreBytes = m_Socket.read_some(
                boost::asio::buffer(
                  m_ReceiveBuffer + m_ReceiveBufferOffset,
                  moreBytes));
            if (ec) {
              LogPrint(eLogError, "Read more bytes error: ", ec.message());
              Terminate();
              return;
            }
            m_NumReceivedBytes += moreBytes;
            m_ReceiveBufferOffset += moreBytes;
            numReloads++;
          }
        }
      }
      while (m_ReceiveBufferOffset >= NTCP_IV_SIZE);
      m_Handler.Flush();
    }
    ScheduleTermination();  // reset termination timer
    Receive();
  }
}

bool NTCPSession::DecryptNextBlock(
    const std::uint8_t* encrypted) {  // 16 bytes
  if (!m_NextMessage) {  // new message, header expected
    // decrypt header and extract length
    std::uint8_t buf[NTCP_IV_SIZE];
    m_Decryption.Decrypt(encrypted, buf);
    uint16_t dataSize = bufbe16toh(buf);
    if (dataSize) {
      // new message
      if (dataSize > NTCP_MAX_MESSAGE_SIZE) {
        LogPrint(eLogError, "NTCP data size ", dataSize, " exceeds max size");
        return false;
      }
      auto msg =
        dataSize <= I2NP_MAX_SHORT_MESSAGE_SIZE - NTCP_PHASE3_ALICE_RI_SIZE ?
          NewI2NPShortMessage() :
          NewI2NPMessage();
      m_NextMessage = ToSharedI2NPMessage(msg);
      memcpy(m_NextMessage->buf, buf, NTCP_IV_SIZE);
      m_NextMessageOffset = NTCP_IV_SIZE;
      m_NextMessage->offset = NTCP_PHASE3_ALICE_RI_SIZE;  // size field
      m_NextMessage->len = dataSize + NTCP_PHASE3_ALICE_RI_SIZE;
    } else {
      // timestamp
      LogPrint("Timestamp");
      return true;
    }
  } else {  // message continues
    m_Decryption.Decrypt(
        encrypted,
        m_NextMessage->buf + m_NextMessageOffset);
    m_NextMessageOffset += NTCP_IV_SIZE;
  }
  if (m_NextMessageOffset >= m_NextMessage->len + NTCP_ADLER32_SIZE) {
    // we have a complete I2NP message
    if (CryptoPP::Adler32().VerifyDigest(
          m_NextMessage->buf + m_NextMessageOffset - NTCP_ADLER32_SIZE,
          m_NextMessage->buf,
          m_NextMessageOffset - NTCP_ADLER32_SIZE))
      m_Handler.PutNextMessage(m_NextMessage);
    else
      LogPrint(eLogWarning,
          "Incorrect Adler checksum of NTCP message. Dropped");
    m_NextMessage = nullptr;
  }
  return true;
}

void NTCPSession::Send(
    std::shared_ptr<i2p::I2NPMessage> msg) {
  m_IsSending = true;
  boost::asio::async_write(
      m_Socket,
      CreateMsgBuffer(msg),
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandleSent,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2,
          std::vector<std::shared_ptr<I2NPMessage> >{ msg }));
}

boost::asio::const_buffers_1 NTCPSession::CreateMsgBuffer(
    std::shared_ptr<I2NPMessage> msg) {
  std::uint8_t* sendBuffer;
  int len;
  if (msg) {
    // regular I2NP
    if (msg->offset < NTCP_PHASE3_ALICE_RI_SIZE)
      LogPrint(eLogError,
          "Malformed I2NP message");  // TODO(unassigned): Error handling
    sendBuffer = msg->GetBuffer() - NTCP_PHASE3_ALICE_RI_SIZE;
    len = msg->GetLength();
    htobe16buf(sendBuffer, len);
  } else {
    // prepare timestamp
    sendBuffer = m_TimeSyncBuffer;
    len = NTCP_PHASE3_ALICE_TS_SIZE;
    htobuf16(sendBuffer, 0);
    htobe32buf(sendBuffer + NTCP_PHASE3_ALICE_TS_SIZE, time(0));
  }
  int rem = (len + 6) & 0x0F;  // %16
  int padding = 0;
  if (rem > 0) {
    padding = NTCP_IV_SIZE - rem;
    i2p::crypto::RandBytes(
        sendBuffer + len + NTCP_PHASE3_ALICE_TS_SIZE,
        padding);
  }
  CryptoPP::Adler32().CalculateDigest(
      sendBuffer + len + NTCP_PHASE3_ALICE_RI_SIZE + padding,
      sendBuffer, len + NTCP_PHASE3_ALICE_RI_SIZE + padding);
  int l = len + padding + 6;
  m_Encryption.Encrypt(sendBuffer, l, sendBuffer);
  return boost::asio::buffer ((const std::uint8_t *)sendBuffer, l);
}

void NTCPSession::Send(
    const std::vector<std::shared_ptr<I2NPMessage> >& msgs) {
  m_IsSending = true;
  std::vector<boost::asio::const_buffer> bufs;
  for (auto it : msgs)
    bufs.push_back(CreateMsgBuffer(it));
  boost::asio::async_write(
      m_Socket,
      bufs,
      boost::asio::transfer_all(),
      std::bind(
          &NTCPSession::HandleSent,
          shared_from_this(),
          std::placeholders::_1,
          std::placeholders::_2, msgs));
}

void NTCPSession::HandleSent(
    const boost::system::error_code& ecode,
    std::size_t bytes_transferred,
    std::vector<std::shared_ptr<I2NPMessage> >) {
  m_IsSending = false;
  if (ecode) {
    LogPrint(eLogWarning, "Couldn't send msgs: ", ecode.message());
    // TODO(unassigned):
    // we shouldn't call Terminate () here, because HandleReceive takes care
    // 'delete this' statement in Terminate() must be eliminated later
    //Terminate();
  } else {
    m_NumSentBytes += bytes_transferred;
    i2p::transport::transports.UpdateSentBytes(bytes_transferred);
    if (!m_SendQueue.empty()) {
      Send(m_SendQueue);
      m_SendQueue.clear();
    } else {
      ScheduleTermination();  // reset termination timer
    }
  }
}

void NTCPSession::SendTimeSyncMessage() {
  Send(nullptr);
}

void NTCPSession::SendI2NPMessages(
    const std::vector<std::shared_ptr<I2NPMessage> >& msgs) {
  m_Server.GetService().post(
      std::bind(
          &NTCPSession::PostI2NPMessages,
          shared_from_this(),
          msgs));
}

void NTCPSession::PostI2NPMessages(
    std::vector<std::shared_ptr<I2NPMessage> > msgs) {
  if (m_IsTerminated)
    return;
  if (m_IsSending) {
    for (auto it : msgs)
      m_SendQueue.push_back(it);
  } else {
    Send(msgs);
  }
}

void NTCPSession::ScheduleTermination() {
  m_TerminationTimer.cancel();
  m_TerminationTimer.expires_from_now(
      boost::posix_time::seconds(NTCP_TERMINATION_TIMEOUT));
  m_TerminationTimer.async_wait(
      std::bind(
          &NTCPSession::HandleTerminationTimer,
          shared_from_this(),
          std::placeholders::_1));
}

void NTCPSession::HandleTerminationTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    LogPrint("No activity for ", NTCP_TERMINATION_TIMEOUT, " seconds");
    // Terminate();
    m_Socket.close();  // invoke Terminate() from HandleReceive
  }
}

}  // namespace transport
}  // namespace i2p
