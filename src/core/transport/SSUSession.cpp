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

#include "SSUSession.h"

#include <boost/bind.hpp>

#include <cstdint>
#include <vector>
#include <memory>

#include "RouterContext.h"
#include "SSU.h"
#include "SSUPacket.h"
#include "Transports.h"
#include "crypto/DiffieHellman.h"
#include "crypto/Hash.h"
#include "crypto/Rand.h"
#include "util/Log.h"
#include "util/Timestamp.h"

namespace i2p {
namespace transport {

std::uint8_t* SSUSessionPacket::MAC() const {
  return data;
}

std::uint8_t* SSUSessionPacket::IV() const {
  return data + std::size_t(16);
}

void SSUSessionPacket::PutFlag(
    std::uint8_t flag) const {
  data[32] = flag;
}

void SSUSessionPacket::PutTime(
    std::uint32_t time) const {
  return htobe32buf(&data[33], time);
}

std::uint8_t * SSUSessionPacket::Encrypted() const {
  return data + std::size_t(32);
}

SSUSession::SSUSession(
    SSUServer& server,
    boost::asio::ip::udp::endpoint& remote_endpoint,
    std::shared_ptr<const i2p::data::RouterInfo> router,
    bool peer_test)
    : TransportSession(router),
      m_Server(server),
      m_RemoteEndpoint(remote_endpoint),
      m_Timer(GetService()),
      m_PeerTest(peer_test),
      m_State(SessionStateUnknown),
      m_IsSessionKey(false),
      m_RelayTag(0),
      m_Data(*this),
      m_IsDataReceived(false) {
  m_CreationTime = i2p::util::GetSecondsSinceEpoch();
}

SSUSession::~SSUSession() {}

boost::asio::io_service& SSUSession::GetService() {
  return IsV6() ? m_Server.GetServiceV6() : m_Server.GetService();
}

void SSUSession::CreateAESandMACKey(
    const std::uint8_t* pub_key) {
  i2p::crypto::DiffieHellman dh;
  std::array<std::uint8_t, 256> shared_key;
  if (!dh.Agree(shared_key.data(), m_DHKeysPair->private_key.data(), pub_key)) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(), "couldn't create shared key");
    return;
  }
  std::uint8_t* session_key = m_SessionKey;
  std::uint8_t* mac_key = m_MACKey;
  if (shared_key.at(0) & 0x80) {
    session_key[0] = 0;
    memcpy(session_key + 1, shared_key.data(), 31);
    memcpy(mac_key, shared_key.data() + 31, 32);
  } else if (shared_key.at(0)) {
    memcpy(session_key, shared_key.data(), 32);
    memcpy(mac_key, shared_key.data() + 32, 32);
  } else {
    // find first non-zero byte
    std::uint8_t* non_zero = shared_key.data() + 1;
    while (!*non_zero) {
      non_zero++;
      if (non_zero - shared_key.data() > 32) {
        LogPrint(eLogWarning,
            "SSUSession:", GetFormattedSessionInfo(),
            "first 32 bytes of shared key is all zeros. Ignored");
        return;
      }
    }
    memcpy(session_key, non_zero, 32);
    i2p::crypto::SHA256().CalculateDigest(
        mac_key,
        non_zero,
        64 - (non_zero - shared_key.data()));
  }
  m_IsSessionKey = true;
  m_SessionKeyEncryption.SetKey(m_SessionKey);
  m_SessionKeyDecryption.SetKey(m_SessionKey);
}

/**
 *
 * Process encrypted/decrypted SSU messages
 *
 */

void SSUSession::ProcessNextMessage(
    std::uint8_t* buf,
    std::size_t len,
    const boost::asio::ip::udp::endpoint& sender_endpoint) {
  m_NumReceivedBytes += len;
  LogPrint(eLogDebug,
      "SSUSession:", GetFormattedSessionInfo(),
      "--> ", len, " bytes transferred, ",
      GetNumReceivedBytes(), " total bytes received");
  i2p::transport::transports.UpdateReceivedBytes(len);
  if (m_State == SessionStateIntroduced) {
    // HolePunch received
    LogPrint("SSUSession: SSU HolePunch of ", len, " bytes received");
    m_State = SessionStateUnknown;
    Connect();
  } else {
    if (!len)
      return;  // ignore zero-length packets
    if (m_State == SessionStateEstablished)
      ScheduleTermination();
    if (m_IsSessionKey) {
      if (Validate(buf, len, m_MACKey)) {  // try session key first
        DecryptSessionKey(buf, len);
      }
    } else {
      // try intro key depending on side
      auto intro_key = GetIntroKey();
      if (intro_key) {
        if (Validate(buf, len, intro_key)) {
          Decrypt(buf, len, intro_key);
        }
      } else {
        // try own intro key
        auto address = i2p::context.GetRouterInfo().GetSSUAddress();
        if (!address) {
          LogPrint(eLogError,
              "SSUSession: ProcessNextMessage(): SSU is not supported");
          return;
        }
        if (Validate(buf, len, address->key)) {
          Decrypt(buf, len, address->key);
        } else {
          LogPrint(eLogError,
              "SSUSession: MAC verification failed ",
              len, " bytes from ", sender_endpoint);
          m_Server.DeleteSession(shared_from_this());
          return;
        }
      }
    }
    // successfully decrypted
    ProcessDecryptedMessage(buf, len, sender_endpoint);
  }
}

void SSUSession::ProcessDecryptedMessage(
    std::uint8_t* buf,
    std::size_t len,
    const boost::asio::ip::udp::endpoint& sender_endpoint) {
  len -= (len & 0x0F);  // %16, delete extra padding
  SSUPacketParser parser(buf, len);
  std::unique_ptr<SSUPacket> packet;
  try {
    packet = parser.ParsePacket();
  } catch(const std::exception& e) {
    LogPrint(eLogError,
        "SSUSession: invalid SSU session packet from ", sender_endpoint);
    return;
  }
  switch (packet->GetHeader()->GetPayloadType()) {
    case SSUHeader::PayloadType::Data:
      ProcessData(packet.get());
      break;
    case SSUHeader::PayloadType::SessionRequest:
      ProcessSessionRequest(packet.get(), sender_endpoint);
      break;
    case SSUHeader::PayloadType::SessionCreated:
      ProcessSessionCreated(packet.get());
      break;
    case SSUHeader::PayloadType::SessionConfirmed:
      ProcessSessionConfirmed(packet.get());
      break;
    case SSUHeader::PayloadType::PeerTest:
      LogPrint(eLogDebug, "SSUSession: PeerTest received");
      ProcessPeerTest(packet.get(), sender_endpoint);
      break;
    case SSUHeader::PayloadType::SessionDestroyed:
      LogPrint(eLogDebug, "SSUSession: SessionDestroy received");
      m_Server.DeleteSession(shared_from_this());
      break;
    case SSUHeader::PayloadType::RelayResponse:
      ProcessRelayResponse(packet.get());
      if (m_State != SessionStateEstablished)
        m_Server.DeleteSession(shared_from_this());
      break;
    case SSUHeader::PayloadType::RelayRequest:
      LogPrint(eLogDebug, "SSUSession: RelayRequest received");
      ProcessRelayRequest(packet.get(), sender_endpoint);
      break;
    case SSUHeader::PayloadType::RelayIntro:
      LogPrint(eLogDebug, "SSUSession: RelayIntro received");
      ProcessRelayIntro(packet.get());
      break;
    default:
      LogPrint(eLogWarning,
          "SSUSession: unexpected payload type: ",
          static_cast<int>(packet->GetHeader()->GetPayloadType()));
  }
}

/**
 * SSU messages (payload types)
 * ------------------------
 *
 *  There are 10 defined SSU messages:
 *
 *  0 SessionRequest
 *  1 SessionCreated
 *  2 SessionConfirmed
 *  3 RelayRequest
 *  4 RelayResponse
 *  5 RelayIntro
 *  6 Data
 *  7 PeerTest
 *  8 SessionDestroyed (implemented as of 0.8.9)
 *  n/a HolePunch
 */

/**
 *
 * Payload type 0: SessionRequest
 *
 */

void SSUSession::ProcessSessionRequest(
    SSUPacket* pkt,
    const boost::asio::ip::udp::endpoint& sender_endpoint) {
  if (IsOutbound()) {
    // cannot handle session request if we are outbound
    return;
  }
  LogPrint(eLogDebug, "SSUSession: SessionRequest received");
  auto packet = static_cast<SSUSessionRequestPacket*>(pkt);
  SetRemoteEndpoint(sender_endpoint);
  if (!m_DHKeysPair)
    m_DHKeysPair = transports.GetNextDHKeysPair();
  CreateAESandMACKey(packet->GetDhX());
  SendSessionCreated(packet->GetDhX());
}

void SSUSession::SendSessionRequest() {
  LogPrint(eLogError,
      "SSUSession:", GetFormattedSessionInfo(), "sending SessionRequest");
  auto intro_key = GetIntroKey();
  if (!intro_key) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "SendSessionRequest(): SSU is not supported");
    return;
  }
  SSUSessionRequestPacket packet;
  packet.SetHeader(
      std::make_unique<SSUHeader>(SSUHeader::PayloadType::SessionRequest));
  std::array<std::uint8_t, static_cast<std::size_t>(SSUSize::IV)> iv;
  i2p::crypto::RandBytes(iv.data(), iv.size());
  packet.GetHeader()->SetIV(iv.data());
  packet.SetDhX(m_DHKeysPair->public_key.data());
  // Fill extended options
  if (i2p::context.GetStatus() == eRouterStatusOK) {  // we don't need relays
    packet.GetHeader()->SetExtendedOptions(true);
    std::array<std::uint8_t, 2> extended_data {{ 0x00, 0x00 }};
    packet.GetHeader()->SetExtendedOptionsData(extended_data.data(), 2);
  }
  const auto address = GetRemoteEndpoint().address();
  if (GetRemoteEndpoint().address().is_v4())
    packet.SetIPAddress(address.to_v4().to_bytes().data(), 4);
  else
    packet.SetIPAddress(address.to_v6().to_bytes().data(), 16);
  const std::size_t buffer_size =
    SSUPacketBuilder::GetPaddedSize(packet.GetSize());
  auto buffer = std::make_unique<std::uint8_t[]>(buffer_size);
  WriteAndEncrypt(&packet, buffer.get(), intro_key, intro_key);
  m_Server.Send(buffer.get(), buffer_size, GetRemoteEndpoint());
}

/**
 *
 * Payload type 1: SessionCreated
 *
 */

void SSUSession::ProcessSessionCreated(SSUPacket* pkt) {
  if (!m_RemoteRouter || !m_DHKeysPair) {
    LogPrint(eLogWarning,
        "SSUSession:", GetFormattedSessionInfo(),
        "unsolicited SessionCreated message");
    return;
  }
  LogPrint(eLogDebug,
      "SSUSession:", GetFormattedSessionInfo(),
      "SessionCreated received");
  m_Timer.cancel();  // connect timer
  auto packet = static_cast<SSUSessionCreatedPacket*>(pkt);
  // x, y, our IP, our port, remote IP, remote port, relayTag, signed on time
  SignedData s;
  // TODO(unassigned): if we cannot create shared key, we should not continue
  CreateAESandMACKey(packet->GetDhY());
  s.Insert(m_DHKeysPair->public_key.data(), 256);  // x
  s.Insert(packet->GetDhY(), 256);  // y
  boost::asio::ip::address our_IP;
  if (packet->GetIPAddressSize() == 4) {  // v4
    boost::asio::ip::address_v4::bytes_type bytes;
    memcpy(bytes.data(), packet->GetIPAddress(), 4);
    our_IP = boost::asio::ip::address_v4(bytes);
  } else {  // v6
    boost::asio::ip::address_v6::bytes_type bytes;
    memcpy(bytes.data(), packet->GetIPAddress(), 16);
    our_IP = boost::asio::ip::address_v6(bytes);
  }
  s.Insert(packet->GetIPAddress(), packet->GetIPAddressSize());  // our IP
  s.Insert<std::uint16_t>(htobe16(packet->GetPort()));  // our port
  LogPrint(eLogInfo,
      "SSUSession:", GetFormattedSessionInfo(),
      "ProcessSessionCreated(): our external address is ",
      our_IP.to_string(), ":", packet->GetPort());
  i2p::context.UpdateAddress(our_IP);
  if (GetRemoteEndpoint().address().is_v4()) {
    // remote IP v4
    s.Insert(GetRemoteEndpoint().address().to_v4().to_bytes().data(), 4);
  } else {
    // remote IP v6
    s.Insert(GetRemoteEndpoint().address().to_v6().to_bytes().data(), 16);
  }
  s.Insert<std::uint16_t>(htobe16(GetRemoteEndpoint().port()));  // remote port
  m_RelayTag = packet->GetRelayTag();
  s.Insert<std::uint32_t>(htobe32(m_RelayTag));  // relayTag
  s.Insert<std::uint32_t>(htobe32(packet->GetSignedOnTime()));  // signed on time
  // decrypt signature
  std::size_t signatureLen = m_RemoteIdentity.GetSignatureLen();
  std::size_t padding_size = signatureLen & 0x0F;  // %16
  if (padding_size > 0)
    signatureLen += (16 - padding_size);
  m_SessionKeyDecryption.SetIV(packet->GetHeader()->GetIV());
  m_SessionKeyDecryption.Decrypt(
      packet->GetSignature(),
      signatureLen,
      packet->GetSignature());
  // verify
  if (s.Verify(m_RemoteIdentity, packet->GetSignature())) {
    // all good
    SendSessionConfirmed(
        packet->GetDhY(),
        packet->GetIPAddress(),
        packet->GetIPAddressSize() + 2);
  } else {  // invalid signature
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "SessionCreated signature verification failed");
  }
}

void SSUSession::SendSessionCreated(const std::uint8_t* x) {
  auto intro_key = GetIntroKey();
  auto address = IsV6() ?
    i2p::context.GetRouterInfo().GetSSUV6Address() :
    i2p::context.GetRouterInfo().GetSSUAddress(true);  // v4 only
  if (!intro_key || !address) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "SendSessionCreated(): SSU is not supported");
    return;
  }
  SSUSessionCreatedPacket packet;
  packet.SetHeader(
      std::make_unique<SSUHeader>(SSUHeader::PayloadType::SessionRequest));
  packet.SetDhY(m_DHKeysPair->public_key.data());
  packet.SetPort(GetRemoteEndpoint().port());
  const std::size_t signatureSize = i2p::context.GetIdentity().GetSignatureLen();
  auto signatureBuf = std::make_unique<std::uint8_t[]>(signatureSize);
  // signature
  // x,y, remote IP, remote port, our IP, our port, relayTag, signed on time
  SignedData s;
  s.Insert(x, 256);  // x
  s.Insert(packet.GetDhY(), 256);  // y
  const auto remoteAddress = GetRemoteEndpoint().address();
  if (remoteAddress.is_v4()) {
    packet.SetIPAddress(remoteAddress.to_v4().to_bytes().data(), 4);
    s.Insert(remoteAddress.to_v4().to_bytes().data(), 4);
  } else {
    packet.SetIPAddress(remoteAddress.to_v6().to_bytes().data(), 16);
    s.Insert(remoteAddress.to_v6().to_bytes().data(), 16);
  }
  s.Insert<std::uint16_t>(packet.GetPort());  // remote port
  if (address->host.is_v4())
    s.Insert(address->host.to_v4().to_bytes().data(), 4);  // our IP V4
  else
    s.Insert(address->host.to_v6().to_bytes().data(), 16);  // our IP V6
  s.Insert<std::uint16_t> (htobe16(address->port));  // our port

  std::uint32_t relayTag = 0;
  if (i2p::context.GetRouterInfo().IsIntroducer()) {
    relayTag = i2p::crypto::Rand<std::uint32_t>();
    if (!relayTag)
      relayTag = 1;
    m_Server.AddRelay(relayTag, GetRemoteEndpoint());
  }
  packet.SetRelayTag(relayTag);
  packet.SetSignedOnTime(i2p::util::GetSecondsSinceEpoch());
  s.Insert<std::uint32_t>(relayTag);
  s.Insert<std::uint32_t>(packet.GetSignedOnTime());
  // store for session confirmation
  m_SessionConfirmData =
    std::unique_ptr<SignedData>(std::make_unique<SignedData>(s));
  s.Sign(i2p::context.GetPrivateKeys(), signatureBuf.get());  // DSA signature
  std::size_t buffer_size = SSUPacketBuilder::GetPaddedSize(packet.GetSize());
  const std::size_t sigPaddingSize = SSUPacketBuilder::GetPaddingSize(
      buffer_size + signatureSize);
  i2p::crypto::RandBytes(signatureBuf.get() + signatureSize, sigPaddingSize);
  packet.SetSignature(signatureBuf.get(), signatureSize + sigPaddingSize);
  // Recompute buffer size
  buffer_size = SSUPacketBuilder::GetPaddedSize(packet.GetSize());
  // encrypt signature and padding with newly created session key
  m_SessionKeyEncryption.SetIV(packet.GetHeader()->GetIV());
  m_SessionKeyEncryption.Encrypt(
      packet.GetSignature(),
      packet.GetSignatureSize(),
      packet.GetSignature());
  // TODO(EinMByte): Deal with large messages in a better way
  if (buffer_size <= SSU_MTU_V4) {
    auto buffer = std::make_unique<std::uint8_t[]>(buffer_size);
    WriteAndEncrypt(&packet, buffer.get(), intro_key, intro_key);
    Send(buffer.get(), buffer_size);
  }
}

/**
 *
 * Payload type 2: SessionConfirmed
 *
 */

void SSUSession::ProcessSessionConfirmed(SSUPacket* pkt) {
  if (m_SessionConfirmData == nullptr) {
    // No session confirm data
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "unsolicited SessionConfirmed");
    return;
  }
  LogPrint(eLogDebug,
      "SSUSession:", GetFormattedSessionInfo(), "SessionConfirmed received");
  auto packet = static_cast<SSUSessionConfirmedPacket*>(pkt);
  m_RemoteIdentity = packet->GetRemoteRouterIdentity();
  m_Data.UpdatePacketSize(m_RemoteIdentity.GetIdentHash());
  // signature time
  m_SessionConfirmData->Insert<std::uint32_t>(htobe32(packet->GetSignedOnTime()));
  if (m_SessionConfirmData->Verify(m_RemoteIdentity, packet->GetSignature())) {
    // verified
    Established();
    return;
  }
  // bad state or verification failed
  LogPrint(eLogError,
      "SSUSession:", GetFormattedSessionInfo(), "SessionConfirmed Failed");
}

void SSUSession::SendSessionConfirmed(
    const std::uint8_t* y,
    const std::uint8_t* our_address,
    std::size_t our_address_len) {
  SSUSessionConfirmedPacket packet;
  packet.SetHeader(
      std::make_unique<SSUHeader>(SSUHeader::PayloadType::SessionRequest));
  std::array<std::uint8_t, static_cast<std::size_t>(SSUSize::IV)> iv;
  i2p::crypto::RandBytes(iv.data(), iv.size());
  packet.GetHeader()->SetIV(iv.data());
  packet.SetRemoteRouterIdentity(i2p::context.GetIdentity());
  packet.SetSignedOnTime(i2p::util::GetSecondsSinceEpoch());
  auto signatureBuf =
    std::make_unique<std::uint8_t[]>(i2p::context.GetIdentity().GetSignatureLen());
  // signature
  // x,y, our IP, our port, remote IP, remote port,
  // relayTag, our signed on time
  SignedData s;
  s.Insert(m_DHKeysPair->public_key.data(), 256);  // x
  s.Insert(y, 256);  // y
  s.Insert(our_address, our_address_len);  // our address/port as seen by party
  const auto address = GetRemoteEndpoint().address();
  if (address.is_v4())  // remote IP V4
    s.Insert(address.to_v4().to_bytes().data(), 4);
  else  // remote IP V6
    s.Insert(address.to_v6().to_bytes().data(), 16);
  s.Insert<std::uint16_t>(htobe16(GetRemoteEndpoint().port()));  // remote port
  s.Insert(htobe32(m_RelayTag));
  s.Insert(htobe32(packet.GetSignedOnTime()));
  s.Sign(i2p::context.GetPrivateKeys(), signatureBuf.get());
  packet.SetSignature(signatureBuf.get());
  const std::size_t buffer_size = SSUPacketBuilder::GetPaddedSize(packet.GetSize());
  auto buffer = std::make_unique<std::uint8_t[]>(buffer_size);
  WriteAndEncrypt(&packet, buffer.get(), m_SessionKey, m_MACKey);
  Send(buffer.get(), buffer_size);
}

/**
 *
 * Payload type 3: RelayRequest
 *
 */

void SSUSession::ProcessRelayRequest(
    SSUPacket* pkt,
    const boost::asio::ip::udp::endpoint& from) {
  auto packet = static_cast<SSURelayRequestPacket*>(pkt);
  auto session = m_Server.FindRelaySession(packet->GetRelayTag());
  if (!session)
    return;
  SendRelayResponse(
      packet->GetNonce(),
      from,
      packet->GetIntroKey(),
      session->GetRemoteEndpoint());
  SendRelayIntro(session.get(), from);
}

void SSUSession::SendRelayRequest(
    std::uint32_t introducer_tag,
    const std::uint8_t* introducer_key) {
  auto address = i2p::context.GetRouterInfo().GetSSUAddress();
  if (!address) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "SendRelayRequest(): SSU is not supported");
    return;
  }
  std::array<std::uint8_t, 96 + 18> buf {};  // TODO(unassigned): document size values
  std::uint8_t* payload = buf.data() + static_cast<std::size_t>(SSUSize::HeaderMin);
  htobe32buf(payload, introducer_tag);
  payload += 4;
  *payload = 0;  // no address
  payload++;
  htobuf16(payload, 0);  // port = 0
  payload += 2;
  *payload = 0;  // challenge
  payload++;
  memcpy(payload, (const std::uint8_t *)address->key, 32);
  payload += 32;
  htobe32buf(payload, i2p::crypto::Rand<std::uint32_t>());  // nonce
  std::array<std::uint8_t, 16> iv;
  i2p::crypto::RandBytes(iv.data(), iv.size());
  if (m_State == SessionStateEstablished) {
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_RELAY_REQUEST,
        buf.data(),
        96,
        m_SessionKey,
        iv.data(),
        m_MACKey);
  } else {
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_RELAY_REQUEST,
        buf.data(),
        96,
        introducer_key,
        iv.data(),
        introducer_key);
  }
  m_Server.Send(
      buf.data(),
      96,
      GetRemoteEndpoint());
}

/**
 *
 * Payload type 4: RelayResponse
 *
 */

void SSUSession::ProcessRelayResponse(SSUPacket* pkt) {
  LogPrint(eLogDebug,
      "SSUSession:", GetFormattedSessionInfo(), "RelayResponse received");
  auto packet = static_cast<SSURelayResponsePacket*>(pkt);
  // TODO(EinMByte): Check remote (charlie) address
  boost::asio::ip::address our_IP;
  if (packet->GetIPAddressAliceSize() == 4) {
    boost::asio::ip::address_v4::bytes_type bytes;
    memcpy(bytes.data(), packet->GetIPAddressAlice(), 4);
    our_IP = boost::asio::ip::address_v4(bytes);
  } else {
    boost::asio::ip::address_v6::bytes_type bytes;
    memcpy(bytes.data(), packet->GetIPAddressAlice(), 16);
    our_IP = boost::asio::ip::address_v6(bytes);
  }
  LogPrint(eLogInfo,
      "SSUSession:", GetFormattedSessionInfo(),
      "ProcessRelayResponse(): our external address is ",
      our_IP.to_string(), ":", packet->GetPortAlice());
  i2p::context.UpdateAddress(our_IP);
}

void SSUSession::SendRelayResponse(
    std::uint32_t nonce,
    const boost::asio::ip::udp::endpoint& from,
    const std::uint8_t* intro_key,
    const boost::asio::ip::udp::endpoint& to) {
  std::array<std::uint8_t, 80 + 18> buf {};  // 64 Alice's ipv4 and 80 Alice's ipv6
  std::uint8_t* payload = buf.data() + static_cast<std::size_t>(SSUSize::HeaderMin);
  // Charlie's address always v4
  if (!to.address().is_v4()) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "SendRelayResponse: Charlie's IP must be V4");
    return;
  }
  *payload = 4;
  payload++;  // size
  htobe32buf(payload, to.address().to_v4().to_ulong());  // Charlie's IP
  payload += 4;  // address
  htobe16buf(payload, to.port());  // Charlie's port
  payload += 2;  // port
  // Alice
  bool is_IPV4 = from.address().is_v4();  // Alice's
  if (is_IPV4) {
    *payload = 4;
    payload++;  // size
    // Alice's IP V4
    memcpy(payload, from.address().to_v4().to_bytes().data(), 4);
    payload += 4;  // address
  } else {
    *payload = 16;
    payload++;  // size
    // Alice's IP V6
    memcpy(payload, from.address().to_v6().to_bytes().data(), 16);
    payload += 16;  // address
  }
  htobe16buf(payload, from.port());  // Alice's port
  payload += 2;  // port
  htobe32buf(payload, nonce);
  if (m_State == SessionStateEstablished) {
    // encrypt with session key
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_RELAY_RESPONSE,
        buf.data(),
        is_IPV4 ? 64 : 80);
    Send(
        buf.data(),
        is_IPV4 ? 64 : 80);
  } else {
    // encrypt with Alice's intro key
    std::array<std::uint8_t, 16> iv;
    i2p::crypto::RandBytes(iv.data(), iv.size());
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_RELAY_RESPONSE,
        buf.data(),
        is_IPV4 ? 64 : 80,
        intro_key,
        iv.data(),
        intro_key);
    m_Server.Send(
        buf.data(),
        is_IPV4 ? 64 : 80,
        from);
  }
  LogPrint(eLogDebug, "SSUSession: RelayResponse sent");
}

/**
 *
 * Payload type 5: RelayIntro
 *
 */

void SSUSession::ProcessRelayIntro(SSUPacket* pkt) {
  auto packet = static_cast<SSURelayIntroPacket*>(pkt);
  if (packet->GetIPAddressSize() == 4) {
    boost::asio::ip::address_v4 address(bufbe32toh(packet->GetIPAddress()));
    // send hole punch of 1 byte
    m_Server.Send(
        {},
        0,
        boost::asio::ip::udp::endpoint(
            address,
            packet->GetPort()));
  } else {
    LogPrint(eLogWarning,
        "SSUSession:", GetFormattedSessionInfo(),
        "ProcessRelayIntro(): address size ",
        packet->GetIPAddressSize(),
        " is not supported");
  }
}

void SSUSession::SendRelayIntro(
    SSUSession* session,
    const boost::asio::ip::udp::endpoint& from) {
  if (!session)
    return;
  // Alice's address always v4
  if (!from.address().is_v4()) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "SendRelayIntro(): Alice's IP must be V4");
    return;
  }
  std::array<std::uint8_t, 48 + 18> buf {};
  std::uint8_t* payload = buf.data() + static_cast<std::size_t>(SSUSize::HeaderMin);
  *payload = 4;
  payload++;  // size
  htobe32buf(payload, from.address().to_v4().to_ulong());  // Alice's IP
  payload += 4;  // address
  htobe16buf(payload, from.port());  // Alice's port
  payload += 2;  // port
  *payload = 0;  // challenge size
  std::array<std::uint8_t, 16> iv;
  i2p::crypto::RandBytes(iv.data(), iv.size());  // random iv
  FillHeaderAndEncrypt(
      PAYLOAD_TYPE_RELAY_INTRO,
      buf.data(),
      48,
      session->m_SessionKey,
      iv.data(),
      session->m_MACKey);
  m_Server.Send(
      buf.data(),
      48,
      session->GetRemoteEndpoint());
  LogPrint(eLogDebug,
      "SSUSession: ", GetFormattedSessionInfo(), "RelayIntro sent");
}

/**
 *
 * Payload type 6: Data
 *
 */

void SSUSession::ProcessData(SSUPacket* pkt) {
  auto packet = static_cast<SSUDataPacket*>(pkt);
  // TODO(EinMByte): Don't use raw data
  m_Data.ProcessMessage(packet->m_RawData, packet->m_RawDataLength);
  m_IsDataReceived = true;
}

void SSUSession::FlushData() {
  if (m_IsDataReceived) {
    m_Data.FlushReceivedMessage();
    m_IsDataReceived = false;
  }
}

/**
 *
 * Payload type 7: PeerTest
 *
 */

void SSUSession::ProcessPeerTest(
    SSUPacket* pkt,
    const boost::asio::ip::udp::endpoint& sender_endpoint) {
  auto packet = static_cast<SSUPeerTestPacket*>(pkt);
  if (packet->GetPort() && !packet->GetIPAddress()) {
    LogPrint(eLogWarning,
        "SSUSession:", GetFormattedSessionInfo(), "address size ",
        " bytes not supported");
    return;
  }
  switch (m_Server.GetPeerTestParticipant(packet->GetNonce())) {
    // existing test
    case PeerTestParticipantAlice1: {
      if (m_State == SessionStateEstablished) {
        LogPrint(eLogDebug,
            "SSUSession:", GetFormattedSessionInfo(),
            "PeerTest from Bob. We are Alice");
        if (i2p::context.GetStatus() == eRouterStatusTesting)  // still not OK
          i2p::context.SetStatus(eRouterStatusFirewalled);
      } else {
        LogPrint(eLogDebug,
            "SSUSession:", GetFormattedSessionInfo(),
            "first PeerTest from Charlie. We are Alice");
        i2p::context.SetStatus(eRouterStatusOK);
        m_Server.UpdatePeerTest(
            packet->GetNonce(),
            PeerTestParticipantAlice2);
        SendPeerTest(
            packet->GetNonce(),
            sender_endpoint.address().to_v4().to_ulong(),
            sender_endpoint.port(),
            packet->GetIntroKey(),
            true,
            false);  // to Charlie
      }
      break;
    }
    case PeerTestParticipantAlice2: {
      if (m_State == SessionStateEstablished) {
        LogPrint(eLogDebug,
            "SSUSession:", GetFormattedSessionInfo(),
            "PeerTest from Bob. We are Alice");
      } else {
        // PeerTest successive
        LogPrint(eLogDebug,
            "SSUSession:", GetFormattedSessionInfo(),
            "second PeerTest from Charlie. We are Alice");
        i2p::context.SetStatus(eRouterStatusOK);
        m_Server.RemovePeerTest(packet->GetNonce());
      }
      break;
    }
    case PeerTestParticipantBob: {
      LogPrint(eLogDebug,
          "SSUSession:", GetFormattedSessionInfo(),
          "PeerTest from Charlie. We are Bob");
      // session with Alice from PeerTest
      auto session = m_Server.GetPeerTestSession(packet->GetNonce());
      if (session && session->m_State == SessionStateEstablished)
        session->Send(  // back to Alice
            PAYLOAD_TYPE_PEER_TEST,
            packet->m_RawData,
            packet->m_RawDataLength);
      m_Server.RemovePeerTest(packet->GetNonce());  // nonce has been used
      break;
    }
    case PeerTestParticipantCharlie: {
      LogPrint(eLogDebug,
          "SSUSession:", GetFormattedSessionInfo(),
          "PeerTest from Alice. We are Charlie");
      SendPeerTest(
          packet->GetNonce(),
          sender_endpoint.address().to_v4().to_ulong(),
          sender_endpoint.port(),
          packet->GetIntroKey());  // to Alice with her actual address
      m_Server.RemovePeerTest(packet->GetNonce());  // nonce has been used
      break;
    }
    // test not found
    case PeerTestParticipantUnknown: {
      if (m_State == SessionStateEstablished) {
        // new test
        if (packet->GetPort()) {
          LogPrint(eLogDebug,
              "SSUSession:", GetFormattedSessionInfo(),
              "PeerTest from Bob. We are Charlie");
          m_Server.NewPeerTest(packet->GetNonce(), PeerTestParticipantCharlie);
          Send(  // back to Bob
              PAYLOAD_TYPE_PEER_TEST,
              packet->m_RawData,
              packet->m_RawDataLength);
          SendPeerTest(  // to Alice with her address received from Bob
              packet->GetNonce(),
              be32toh(packet->GetIPAddress()),
              be16toh(packet->GetPort()),
              packet->GetIntroKey());
        } else {
          LogPrint(eLogDebug,
              "SSUSession:", GetFormattedSessionInfo(),
              "PeerTest from Alice. We are Bob");
          auto session =
            m_Server.GetRandomEstablishedSession(
                shared_from_this());  // Charlie
          if (session) {
            m_Server.NewPeerTest(
                packet->GetNonce(),
                PeerTestParticipantBob,
                shared_from_this());
            session->SendPeerTest(
                packet->GetNonce(),
                sender_endpoint.address().to_v4().to_ulong(),
                sender_endpoint.port(),
                packet->GetIntroKey(),
                false);  // to Charlie with Alice's actual address
          }
        }
      } else {
        LogPrint(eLogError,
            "SSUSession:", GetFormattedSessionInfo(), "unexpected PeerTest");
      }
    }
  }
}

void SSUSession::SendPeerTest(
    std::uint32_t nonce,
    std::uint32_t address,
    std::uint16_t port,
    const std::uint8_t* intro_key,
    bool to_address,  // is true for Alice<->Charlie communications only
    bool send_address) {  // is false if message comes from Alice
  std::array<std::uint8_t, 80 + 18> buf {};
  std::uint8_t* payload = buf.data() + static_cast<std::size_t>(SSUSize::HeaderMin);
  htobe32buf(payload, nonce);
  payload += 4;  // nonce
  // address and port
  if (send_address && address) {
    *payload = 4;
    payload++;  // size
    htobe32buf(payload, address);
    payload += 4;  // address
  } else {
    *payload = 0;
    payload++;  // size
  }
  htobe16buf(payload, port);
  payload += 2;  // port
  // intro key
  if (to_address) {
    // send our intro key to address instead it's own
    auto addr = i2p::context.GetRouterInfo().GetSSUAddress();
    if (addr)
      memcpy(payload, addr->key, 32);  // intro key
    else
      LogPrint(eLogError,
          "SSUSession:", GetFormattedSessionInfo(),
          "SSU is not supported, can't send PeerTest");
  } else {
    memcpy(payload, intro_key, 32);  // intro key
  }
  // send
  std::array<std::uint8_t, 16> iv;
  i2p::crypto::RandBytes(iv.data(), iv.size());
  if (to_address) {
    // encrypt message with specified intro key
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_PEER_TEST,
        buf.data(),
        80,
        intro_key,
        iv.data(),
        intro_key);
    boost::asio::ip::udp::endpoint ep(
        boost::asio::ip::address_v4(address),
        port);
    m_Server.Send(buf.data(), 80, ep);
  } else {
    // encrypt message with session key
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_PEER_TEST,
        buf.data(),
        80);
    Send(buf.data(), 80);
  }
}

void SSUSession::SendPeerTest() {
  // we are Alice
  LogPrint(eLogDebug,
      "SSUSession: <--", GetFormattedSessionInfo(), "sending PeerTest");
  auto address = i2p::context.GetRouterInfo().GetSSUAddress();
  if (!address) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "SSU is not supported, can't send PeerTest");
    return;
  }
  std::uint32_t nonce = i2p::crypto::Rand<std::uint32_t>();
  if (!nonce)
    nonce = 1;
  m_PeerTest = false;
  m_Server.NewPeerTest(nonce, PeerTestParticipantAlice1);
  SendPeerTest(
      nonce,
      0,  // address and port always zero for Alice
      0,  // ^
      address->key,
      false,
      false);
}

/**
 *
 * Payload type 8: SessionDestroyed
 *
 */

void SSUSession::SendSesionDestroyed() {
  if (m_IsSessionKey) {
    std::array<std::uint8_t, 48 + 18> buf {};
    // encrypt message with session key
    FillHeaderAndEncrypt(PAYLOAD_TYPE_SESSION_DESTROYED, buf.data(), 48);
    try {
      Send(buf.data(), 48);
    } catch(std::exception& ex) {
      LogPrint(eLogError,
          "SSUSession:", GetFormattedSessionInfo(),
          "SendSesionDestroyed(): '", ex.what(), "'");
    }
    LogPrint(eLogDebug,
        "SSUSession:", GetFormattedSessionInfo(), "SessionDestroyed sent");
  }
}

void SSUSession::SendKeepAlive() {
  if (m_State == SessionStateEstablished) {
    std::array<std::uint8_t, 48 + 18> buf {};
    std::uint8_t* payload = buf.data() + static_cast<std::size_t>(SSUSize::HeaderMin);
    *payload = 0;  // flags
    payload++;
    *payload = 0;  // num fragments
    // encrypt message with session key
    FillHeaderAndEncrypt(PAYLOAD_TYPE_DATA, buf.data(), 48);
    Send(buf.data(), 48);
    LogPrint(eLogDebug,
        "SSUSession:", GetFormattedSessionInfo(), "keep-alive sent");
    ScheduleTermination();
  }
}

void SSUSession::FillHeaderAndEncrypt(
    std::uint8_t payload_type,
    std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* aes_key,
    const std::uint8_t* iv,
    const std::uint8_t* mac_key,
    std::uint8_t flag) {
  if (len < static_cast<std::size_t>(SSUSize::HeaderMin)) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "unexpected SSU packet length ", len);
    return;
  }
  SSUSessionPacket pkt(buf, len);
  memcpy(pkt.IV(), iv, 16);
  pkt.PutFlag(flag | (payload_type << 4));  // MSB is 0
  pkt.PutTime(i2p::util::GetSecondsSinceEpoch());
  std::uint8_t* encrypted = pkt.Encrypted();
  auto encrypted_len = len - (encrypted - buf);
  i2p::crypto::CBCEncryption encryption(aes_key, iv);
  encryption.Encrypt(
      encrypted,
      encrypted_len,
      encrypted);
  // assume actual buffer size is 18 (16 + 2) bytes more
  memcpy(buf + len, iv, 16);
  htobe16buf(buf + len + 16, encrypted_len);
  i2p::crypto::HMACMD5Digest(
      encrypted,
      encrypted_len + 18,
      mac_key,
      pkt.MAC());
}

void SSUSession::WriteAndEncrypt(
    SSUPacket* packet,
    std::uint8_t* buffer,
    const std::uint8_t* aes_key,
    const std::uint8_t* mac_key) {
  packet->GetHeader()->SetTime(i2p::util::GetSecondsSinceEpoch());
  std::uint8_t* buf = buffer;
  SSUPacketBuilder::WritePacket(buf, packet);
  // Encrypt everything after the MAC and IV
  std::uint8_t* encrypted =
    buffer + static_cast<std::size_t>(SSUSize::IV) + static_cast<std::size_t>(SSUSize::MAC);
  auto encrypted_len = SSUPacketBuilder::GetPaddingSize(
      (buf - buffer) - (static_cast<std::size_t>(SSUSize::IV)
      + static_cast<std::size_t>(SSUSize::MAC)));
  // Add padding
  i2p::crypto::RandBytes(buf, encrypted_len);
  i2p::crypto::CBCEncryption encryption(aes_key, packet->GetHeader()->GetIV());
  encryption.Encrypt(encrypted, encrypted_len, encrypted);
  // Compute HMAC of encryptedPayload + IV + (payloadLength ^ protocolVersion)
  // Currently, protocolVersion == 0
  buf = encrypted;
  SSUPacketBuilder::WriteData(
      encrypted,
      packet->GetHeader()->GetIV(),
      static_cast<std::size_t>(SSUSize::IV));
  SSUPacketBuilder::WriteUInt16(buf, encrypted_len);
  i2p::crypto::HMACMD5Digest(
      encrypted,
      encrypted_len + static_cast<std::size_t>(SSUSize::BufferMargin),
      mac_key,
      packet->GetHeader()->GetMAC());
  // Write header
  SSUPacketBuilder::WriteHeader(buffer, packet->GetHeader());
}

void SSUSession::FillHeaderAndEncrypt(
    std::uint8_t payload_type,
    std::uint8_t* buf,
    std::size_t len) {
  if (len < static_cast<std::size_t>(SSUSize::HeaderMin)) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "unexpected SSU packet length ", len);
    return;
  }
  SSUSessionPacket pkt(buf, len);
  i2p::crypto::RandBytes(pkt.IV(), 16);  // random iv
  m_SessionKeyEncryption.SetIV(pkt.IV());
  pkt.PutFlag(payload_type << 4);  // MSB is 0
  pkt.PutTime(i2p::util::GetSecondsSinceEpoch());
  std::uint8_t* encrypted = pkt.Encrypted();
  auto encrypted_len = len - (encrypted - buf);
  m_SessionKeyEncryption.Encrypt(
      encrypted,
      encrypted_len,
      encrypted);
  // assume actual buffer size is 18 (16 + 2) bytes more
  memcpy(buf + len, pkt.IV(), 16);
  htobe16buf(buf + len + 16, encrypted_len);
  i2p::crypto::HMACMD5Digest(
      encrypted,
      encrypted_len + 18,
      m_MACKey,
      pkt.MAC());
}

void SSUSession::Decrypt(
    std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* aes_key) {
  if (len < static_cast<std::size_t>(SSUSize::HeaderMin)) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "Decrypt(): unexpected SSU packet length ", len);
    return;
  }
  SSUSessionPacket pkt(buf, len);
  std::uint8_t* encrypted = pkt.Encrypted();
  auto encrypted_len = len - (encrypted - buf);
  i2p::crypto::CBCDecryption decryption;
  decryption.SetKey(aes_key);
  decryption.SetIV(pkt.IV());
  decryption.Decrypt(
      encrypted,
      encrypted_len,
      encrypted);
}

void SSUSession::DecryptSessionKey(
    std::uint8_t* buf,
    std::size_t len) {
  if (len < static_cast<std::size_t>(SSUSize::HeaderMin)) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "DecryptSessionKey(): unexpected SSU packet length ", len);
    return;
  }
  SSUSessionPacket pkt(buf, len);
  std::uint8_t* encrypted = pkt.Encrypted();
  auto encrypted_len = len - (encrypted - buf);
  if (encrypted_len > 0) {
    m_SessionKeyDecryption.SetIV(pkt.IV());
    m_SessionKeyDecryption.Decrypt(
        encrypted,
        encrypted_len,
        encrypted);
  }
}

bool SSUSession::Validate(
    std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* mac_key) {
  if (len < static_cast<std::size_t>(SSUSize::HeaderMin)) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "Validate(): unexpected SSU packet length ", len);
    return false;
  }
  SSUSessionPacket pkt(buf, len);
  std::uint8_t * encrypted = pkt.Encrypted();
  auto encrypted_len = len - (encrypted - buf);
  // assume actual buffer size is 18 (16 + 2) bytes more
  memcpy(buf + len, pkt.IV(), 16);
  htobe16buf(buf + len + 16, encrypted_len);
  std::array<std::uint8_t, 16> digest;
  i2p::crypto::HMACMD5Digest(
      encrypted,
      encrypted_len + 18,
      mac_key,
      digest.data());
  return !memcmp(pkt.MAC(), digest.data(), digest.size());
}

void SSUSession::Connect() {
  if (m_State == SessionStateUnknown) {
    // set connect timer
    ScheduleConnectTimer();
    m_DHKeysPair = transports.GetNextDHKeysPair();
    SendSessionRequest();
  }
}

void SSUSession::WaitForConnect() {
  if (IsOutbound())
    LogPrint(eLogWarning,
        "SSUSession:", GetFormattedSessionInfo(),
        "WaitForConnect() for outgoing session");
  else
    ScheduleConnectTimer();
}

void SSUSession::ScheduleConnectTimer() {
  m_Timer.cancel();
  m_Timer.expires_from_now(
      boost::posix_time::seconds(
        SSU_CONNECT_TIMEOUT));
  m_Timer.async_wait(
      std::bind(
        &SSUSession::HandleConnectTimer,
        shared_from_this(),
        std::placeholders::_1));
}

void SSUSession::HandleConnectTimer(
    const boost::system::error_code& ecode) {
  if (!ecode) {
    // timeout expired
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "session was not established after ",
        SSU_CONNECT_TIMEOUT, " seconds");
    Failed();
  }
}

void SSUSession::Introduce(
    std::uint32_t introducer_tag,
    const std::uint8_t* introducer_key) {
  if (m_State == SessionStateUnknown) {
    // set connect timer
    m_Timer.expires_from_now(
        boost::posix_time::seconds(
          SSU_CONNECT_TIMEOUT));
    m_Timer.async_wait(
        std::bind(
          &SSUSession::HandleConnectTimer,
          shared_from_this(),
          std::placeholders::_1));
  }
  SendRelayRequest(introducer_tag, introducer_key);
}

void SSUSession::WaitForIntroduction() {
  m_State = SessionStateIntroduced;
  // set connect timer
  m_Timer.expires_from_now(
      boost::posix_time::seconds(
        SSU_CONNECT_TIMEOUT));
  m_Timer.async_wait(
      std::bind(
        &SSUSession::HandleConnectTimer,
        shared_from_this(),
        std::placeholders::_1));
}

void SSUSession::Close() {
  m_State = SessionStateClosed;
  SendSesionDestroyed();
  transports.PeerDisconnected(shared_from_this());
  m_Data.Stop();
  m_Timer.cancel();
}

void SSUSession::Done() {
  GetService().post(
      std::bind(
        &SSUSession::Failed,
        shared_from_this()));
}

void SSUSession::Established() {
  // clear out session confirmation data
  m_SessionConfirmData.reset(nullptr);
  m_State = SessionStateEstablished;
  if (m_DHKeysPair) {
    m_DHKeysPair.reset(nullptr);
  }
  m_Data.Start();
  // send delivery status
  m_Data.Send(CreateDeliveryStatusMsg(0));
  // send database store
  m_Data.Send(CreateDatabaseStoreMsg());
  transports.PeerConnected(shared_from_this());
  if (m_PeerTest && (m_RemoteRouter && m_RemoteRouter->IsPeerTesting()))
    SendPeerTest();
  ScheduleTermination();
}

void SSUSession::Failed() {
  if (m_State != SessionStateFailed) {
    m_State = SessionStateFailed;
    m_Server.DeleteSession(shared_from_this());
  }
}

void SSUSession::ScheduleTermination() {
  m_Timer.cancel();
  m_Timer.expires_from_now(
      boost::posix_time::seconds(
          SSU_TERMINATION_TIMEOUT));
  m_Timer.async_wait(
      std::bind(
          &SSUSession::HandleTerminationTimer,
          shared_from_this(),
          std::placeholders::_1));
}

void SSUSession::HandleTerminationTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    LogPrint(eLogError,
        "SSUSession:", GetFormattedSessionInfo(),
        "no activity for ", SSU_TERMINATION_TIMEOUT, " seconds");
    Failed();
  }
}

const std::uint8_t* SSUSession::GetIntroKey() const {
  if (m_RemoteRouter) {
    // we are client
    auto address = m_RemoteRouter->GetSSUAddress();
    return address ? (const std::uint8_t *)address->key : nullptr;
  } else {
    // we are server
    auto address = i2p::context.GetRouterInfo().GetSSUAddress();
    return address ? (const std::uint8_t *)address->key : nullptr;
  }
}

void SSUSession::SendI2NPMessages(
    const std::vector<std::shared_ptr<I2NPMessage>>& msgs) {
  GetService().post(
      std::bind(
        &SSUSession::PostI2NPMessages,
        shared_from_this(),
        msgs));
}

void SSUSession::PostI2NPMessages(
    std::vector<std::shared_ptr<I2NPMessage>> msgs) {
  if (m_State == SessionStateEstablished) {
    for (auto it : msgs)
      if (it)
        m_Data.Send(it);
  }
}

void SSUSession::Send(
    std::uint8_t type,
    const std::uint8_t* payload,
    std::size_t len) {
  std::array<std::uint8_t, SSU_MTU_V4 + 18> buf {};
  std::size_t msg_size = len + static_cast<std::size_t>(SSUSize::HeaderMin);
  std::size_t padding_size = msg_size & 0x0F;  // %16
  if (padding_size > 0)
    msg_size += (16 - padding_size);
  if (msg_size > SSU_MTU_V4) {
    LogPrint(eLogWarning,
        "SSUSession:", GetFormattedSessionInfo(),
        "<-- payload size ", msg_size, " exceeds MTU");
    return;
  }
  memcpy(buf.data() + static_cast<std::size_t>(SSUSize::HeaderMin), payload, len);
  // encrypt message with session key
  FillHeaderAndEncrypt(type, buf.data(), msg_size);
  Send(buf.data(), msg_size);
}

void SSUSession::Send(
    const std::uint8_t* buf,
    std::size_t size) {
  m_NumSentBytes += size;
  LogPrint(eLogDebug,
      "SSUSession:", GetFormattedSessionInfo(),
      "<-- ", size, " bytes transferred, ",
      GetNumSentBytes(), " total bytes sent");
  i2p::transport::transports.UpdateSentBytes(size);
  m_Server.Send(buf, size, GetRemoteEndpoint());
}

}  // namespace transport
}  // namespace i2p

