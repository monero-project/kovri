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

#include "SSUSession.h"

#include <boost/bind.hpp>

#include <cryptopp/dh.h>
#include <cryptopp/sha.h>

#include <vector>

#include "RouterContext.h"
#include "SSU.h"
#include "Transports.h"
#include "crypto/Rand.h"
#include "crypto/CryptoConst.h"
#include "util/Log.h"
#include "util/Timestamp.h"

namespace i2p {
namespace transport {

constexpr size_t SSU_KEYING_MATERIAL_SIZE = 64;
const uint8_t SSU_FLAG_REKEY = 0x08;
const uint8_t SSU_FLAG_EXTENDED_OPTIONS = 0x04;

size_t SSUSessionPacket::ComputeHeaderSize() const {
  size_t hdr_size = SSU_HEADER_SIZE_MIN;
  // the index at which the extended options are located at
  size_t opts_idx = SSU_HEADER_SIZE_MIN;
  if (Rekey()) {
    LogPrint(eLogDebug, "SSU Packet has rekey data");
    // the header has rekey data
    // add that to the extended options offset and header size
    opts_idx += SSU_KEYING_MATERIAL_SIZE;
    hdr_size += SSU_KEYING_MATERIAL_SIZE;
  }
  if (HasExtendedOptions()) {
    LogPrint(eLogDebug, "SSU Packet has extended options");
    // the header has extended options
    if (opts_idx < datalen) {
      // the size of the header includes the size of
      // the extended options +1 byte holding the size
      hdr_size += dataptr[opts_idx] + 1;
    }
  }
  return hdr_size;
}

bool SSUSessionPacket::Rekey() const {
  return Flag() & SSU_FLAG_REKEY;
}

bool SSUSessionPacket::HasExtendedOptions() const {
  return Flag() & SSU_FLAG_EXTENDED_OPTIONS;
}

bool SSUSessionPacket::ExtractExtendedOptions(
    SSUExtendedOptions & opts) const {
  size_t opts_idx = SSU_HEADER_SIZE_MIN;
  if (Rekey()) opts_idx += SSU_KEYING_MATERIAL_SIZE;
  if (opts_idx + 1 >= datalen) {
    // options are bigger than the ssu header?
    // yuck, let's not set anything and return false
    return false;
  }
  opts.datalen = dataptr[opts_idx];
  opts.dataptr = dataptr + opts_idx + 1;
  return true;
}

uint8_t SSUSessionPacket::GetPayloadType() const {
  return Flag() >> 4;
}

uint8_t* SSUSessionPacket::MAC() const {
  return dataptr;
}

uint8_t* SSUSessionPacket::IV() const {
  return dataptr + size_t(16);
}

uint8_t SSUSessionPacket::Flag() const {
  return dataptr[32];
}

void SSUSessionPacket::PutFlag(
    uint8_t f) const {
  dataptr[32] = f;
}

uint32_t SSUSessionPacket::Time() const {
  return bufbe32toh(&dataptr[33]);
}

void SSUSessionPacket::PutTime(
    uint32_t t) const {
  return htobe32buf(&dataptr[33], t);
}

uint8_t * SSUSessionPacket::Encrypted() const {
  return dataptr + size_t(32);
}

bool SSUSessionPacket::ParseHeader() {
  headerlen = ComputeHeaderSize();
  if (!headerlen)
    return false;  // failed to parse header size
  bodyptr = dataptr + headerlen;
  bodylen = datalen - headerlen;
  return true;
}

SSUSession::SSUSession(
    SSUServer& server,
    boost::asio::ip::udp::endpoint& remoteEndpoint,
    std::shared_ptr<const i2p::data::RouterInfo> router,
    bool peerTest)
    : TransportSession(router),
      m_Server(server),
      m_RemoteEndpoint(remoteEndpoint),
      m_Timer(GetService()),
      m_PeerTest(peerTest),
      m_State(eSessionStateUnknown),
      m_IsSessionKey(false),
      m_RelayTag(0),
      m_Data(*this),
      m_IsDataReceived(false) {
  m_CreationTime = i2p::util::GetSecondsSinceEpoch();
}

SSUSession::~SSUSession() {}

boost::asio::io_service& SSUSession::GetService() {
  return IsV6 () ? m_Server.GetServiceV6 () : m_Server.GetService();
}

void SSUSession::CreateAESandMacKey(
    const uint8_t* pubKey) {
  CryptoPP::DH dh(
      i2p::crypto::elgp,
      i2p::crypto::elgg);
  uint8_t sharedKey[256];
  if (!dh.Agree(
        sharedKey,
        m_DHKeysPair->privateKey,
        pubKey)) {
    LogPrint(eLogError, "Couldn't create shared key");
    return;
  }
  uint8_t* sessionKey = m_SessionKey,
              *macKey = m_MacKey;
  if (sharedKey[0] & 0x80) {
    sessionKey[0] = 0;
    memcpy(sessionKey + 1, sharedKey, 31);
    memcpy(macKey, sharedKey + 31, 32);
  } else if (sharedKey[0]) {
    memcpy(sessionKey, sharedKey, 32);
    memcpy(macKey, sharedKey + 32, 32);
  } else {
    // find first non-zero byte
    uint8_t * nonZero = sharedKey + 1;
    while (!*nonZero) {
      nonZero++;
      if (nonZero - sharedKey > 32) {
        LogPrint("First 32 bytes of shared key is all zeros. Ignored");
        return;
      }
    }
    memcpy(sessionKey, nonZero, 32);
    CryptoPP::SHA256().CalculateDigest(
        macKey,
        nonZero,
        64 - (nonZero - sharedKey));
  }
  m_IsSessionKey = true;
  m_SessionKeyEncryption.SetKey(m_SessionKey);
  m_SessionKeyDecryption.SetKey(m_SessionKey);
}

void SSUSession::ProcessNextMessage(
    uint8_t* buf,
    size_t len,
    const boost::asio::ip::udp::endpoint& senderEndpoint) {
  m_NumReceivedBytes += len;
  i2p::transport::transports.UpdateReceivedBytes(len);
  if (m_State == eSessionStateIntroduced) {
    // HolePunch received
    LogPrint("SSU HolePunch of ", len, " bytes received");
    m_State = eSessionStateUnknown;
    Connect();
  } else {
    if (!len)
      return;  // ignore zero-length packets
    if (m_State == eSessionStateEstablished)
      ScheduleTermination();
    if (m_IsSessionKey) {
      if (Validate(buf, len, m_MacKey)) {  // try session key first
        DecryptSessionKey(buf, len);
      }
    } else {
      // try intro key depending on side
      auto introKey = GetIntroKey();
      if (introKey) {
        if (Validate(buf, len, introKey)) {
          Decrypt(buf, len, introKey);
        }
      } else {
        // try own intro key
        auto address = i2p::context.GetRouterInfo().GetSSUAddress();
        if (!address) {
          LogPrint(eLogError, "SSU is not supported");
          return;
        }
        if (Validate(buf, len, address->key)) {
          Decrypt(buf, len, address->key);
        } else {
          LogPrint(eLogError,
              "MAC verification failed ", len, " bytes from ", senderEndpoint);
          m_Server.DeleteSession(shared_from_this());
          return;
        }
      }
    }
    // successfully decrypted
    ProcessDecryptedMessage(buf, len, senderEndpoint);
  }
}

void SSUSession::ProcessDecryptedMessage(
    uint8_t* buf,
    size_t len,
    const boost::asio::ip::udp::endpoint& senderEndpoint) {
  len -= (len & 0x0F);  // %16, delete extra padding
  if (len <= SSU_HEADER_SIZE_MIN)
    return;  // too small
  SSUSessionPacket pkt(buf, len);
  if (!pkt.ParseHeader()) {
    // invalid ssu header
    LogPrint(eLogError,
        "Invalid SSU session packet header from ", senderEndpoint);
    return;
  }
  auto payload_type = pkt.GetPayloadType();
  switch (payload_type) {
    case PAYLOAD_TYPE_DATA:
      ProcessData(pkt);
    break;
    case PAYLOAD_TYPE_SESSION_REQUEST:
      ProcessSessionRequest(pkt, senderEndpoint);
    break;
    case PAYLOAD_TYPE_SESSION_CREATED:
      ProcessSessionCreated(pkt);
    break;
    case PAYLOAD_TYPE_SESSION_CONFIRMED:
      ProcessSessionConfirmed(pkt);
    break;
    case PAYLOAD_TYPE_PEER_TEST:
      LogPrint(eLogDebug, "SSU peer test received");
      ProcessPeerTest(pkt, senderEndpoint);
    break;
    case PAYLOAD_TYPE_SESSION_DESTROYED: {
      LogPrint(eLogDebug, "SSU session destroy received");
      m_Server.DeleteSession(shared_from_this());
      break;
    }
    case PAYLOAD_TYPE_RELAY_RESPONSE:
      ProcessRelayResponse(pkt);
      if (m_State != eSessionStateEstablished)
        m_Server.DeleteSession(shared_from_this());
    break;
    case PAYLOAD_TYPE_RELAY_REQUEST:
      LogPrint(eLogDebug, "SSU relay request received");
      ProcessRelayRequest(pkt, senderEndpoint);
    break;
    case PAYLOAD_TYPE_RELAY_INTRO:
      LogPrint(eLogDebug, "SSU relay intro received");
      ProcessRelayIntro(pkt);
    break;
    default:
      LogPrint(eLogWarning,
          "Unexpected SSU payload type ", static_cast<int>(payload_type));
  }
}

void SSUSession::ProcessSessionRequest(
    SSUSessionPacket& pkt,
    const boost::asio::ip::udp::endpoint& senderEndpoint) {
  if (IsOutbound()) {
    // cannot handle session request if we are outbound
    return;
  }
  LogPrint(eLogDebug, "Session request received");
  m_RemoteEndpoint = senderEndpoint;
  if (!m_DHKeysPair)
    m_DHKeysPair = transports.GetNextDHKeysPair();
  CreateAESandMacKey(pkt.bodyptr);
  SendSessionCreated(pkt.bodyptr);
}

void SSUSession::ProcessSessionCreated(
    SSUSessionPacket & pkt) {
  if (!m_RemoteRouter || !m_DHKeysPair) {
    LogPrint(eLogWarning, "Unsolicited session created message");
    return;
  }
  LogPrint(eLogDebug, "Session created received");
  m_Timer.cancel();  // connect timer
  // x, y, our IP, our port, remote IP, remote port, relayTag, signed on time
  SignedData s;
  uint8_t* payload = pkt.bodyptr;
  uint8_t* y = payload;
  CreateAESandMacKey(y);
  s.Insert(m_DHKeysPair->publicKey, 256);  // x
  s.Insert(y, 256);  // y
  payload += 256;
  uint8_t addressSize = *payload;
  payload += 1;  // size
  uint8_t* ourAddress = payload;
  boost::asio::ip::address ourIP;
  if (addressSize == 4) {  // v4
    boost::asio::ip::address_v4::bytes_type bytes;
    memcpy(bytes.data(), ourAddress, 4);
    ourIP = boost::asio::ip::address_v4(bytes);
  } else {  // v6
    boost::asio::ip::address_v6::bytes_type bytes;
    memcpy(bytes.data(), ourAddress, 16);
    ourIP = boost::asio::ip::address_v6(bytes);
  }
  s.Insert(ourAddress, addressSize);  // our IP
  payload += addressSize;  // address
  uint16_t ourPort = bufbe16toh(payload);
  s.Insert(payload, 2);  // our port
  payload += 2;  // port
  LogPrint("Our external address is ", ourIP.to_string(), ":", ourPort);
  i2p::context.UpdateAddress(ourIP);
  if (m_RemoteEndpoint.address().is_v4())
    // remote IP v4
    s.Insert(m_RemoteEndpoint.address().to_v4().to_bytes().data(), 4);
  else
    // remote IP v6
    s.Insert(m_RemoteEndpoint.address().to_v6().to_bytes().data(), 16);
  s.Insert<uint16_t> (htobe16(m_RemoteEndpoint.port()));  // remote port
  s.Insert(payload, 8);  // relayTag and signed on time
  m_RelayTag = bufbe32toh(payload);
  payload += 4;  // relayTag
  payload += 4;  // signed on time
  // decrypt signature
  size_t signatureLen = m_RemoteIdentity.GetSignatureLen();
  size_t paddingSize = signatureLen & 0x0F;  // %16
  if (paddingSize > 0)
    signatureLen += (16 - paddingSize);
  m_SessionKeyDecryption.SetIV(pkt.IV());
  m_SessionKeyDecryption.Decrypt(payload, signatureLen, payload);
  // verify
  if (s.Verify(m_RemoteIdentity, payload)) {
    // all good
    SendSessionConfirmed(y, ourAddress, addressSize + 2);
  } else {  // invalid signature
    LogPrint(eLogError, "SSU signature verification failed in session created");
  }
}

void SSUSession::ProcessSessionConfirmed(
    SSUSessionPacket & pkt) {
  if (m_SessionConfirmData == nullptr) {
    // no session confirm data wtf?
    LogPrint(eLogError, "SSU Unsolicited Session Confirm");
    return;
  }
  LogPrint(eLogDebug, "Session confirmed received");
  uint8_t* buf = pkt.dataptr;
  uint8_t* payload = pkt.bodyptr;
  payload++;  // identity fragment info
  uint16_t identitySize = bufbe16toh(payload);
  payload += 2;  // size of identity fragment
  m_RemoteIdentity.FromBuffer(payload, identitySize);
  m_Data.UpdatePacketSize(m_RemoteIdentity.GetIdentHash());
  payload += identitySize;  // identity
  m_SessionConfirmData->Insert(
      payload,
      4);  // signature time
  payload += 4;  // signed-on time
  size_t paddingSize = (payload - buf) +
    m_RemoteIdentity.GetSignatureLen();
  paddingSize &= 0x0F;  // %16
  if (paddingSize > 0)
    paddingSize = 16 - paddingSize;
  payload += paddingSize;
  if (m_SessionConfirmData->Verify(m_RemoteIdentity, payload)) {
    // verified
    Established();
    return;
  }
  // bad state or verification failed
  LogPrint(eLogError, "SSU Session Confirm Failed");
}

void SSUSession::SendSessionRequest() {
  auto introKey = GetIntroKey();
  if (!introKey) {
    LogPrint(eLogError, "SSU is not supported");
    return;
  }
  uint8_t buf[320 + 18] = {};  // 304 bytes for ipv4, 320 for ipv6, all set to 0
  uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
  memcpy(payload, m_DHKeysPair->publicKey, 256);  // x
  bool isV4 = m_RemoteEndpoint.address().is_v4();
  if (isV4) {
    payload[256] = 4;
    memcpy(
        payload + 257,
        m_RemoteEndpoint.address().to_v4().to_bytes().data(),
        4);
  } else {
    payload[256] = 16;
    memcpy(
        payload + 257,
        m_RemoteEndpoint.address().to_v6().to_bytes().data(),
        16);
  }
  uint8_t iv[16];
  i2p::crypto::RandBytes(iv, 16);

  FillHeaderAndEncrypt(
      PAYLOAD_TYPE_SESSION_REQUEST,
      buf,
      isV4 ? 304 : 320,
      introKey,
      iv,
      introKey);
  m_Server.Send(
      buf,
      isV4 ? 304 : 320,
      m_RemoteEndpoint);
}

void SSUSession::SendRelayRequest(
    uint32_t iTag,
    const uint8_t* iKey) {
  auto address = i2p::context.GetRouterInfo().GetSSUAddress();
  if (!address) {
    LogPrint(eLogError, "SSU is not supported");
    return;
  }
  uint8_t buf[96 + 18] = {};
  uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
  htobe32buf(payload, iTag);
  payload += 4;
  *payload = 0;  // no address
  payload++;
  htobuf16(payload, 0);  // port = 0
  payload += 2;
  *payload = 0;  // challenge
  payload++;
  memcpy(payload, (const uint8_t *)address->key, 32);
  payload += 32;
  htobe32buf(payload, i2p::crypto::Rand<uint32_t>());  // nonce
  uint8_t iv[16];
  i2p::crypto::RandBytes(iv, 16);
  if (m_State == eSessionStateEstablished) {
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_RELAY_REQUEST,
        buf,
        96,
        m_SessionKey,
        iv,
        m_MacKey);
  } else {
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_RELAY_REQUEST,
        buf,
        96,
        iKey,
        iv,
        iKey);
  }
  m_Server.Send(
      buf,
      96,
      m_RemoteEndpoint);
}

void SSUSession::SendSessionCreated(
    const uint8_t* x) {
  auto introKey = GetIntroKey();
  auto address = IsV6() ?
    i2p::context.GetRouterInfo().GetSSUV6Address() :
    i2p::context.GetRouterInfo().GetSSUAddress(true);  // v4 only
  if (!introKey || !address) {
    LogPrint(eLogError, "SSU is not supported");
    return;
  }
  // x,y, remote IP, remote port, our IP, our port, relayTag, signed on time
  SignedData s;
  s.Insert(x, 256);  // x
  uint8_t buf[384 + 18] = {};
  uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
  memcpy(payload, m_DHKeysPair->publicKey, 256);
  s.Insert(payload, 256);  // y
  payload += 256;
  if (m_RemoteEndpoint.address().is_v4()) {
    // ipv4
    *payload = 4;
    payload++;
    memcpy(
        payload,
        m_RemoteEndpoint.address().to_v4().to_bytes().data(),
        4);
    s.Insert(payload, 4);  // remote endpoint IP V4
    payload += 4;
  } else {
    // ipv6
    *payload = 16;
    payload++;
    memcpy(
        payload,
        m_RemoteEndpoint.address().to_v6().to_bytes().data(),
        16);
    s.Insert(payload, 16);  // remote endpoint IP V6
    payload += 16;
  }
  htobe16buf(payload, m_RemoteEndpoint.port());
  s.Insert(payload, 2);  // remote port
  payload += 2;
  if (address->host.is_v4())
    s.Insert(address->host.to_v4().to_bytes().data(), 4);  // our IP V4
  else
    s.Insert(address->host.to_v6().to_bytes().data(), 16);  // our IP V6
  s.Insert<uint16_t> (htobe16(address->port));  // our port
  uint32_t relayTag = 0;
  if (i2p::context.GetRouterInfo().IsIntroducer()) {
    relayTag = i2p::crypto::Rand<uint32_t>();
    if (!relayTag)
      relayTag = 1;
    m_Server.AddRelay(relayTag, m_RemoteEndpoint);
  }
  htobe32buf(payload, relayTag);
  payload += 4;  // relay tag
  htobe32buf(payload, i2p::util::GetSecondsSinceEpoch());  // signed on time
  payload += 4;
  s.Insert(payload - 8, 4);  // put relayTag
  // store for session confirmation
  m_SessionConfirmData = std::unique_ptr<SignedData>(new SignedData(s));
  s.Insert(payload - 4, 4);  // put timestamp
  s.Sign(i2p::context.GetPrivateKeys(), payload);  // DSA signature
  uint8_t iv[16];
  i2p::crypto::RandBytes(iv, 16);
  // encrypt signature and padding with newly created session key
  size_t signatureLen = i2p::context.GetIdentity().GetSignatureLen();
  size_t paddingSize = signatureLen & 0x0F;  // %16
  if (paddingSize > 0) {
    signatureLen += (16 - paddingSize);
    i2p::crypto::RandBytes(payload, paddingSize);
  }
  m_SessionKeyEncryption.SetIV(iv);
  m_SessionKeyEncryption.Encrypt(
      payload,
      signatureLen,
      payload);
  payload += signatureLen;
  size_t msgLen = payload - buf;
  if (msgLen <= SSU_MTU_V4 ) {
    // encrypt message with intro key
    FillHeaderAndEncrypt(
      PAYLOAD_TYPE_SESSION_CREATED,
      buf,
      msgLen,
      introKey,
      iv,
      introKey);
    // send it
    Send(buf, msgLen);
  }
}

void SSUSession::SendSessionConfirmed(
    const uint8_t* y,
    const uint8_t* ourAddress,
    size_t ourAddressLen) {
  uint8_t buf[512 + 18] = {};
  uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
  *payload = 1;  // 1 fragment
  payload++;  // info
  size_t identLen = i2p::context.GetIdentity().GetFullLen();  // 387+ bytes
  htobe16buf(payload, identLen);
  payload += 2;  // cursize
  i2p::context.GetIdentity().ToBuffer(payload, identLen);
  payload += identLen;
  uint32_t signedOnTime = i2p::util::GetSecondsSinceEpoch();
  htobe32buf(payload, signedOnTime);  // signed on time
  payload += 4;
  auto signatureLen = i2p::context.GetIdentity().GetSignatureLen();
  size_t paddingSize = ((payload - buf) + signatureLen)%16;
  if (paddingSize > 0)
    paddingSize = 16 - paddingSize;
  // TODO(unassigned): fill padding
  payload += paddingSize;  // padding size
  // signature
  // x,y, our IP, our port, remote IP, remote port,
  // relayTag, our signed on time
  SignedData s;
  s.Insert(m_DHKeysPair->publicKey, 256);  // x
  s.Insert(y, 256);  // y
  s.Insert(ourAddress, ourAddressLen);  // our address/port as seem by party
  if (m_RemoteEndpoint.address().is_v4())
    // remote IP V4
    s.Insert(m_RemoteEndpoint.address().to_v4().to_bytes().data(), 4);
  else
    // remote IP V6
    s.Insert(m_RemoteEndpoint.address().to_v6().to_bytes().data(), 16);
  s.Insert<uint16_t> (htobe16(m_RemoteEndpoint.port()));  // remote port
  s.Insert(htobe32(m_RelayTag));  // relay tag
  s.Insert(htobe32(signedOnTime));  // signed on time
  s.Sign(i2p::context.GetPrivateKeys(), payload);  // DSA signature
  payload += signatureLen;
  size_t msgLen = payload - buf;
  uint8_t iv[16];
  i2p::crypto::RandBytes(iv, 16);
  // encrypt message with session key
  FillHeaderAndEncrypt(
      PAYLOAD_TYPE_SESSION_CONFIRMED,
      buf,
      msgLen,
      m_SessionKey,
      iv,
      m_MacKey);
  Send(buf, msgLen);
}

void SSUSession::ProcessRelayRequest(
    SSUSessionPacket& pkt,
    const boost::asio::ip::udp::endpoint& from) {
  uint8_t* buf = pkt.bodyptr;
  uint32_t relayTag = bufbe32toh(buf);
  auto session = m_Server.FindRelaySession(relayTag);
  if (session) {
    buf += 4;  // relay tag
    uint8_t size = *buf;
    buf++;  // size
    buf += size;  // address
    buf += 2;  // port
    uint8_t challengeSize = *buf;
    buf++;  // challenge size
    buf += challengeSize;
    uint8_t * introKey = buf;
    buf += 32;  // introkey
    uint32_t nonce = bufbe32toh(buf);
    SendRelayResponse(
        nonce,
        from,
        introKey,
        session->m_RemoteEndpoint);
    SendRelayIntro(session.get(), from);
  }
}

void SSUSession::SendRelayResponse(
    uint32_t nonce,
    const boost::asio::ip::udp::endpoint& from,
    const uint8_t* introKey,
    const boost::asio::ip::udp::endpoint& to) {
  uint8_t buf[80 + 18] = {};  // 64 Alice's ipv4 and 80 Alice's ipv6
  uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
  // Charlie's address always v4
  if (!to.address().is_v4()) {
    LogPrint(eLogError, "Charlie's IP must be v4");
    return;
  }
  *payload = 4;
  payload++;  // size
  htobe32buf(payload, to.address().to_v4().to_ulong());  // Charlie's IP
  payload += 4;  // address
  htobe16buf(payload, to.port());  // Charlie's port
  payload += 2;  // port
  // Alice
  bool isV4 = from.address().is_v4();  // Alice's
  if (isV4) {
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
  if (m_State == eSessionStateEstablished) {
    // encrypt with session key
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_RELAY_RESPONSE,
        buf,
        isV4 ? 64 : 80);
    Send(
        buf,
        isV4 ? 64 : 80);
  } else {
    // encrypt with Alice's intro key
    uint8_t iv[16];
    i2p::crypto::RandBytes(iv, 16);
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_RELAY_RESPONSE,
        buf,
        isV4 ? 64 : 80,
        introKey,
        iv,
        introKey);
    m_Server.Send(
        buf,
        isV4 ? 64 : 80,
        from);
  }
  LogPrint(eLogDebug, "SSU relay response sent");
}

void SSUSession::SendRelayIntro(
    SSUSession* session,
    const boost::asio::ip::udp::endpoint& from) {
  if (!session)
    return;
  // Alice's address always v4
  if (!from.address().is_v4()) {
    LogPrint(eLogError, "Alice's IP must be v4");
    return;
  }
  uint8_t buf[48 + 18] = {};
  uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
  *payload = 4;
  payload++;  // size
  htobe32buf(payload, from.address().to_v4().to_ulong());  // Alice's IP
  payload += 4;  // address
  htobe16buf(payload, from.port());  // Alice's port
  payload += 2;  // port
  *payload = 0;  // challenge size
  uint8_t iv[16];
  i2p::crypto::RandBytes(iv, 16);  // random iv
  FillHeaderAndEncrypt(
      PAYLOAD_TYPE_RELAY_INTRO,
      buf,
      48,
      session->m_SessionKey,
      iv,
      session->m_MacKey);
  m_Server.Send(
      buf,
      48,
      session->m_RemoteEndpoint);
  LogPrint(eLogDebug, "SSU relay intro sent");
}

void SSUSession::ProcessRelayResponse(
    SSUSessionPacket & pkt) {
  LogPrint(eLogDebug, "Relay response received");
  uint8_t* payload = pkt.bodyptr;
  uint8_t remoteSize = *payload;
  payload++;  // remote size
  // boost::asio::ip::address_v4 remoteIP (bufbe32toh (payload));
  payload += remoteSize;  // remote address
  // uint16_t remotePort = bufbe16toh (payload);
  payload += 2;  // remote port
  uint8_t ourSize = *payload;
  payload++;  // our size
  boost::asio::ip::address ourIP;
  if (ourSize == 4) {
    boost::asio::ip::address_v4::bytes_type bytes;
    memcpy(bytes.data(), payload, 4);
    ourIP = boost::asio::ip::address_v4(bytes);
  } else {
    boost::asio::ip::address_v6::bytes_type bytes;
    memcpy(bytes.data(), payload, 16);
    ourIP = boost::asio::ip::address_v6(bytes);
  }
  payload += ourSize;  // our address
  uint16_t ourPort = bufbe16toh(payload);
  payload += 2;  // our port
  LogPrint("Our external address is ", ourIP.to_string(), ":", ourPort);
  i2p::context.UpdateAddress(ourIP);
}

void SSUSession::ProcessRelayIntro(
    SSUSessionPacket & pkt) {
  uint8_t* buf = pkt.bodyptr;
  uint8_t size = *buf;
  if (size == 4) {
    buf++;  // size
    boost::asio::ip::address_v4 address(bufbe32toh(buf));
    buf += 4;  // address
    uint16_t port = bufbe16toh(buf);
    // send hole punch of 1 byte
    m_Server.Send(
        buf,
        0,
        boost::asio::ip::udp::endpoint(
          address,
          port));
  } else {
    LogPrint(eLogWarning,
        "Address size ", static_cast<int>(size), " is not supported");
  }
}

void SSUSession::FillHeaderAndEncrypt(
    uint8_t payloadType,
    uint8_t* buf,
    size_t len,
    const uint8_t* aesKey,
    const uint8_t* iv,
    const uint8_t* macKey) {
  if (len < SSU_HEADER_SIZE_MIN) {
    LogPrint(eLogError, "Unexpected SSU packet length ", len);
    return;
  }
  SSUSessionPacket pkt(buf, len);
  memcpy(pkt.IV(), iv, 16);
  pkt.PutFlag(payloadType << 4);  // MSB is 0
  pkt.PutTime(i2p::util::GetSecondsSinceEpoch());
  uint8_t* encrypted = pkt.Encrypted();
  uint16_t encryptedLen = len - (encrypted - buf);
  i2p::crypto::CBCEncryption encryption(aesKey, iv);
  encryption.Encrypt(
      encrypted,
      encryptedLen,
      encrypted);
  // assume actual buffer size is 18 (16 + 2) bytes more
  memcpy(buf + len, iv, 16);
  htobe16buf(buf + len + 16, encryptedLen);
  i2p::crypto::HMACMD5Digest(
      encrypted,
      encryptedLen + 18,
      macKey,
      pkt.MAC());
}

void SSUSession::FillHeaderAndEncrypt(
    uint8_t payloadType,
    uint8_t* buf,
    size_t len) {
  if (len < SSU_HEADER_SIZE_MIN) {
    LogPrint(eLogError, "Unexpected SSU packet length ", len);
    return;
  }
  SSUSessionPacket pkt(buf, len);
  i2p::crypto::RandBytes(pkt.IV(), 16);  // random iv
  m_SessionKeyEncryption.SetIV(pkt.IV());
  pkt.PutFlag(payloadType << 4);  // MSB is 0
  pkt.PutTime(i2p::util::GetSecondsSinceEpoch());
  uint8_t* encrypted = pkt.Encrypted();
  uint16_t encryptedLen = len - (encrypted - buf);
  m_SessionKeyEncryption.Encrypt(
      encrypted,
      encryptedLen,
      encrypted);
  // assume actual buffer size is 18 (16 + 2) bytes more
  memcpy(buf + len, pkt.IV(), 16);
  htobe16buf(buf + len + 16, encryptedLen);
  i2p::crypto::HMACMD5Digest(
      encrypted,
      encryptedLen + 18,
      m_MacKey,
      pkt.MAC());
}

void SSUSession::Decrypt(
    uint8_t* buf,
    size_t len,
    const uint8_t* aesKey) {
  if (len < SSU_HEADER_SIZE_MIN) {
    LogPrint(eLogError, "Unexpected SSU packet length ", len);
    return;
  }
  SSUSessionPacket pkt(buf, len);
  uint8_t* encrypted = pkt.Encrypted();
  uint16_t encryptedLen = len - (encrypted - buf);
  i2p::crypto::CBCDecryption decryption;
  decryption.SetKey(aesKey);
  decryption.SetIV(pkt.IV());
  decryption.Decrypt(
      encrypted,
      encryptedLen,
      encrypted);
}

void SSUSession::DecryptSessionKey(
    uint8_t* buf,
    size_t len) {
  if (len < SSU_HEADER_SIZE_MIN) {
    LogPrint(eLogError, "Unexpected SSU packet length ", len);
    return;
  }
  SSUSessionPacket pkt(buf, len);
  uint8_t * encrypted = pkt.Encrypted();
  uint16_t encryptedLen = len - (encrypted - buf);
  if (encryptedLen > 0) {
    m_SessionKeyDecryption.SetIV(pkt.IV());
    m_SessionKeyDecryption.Decrypt(
        encrypted,
        encryptedLen,
        encrypted);
  }
}

bool SSUSession::Validate(
    uint8_t* buf,
    size_t len,
    const uint8_t* macKey) {
  if (len < SSU_HEADER_SIZE_MIN) {
    LogPrint(eLogError, "Unexpected SSU packet length ", len);
    return false;
  }
  SSUSessionPacket pkt(buf, len);
  uint8_t * encrypted = pkt.Encrypted();
  uint16_t encryptedLen = len - (encrypted - buf);
  // assume actual buffer size is 18 (16 + 2) bytes more
  memcpy(buf + len, pkt.IV(), 16);
  htobe16buf(buf + len + 16, encryptedLen);
  uint8_t digest[16];
  i2p::crypto::HMACMD5Digest(
      encrypted,
      encryptedLen + 18,
      macKey,
      digest);
  return !memcmp(pkt.MAC(), digest, 16);
}

void SSUSession::Connect() {
  if (m_State == eSessionStateUnknown) {
    // set connect timer
    ScheduleConnectTimer();
    m_DHKeysPair = transports.GetNextDHKeysPair();
    SendSessionRequest();
  }
}

void SSUSession::WaitForConnect() {
  if (IsOutbound())
    LogPrint(eLogError, "SSU wait for connect for outgoing session");
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
    LogPrint("SSU session was not established after ",
        SSU_CONNECT_TIMEOUT, " second");
    Failed();
  }
}

void SSUSession::Introduce(
    uint32_t iTag,
    const uint8_t* iKey) {
  if (m_State == eSessionStateUnknown) {
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
  SendRelayRequest(iTag, iKey);
}

void SSUSession::WaitForIntroduction() {
  m_State = eSessionStateIntroduced;
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
  m_State = eSessionStateClosed;
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
  m_SessionConfirmData = nullptr;
  m_State = eSessionStateEstablished;
  if (m_DHKeysPair) {
    delete m_DHKeysPair;
    m_DHKeysPair = nullptr;
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
  if (m_State != eSessionStateFailed) {
    m_State = eSessionStateFailed;
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
    LogPrint("SSU no activity for ", SSU_TERMINATION_TIMEOUT, " seconds");
    Failed();
  }
}

const uint8_t* SSUSession::GetIntroKey() const {
  if (m_RemoteRouter) {
    // we are client
    auto address = m_RemoteRouter->GetSSUAddress();
    return address ? (const uint8_t *)address->key : nullptr;
  } else {
    // we are server
    auto address = i2p::context.GetRouterInfo().GetSSUAddress();
    return address ? (const uint8_t *)address->key : nullptr;
  }
}

void SSUSession::SendI2NPMessages(
    const std::vector<std::shared_ptr<I2NPMessage> >& msgs) {
  GetService().post(
      std::bind(
        &SSUSession::PostI2NPMessages,
        shared_from_this(),
        msgs));
}

void SSUSession::PostI2NPMessages(
    std::vector<std::shared_ptr<I2NPMessage> > msgs) {
  if (m_State == eSessionStateEstablished) {
    for (auto it : msgs)
      if (it)
        m_Data.Send(it);
  }
}

void SSUSession::ProcessData(
    SSUSessionPacket & pkt) {
  m_Data.ProcessMessage(pkt.bodyptr, pkt.bodylen);
  m_IsDataReceived = true;
}

void SSUSession::FlushData() {
  if (m_IsDataReceived) {
    m_Data.FlushReceivedMessage();
    m_IsDataReceived = false;
  }
}

void SSUSession::ProcessPeerTest(
    SSUSessionPacket& pkt,
    const boost::asio::ip::udp::endpoint& senderEndpoint) {
  uint8_t * buf = pkt.bodyptr;
  size_t len = pkt.bodylen;
  uint32_t nonce = bufbe32toh(buf);  // 4 bytes
  uint8_t size = buf[4];  // 1 byte
  uint32_t address = (size == 4) ?
    buf32toh(buf + 5) :
    0;  // big endian, size bytes
  uint16_t port = buf16toh(buf + size + 5);  // big endian, 2 bytes
  const uint8_t* introKey = buf + size + 7;
  if (port && !address) {
    LogPrint(eLogWarning, "Address of ", size, " bytes not supported");
    return;
  }
  switch (m_Server.GetPeerTestParticipant(nonce)) {
    // existing test
    case ePeerTestParticipantAlice1: {
      if (m_State == eSessionStateEstablished) {
        LogPrint(eLogDebug, "SSU peer test from Bob. We are Alice");
        if (i2p::context.GetStatus() == eRouterStatusTesting)  // still not OK
          i2p::context.SetStatus(eRouterStatusFirewalled);
      } else {
        LogPrint(eLogDebug, "SSU first peer test from Charlie. We are Alice");
        i2p::context.SetStatus(eRouterStatusOK);
        m_Server.UpdatePeerTest(
            nonce,
            ePeerTestParticipantAlice2);
        SendPeerTest(
            nonce,
            senderEndpoint.address().to_v4().to_ulong(),
            senderEndpoint.port(),
            introKey,
            true,
            false);  // to Charlie
      }
      break;
    }
    case ePeerTestParticipantAlice2: {
      if (m_State == eSessionStateEstablished) {
        LogPrint(eLogDebug, "SSU peer test from Bob. We are Alice");
      } else {
        // peer test successive
        LogPrint(eLogDebug, "SSU second peer test from Charlie. We are Alice");
        i2p::context.SetStatus(eRouterStatusOK);
        m_Server.RemovePeerTest(nonce);
      }
      break;
    }
    case ePeerTestParticipantBob: {
      LogPrint(eLogDebug, "SSU peer test from Charlie. We are Bob");
      // session with Alice from PeerTest
      auto session = m_Server.GetPeerTestSession(nonce);
      if (session && session->m_State == eSessionStateEstablished)
        session->Send(  // back to Alice
            PAYLOAD_TYPE_PEER_TEST,
            buf,
            len);
      m_Server.RemovePeerTest(nonce);  // nonce has been used
      break;
    }
    case ePeerTestParticipantCharlie: {
      LogPrint(eLogDebug, "SSU peer test from Alice. We are Charlie");
      SendPeerTest(
          nonce,
          senderEndpoint.address().to_v4().to_ulong(),
          senderEndpoint.port(),
          introKey);  // to Alice with her actual address
      m_Server.RemovePeerTest(nonce);  // nonce has been used
      break;
    }
    // test not found
    case ePeerTestParticipantUnknown: {
      if (m_State == eSessionStateEstablished) {
        // new test
        if (port) {
          LogPrint(eLogDebug, "SSU peer test from Bob. We are Charlie");
          m_Server.NewPeerTest(nonce, ePeerTestParticipantCharlie);
          Send(  // back to Bob
              PAYLOAD_TYPE_PEER_TEST,
              buf,
              len);
          SendPeerTest(  // to Alice with her address received from Bob
              nonce,
              be32toh(address),
              be16toh(port),
              introKey);
        } else {
          LogPrint(eLogDebug, "SSU peer test from Alice. We are Bob");
          auto session =
            m_Server.GetRandomEstablishedSession(
                shared_from_this());  // Charlie
          if (session) {
            m_Server.NewPeerTest(
                nonce,
                ePeerTestParticipantBob,
                shared_from_this());
            session->SendPeerTest(
                nonce,
                senderEndpoint.address().to_v4().to_ulong(),
                senderEndpoint.port(),
                introKey,
                false);  // to Charlie with Alice's actual address
          }
        }
      } else {
        LogPrint(eLogError, "SSU unexpected peer test");
      }
    }
  }
}

void SSUSession::SendPeerTest(
    uint32_t nonce,
    uint32_t address,
    uint16_t port,
    const uint8_t* introKey,
    bool toAddress,  // is true for Alice<->Charlie communications only
    bool sendAddress) {  // is false if message comes from Alice
  uint8_t buf[80 + 18] = {};
  uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
  htobe32buf(payload, nonce);
  payload += 4;  // nonce
  // address and port
  if (sendAddress && address) {
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
  if (toAddress) {
    // send our intro key to address instead it's own
    auto addr = i2p::context.GetRouterInfo().GetSSUAddress();
    if (addr)
      memcpy(payload, addr->key, 32);  // intro key
    else
      LogPrint(eLogError, "SSU is not supported. Can't send peer test");
  } else {
    memcpy(payload, introKey, 32);  // intro key
  }
  // send
  uint8_t iv[16];
  i2p::crypto::RandBytes(iv, 16);
  if (toAddress) {
    // encrypt message with specified intro key
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_PEER_TEST,
        buf,
        80,
        introKey,
        iv,
        introKey);
    boost::asio::ip::udp::endpoint e(
        boost::asio::ip::address_v4(
          address),
        port);
    m_Server.Send(buf, 80, e);
  } else {
    // encrypt message with session key
    FillHeaderAndEncrypt(
        PAYLOAD_TYPE_PEER_TEST,
        buf,
        80);
    Send(buf, 80);
  }
}

void SSUSession::SendPeerTest() {
  // we are Alice
  LogPrint(eLogDebug, "SSU sending peer test");
  auto address = i2p::context.GetRouterInfo().GetSSUAddress();
  if (!address) {
    LogPrint(eLogError, "SSU is not supported. Can't send peer test");
    return;
  }
  uint32_t nonce = i2p::crypto::Rand<uint32_t>();
  if (!nonce)
    nonce = 1;
  m_PeerTest = false;
  m_Server.NewPeerTest(nonce, ePeerTestParticipantAlice1);
  SendPeerTest(
      nonce,
      0,  // address and port always zero for Alice
      0,  // ^
      address->key,
      false,
      false);
}

void SSUSession::SendKeepAlive() {
  if (m_State == eSessionStateEstablished) {
    uint8_t buf[48 + 18] = {};
    uint8_t* payload = buf + SSU_HEADER_SIZE_MIN;
    *payload = 0;  // flags
    payload++;
    *payload = 0;  // num fragments
    // encrypt message with session key
    FillHeaderAndEncrypt(PAYLOAD_TYPE_DATA, buf, 48);
    Send(buf, 48);
    LogPrint(eLogDebug, "SSU keep-alive sent");
    ScheduleTermination();
  }
}

void SSUSession::SendSesionDestroyed() {
  if (m_IsSessionKey) {
    uint8_t buf[48 + 18] = {};
    // encrypt message with session key
    FillHeaderAndEncrypt(PAYLOAD_TYPE_SESSION_DESTROYED, buf, 48);
    try {
      Send(buf, 48);
    } catch(std::exception& ex) {
      LogPrint(eLogError, "SSU send session destroyed exception ", ex.what());
    }
    LogPrint(eLogDebug, "SSU session destroyed sent");
  }
}

void SSUSession::Send(
    uint8_t type,
    const uint8_t* payload,
    size_t len) {
  uint8_t buf[SSU_MTU_V4 + 18] = {};
  size_t msgSize = len + SSU_HEADER_SIZE_MIN;
  size_t paddingSize = msgSize & 0x0F;  // %16
  if (paddingSize > 0)
    msgSize += (16 - paddingSize);
  if (msgSize > SSU_MTU_V4) {
    LogPrint(eLogWarning, "SSU payload size ", msgSize, " exceeds MTU");
    return;
  }
  memcpy(buf + SSU_HEADER_SIZE_MIN, payload, len);
  // encrypt message with session key
  FillHeaderAndEncrypt(type, buf, msgSize);
  Send(buf, msgSize);
}

void SSUSession::Send(
    const uint8_t* buf,
    size_t size) {
  m_NumSentBytes += size;
  i2p::transport::transports.UpdateSentBytes(size);
  m_Server.Send(buf, size, m_RemoteEndpoint);
}

}  // namespace transport
}  // namespace i2p

