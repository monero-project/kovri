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
#include "SSUPacket.h"

#include <exception>

#include "util/Log.h"
#include "util/Timestamp.h"
#include "util/I2PEndian.h"
#include "crypto/Rand.h"

namespace i2p {
namespace transport {

constexpr std::size_t SSU_KEYING_MATERIAL_SIZE = 64;
constexpr std::size_t SSU_DH_PUBLIC_SIZE = 256;
const uint8_t SSU_FLAG_REKEY = 0x08;

// Data message flags
const uint8_t DATA_FLAG_EXTENDED_DATA_INCLUDED = 0x02;
const uint8_t DATA_FLAG_WANT_REPLY = 0x04;
const uint8_t DATA_FLAG_REQUEST_PREVIOUS_ACKS = 0x08;
const uint8_t DATA_FLAG_EXPLICIT_CONGESTION_NOTIFICATION = 0x10;
const uint8_t DATA_FLAG_ACK_BITFIELDS_INCLUDED = 0x40;
const uint8_t DATA_FLAG_EXPLICIT_ACKS_INCLUDED = 0x80;
const uint8_t DATA_FLAG_ACK_BITFIELD_HAS_NEXT = 0x80;

SSUHeader::SSUHeader(PayloadType type, uint8_t* mac, uint8_t* iv,
    uint32_t time)
  : m_Mac(mac), m_Iv(iv), m_Rekey(false), m_Extended(false),
    m_Time(time), m_PayloadType(type) {
}

void SSUHeader::SetMac(uint8_t* macPtr) {
  m_Mac = macPtr;
}

uint8_t const* SSUHeader::GetMac() const {
  return m_Mac;
}

void SSUHeader::SetIv(uint8_t* ivPtr) {
  m_Iv = ivPtr;
}

uint8_t const* SSUHeader::GetIv() const {
  return m_Iv;
}

void SSUHeader::SetPayloadType(short type) {
  if (type < 0 || type > 8)
      throw std::invalid_argument("SSUHeader::SetPayloadType invalid type given");
  m_PayloadType = static_cast<PayloadType>(type);
}

SSUHeader::PayloadType SSUHeader::GetPayloadType() const {
  return m_PayloadType;
}

void SSUHeader::SetRekey(bool rekey) {
  m_Rekey = rekey;
}

void SSUHeader::SetExtendedOptionsData(uint8_t* data,
    std::size_t size) {
  m_ExtendedOptionsSize = size;
  m_ExtendedOptions = data;
}

uint8_t const* SSUHeader::GetExtendedOptionsData() const {
  return m_ExtendedOptions;
}

std::size_t SSUHeader::GetExtendedOptionsSize() const {
  return m_ExtendedOptionsSize;
}

void SSUHeader::SetExtendedOptions(bool extended) {
  m_Extended = extended;
}

void SSUHeader::SetTime(uint32_t time) {
  m_Time = time;
}

uint32_t SSUHeader::GetTime() const {
  return m_Time;
}

bool SSUHeader::HasRekey() const {
  return m_Rekey;
}

bool SSUHeader::HasExtendedOptions() const {
  return m_Extended;
}

std::size_t SSUHeader::GetSize() const {
  std::size_t size = SSU_HEADER_SIZE_MIN;
  if(HasRekey())
    size += SSU_KEYING_MATERIAL_SIZE;
  if(HasExtendedOptions())
    size += m_ExtendedOptionsSize + 1;
  return size;
}

void SSUPacket::SetHeader(std::unique_ptr<SSUHeader> header) {
  m_Header = std::move(header);
}

SSUHeader* SSUPacket::GetHeader() const {
  return m_Header.get();
}

std::size_t SSUPacket::GetSize() const {
  return m_Header ? m_Header->GetSize() : 0;
}

void SSUSessionRequestPacket::SetDhX(uint8_t* dhX) {
  m_DhX = dhX;
}

uint8_t const* SSUSessionRequestPacket::GetDhX() const {
  return m_DhX;
}

void SSUSessionRequestPacket::SetIpAddress(uint8_t* ip, std::size_t size) {
  m_IpAddressSize = size;
  m_IpAddress = ip;
}

uint8_t const* SSUSessionRequestPacket::GetIpAddress() const {
  return m_IpAddress;
}

std::size_t SSUSessionRequestPacket::GetIpAddressSize() const {
  return m_IpAddressSize;
}

std::size_t SSUSessionRequestPacket::GetSize() const {
  // DH X-parameter, address (and size)
  return SSUPacket::GetSize() + SSU_DH_PUBLIC_SIZE + 1 + m_IpAddressSize;
}

void SSUSessionCreatedPacket::SetDhY(uint8_t* dhY) {
  m_DhY = dhY;
}

uint8_t const* SSUSessionCreatedPacket::GetDhY() const {
  return m_DhY;
}

void SSUSessionCreatedPacket::SetIpAddress(uint8_t* ip, std::size_t size) {
  m_IpAddress = ip;
  m_AddressSize = size;
}

uint8_t const* SSUSessionCreatedPacket::GetIpAddress() const {
  return m_IpAddress;
}

std::size_t SSUSessionCreatedPacket::GetIpAddressSize() const {
  return m_AddressSize;
}

void SSUSessionCreatedPacket::SetPort(uint16_t port) {
  m_Port = port;
}

uint16_t SSUSessionCreatedPacket::GetPort() const {
  return m_Port;
}

void SSUSessionCreatedPacket::SetRelayTag(uint32_t relayTag) {
  m_RelayTag = relayTag;
}

uint32_t SSUSessionCreatedPacket::GetRelayTag() const {
  return m_RelayTag;
}

void SSUSessionCreatedPacket::SetSignature(uint8_t* signature,
    std::size_t size) {
  m_SignatureSize = size;
  m_Signature = signature;
}

uint8_t* SSUSessionCreatedPacket::GetSignature() const {
  return m_Signature;
}

std::size_t SSUSessionCreatedPacket::GetSignatureSize() const {
  return m_SignatureSize;
}

void SSUSessionCreatedPacket::SetSignedOnTime(uint32_t time) {
  m_SignedOnTime = time;
}

uint32_t SSUSessionCreatedPacket::GetSignedOnTime() const {
  return m_SignedOnTime;
}

std::size_t SSUSessionCreatedPacket::GetSize() const {
  // DH X-parameter, 1 byte address size, address size,
  //    port size (2 bytes), relay tag size, time size,
  //    signature size
  return SSUPacket::GetSize() + SSU_DH_PUBLIC_SIZE + 1 + m_AddressSize
    + 2 + 4 + 4 + m_SignatureSize;
}

void SSUSessionConfirmedPacket::SetRemoteRouterIdentity(
    const i2p::data::IdentityEx& identity) {
  m_RemoteIdentity = identity;
}

i2p::data::IdentityEx SSUSessionConfirmedPacket::GetRemoteRouterIdentity() const {
  return m_RemoteIdentity;
}

void SSUSessionConfirmedPacket::SetSignature(uint8_t* signature) {
  m_Signature = signature;
}

uint8_t const* SSUSessionConfirmedPacket::GetSignature() const {
  return m_Signature;
}

void SSUSessionConfirmedPacket::SetSignedOnTime(uint32_t time) {
  m_SignedOnTime = time;
}

uint32_t SSUSessionConfirmedPacket::GetSignedOnTime() const {
  return m_SignedOnTime;
}

std::size_t SSUSessionConfirmedPacket::GetSize() const {
  // Identity size, signature size, time size
  return SSUPacket::GetSize() + m_RemoteIdentity.GetFullLen() 
    + m_RemoteIdentity.GetSignatureLen() + 4;
}

void SSURelayRequestPacket::SetRelayTag(uint32_t relayTag) {
  m_RelayTag = relayTag;
}

uint32_t SSURelayRequestPacket::GetRelayTag() const {
  return m_RelayTag;
}

void SSURelayRequestPacket::SetIpAddress(uint8_t* ipAddress, std::size_t size) {
  m_IpAddressSize = size;
  m_IpAddress = ipAddress;
}

uint8_t const* SSURelayRequestPacket::GetIpAddress() const {
  return m_IpAddress;
}

void SSURelayRequestPacket::SetChallenge(uint8_t* challenge, std::size_t size) {
  m_ChallengeSize = size;
  m_Challenge = challenge;
}

uint8_t const* SSURelayRequestPacket::GetChallenge() const {
  return m_Challenge;
}

void SSURelayRequestPacket::SetPort(uint16_t port) {
  m_Port = port;
}

uint16_t SSURelayRequestPacket::GetPort() const {
  return m_Port;
}

void SSURelayRequestPacket::SetIntroKey(uint8_t* key) {
  m_IntroKey = key;
}

uint8_t const* SSURelayRequestPacket::GetIntroKey() const {
  return m_IntroKey;
}

void SSURelayRequestPacket::SetNonce(uint32_t nonce) {
  m_Nonce = nonce;
}

uint32_t SSURelayRequestPacket::GetNonce() const {
  return m_Nonce;
}

std::size_t SSURelayRequestPacket::GetSize() const {
  // Relay tag, nonce, address (and size), port,
  //       challenge (and size), intro key
  return SSUPacket::GetSize() + 4 + 4 + m_IpAddressSize + 1
    + 2 + m_ChallengeSize + 1 + SSU_INTRO_KEY_SIZE;
}

void SSURelayResponsePacket::SetNonce(uint32_t nonce) {
  m_Nonce = nonce;
}

uint32_t SSURelayResponsePacket::GetNonce() const {
  return m_Nonce;
}

void SSURelayResponsePacket::SetIpAddressAlice(uint8_t* ipAddress, std::size_t size) {
  m_IpAddressAliceSize = size;
  m_IpAddressAlice = ipAddress;
}

uint8_t const* SSURelayResponsePacket::GetIpAddressAlice() const {
  return m_IpAddressAlice;
}

std::size_t SSURelayResponsePacket::GetIpAddressAliceSize() const {
  return m_IpAddressAliceSize;
}

void SSURelayResponsePacket::SetIpAddressCharlie(uint8_t* ipAddress,
    std::size_t size) {
  m_IpAddressCharlieSize = size;
  m_IpAddressCharlie = ipAddress;
}

uint8_t const* SSURelayResponsePacket::GetIpAddressCharlie() const {
  return m_IpAddressCharlie;
}

void SSURelayResponsePacket::SetPortAlice(uint16_t port) {
  m_PortAlice = port;
}

uint16_t SSURelayResponsePacket::GetPortAlice() const {
  return m_PortAlice;
}

void SSURelayResponsePacket::SetPortCharlie(uint16_t port) {
  m_PortCharlie = port;
}

uint16_t SSURelayResponsePacket::GetPortCharlie() const {
  return m_PortCharlie;
}

std::size_t SSURelayResponsePacket::GetSize() const {
  // Nonce, address (and size) for Alice and Charlie,
  //    port for Alice and Charlie
  return SSUPacket::GetSize() + 4 + m_IpAddressAliceSize + 1 +
    m_IpAddressCharlieSize + 1 + 2 + 2;
}

void SSURelayIntroPacket::SetIpAddress(uint8_t* ipAddress, std::size_t size) {
  m_IpAddressSize = size;
  m_IpAddress = ipAddress;
}

uint8_t const* SSURelayIntroPacket::GetIpAddress() const {
  return m_IpAddress;
}

std::size_t SSURelayIntroPacket::GetIpAddressSize() const {
  return m_IpAddressSize;
}

void SSURelayIntroPacket::SetChallenge(uint8_t* challenge, std::size_t size) {
  m_ChallengeSize = size;
  m_Challenge = challenge;
}

uint8_t const* SSURelayIntroPacket::GetChallenge() const {
  return m_Challenge;
}

void SSURelayIntroPacket::SetPort(uint16_t port) {
  m_Port = port;
}

uint16_t SSURelayIntroPacket::GetPort() const {
  return m_Port;
}

std::size_t SSURelayIntroPacket::GetSize() const {
  // Address (and size), challenge (and size), port
  return SSUPacket::GetSize() + m_IpAddressSize + 1
    + m_ChallengeSize + 1 + 2;
}

std::size_t SSUFragment::GetSize() const {
  return m_Size;
}

void SSUFragment::SetMessageId(uint32_t messageId) {
  m_MessageId = messageId;
}

void SSUFragment::SetNumber(uint8_t number) {
  m_Number = number;
}

void SSUFragment::SetIsLast(bool isLast) {
  m_IsLast = isLast;
}

void SSUFragment::SetSize(std::size_t size) {
  m_Size = size;
}

void SSUFragment::SetData(uint8_t* data) {
  m_Data = data;
}

void SSUDataPacket::AddExplicitACK(uint32_t messageId) {
  m_ExplicitACKs.push_back(messageId);
}

void SSUDataPacket::AddACK(uint32_t messageId) {
  m_ACKs.push_back(messageId);
}

void SSUDataPacket::AddACKBitfield(uint8_t bitfield) {
  m_ACKBitfields.push_back(bitfield);
}

void SSUDataPacket::AddFragment(SSUFragment fragment) {
  m_Fragments.push_back(fragment);
}

std::size_t SSUDataPacket::GetSize() const {
  // Flag, number of fragments
  std::size_t size = SSUPacket::GetSize() + 1 + 1;
  // Explicit ACKs
  if(!m_ExplicitACKs.empty())
    size += 1 + m_ExplicitACKs.size() * 4;
  // ACK bitfields
  if(!m_ACKs.empty())
    size += 1 + m_ACKs.size() * (4 + 1);
  // TODO(EinMByte): Count extended data
  for(const SSUFragment& frag : m_Fragments)
    size += frag.GetSize() + 4 + 3;
  return size;
}

void SSUPeerTestPacket::SetNonce(uint32_t nonce) {
  m_Nonce = nonce;
}

uint32_t SSUPeerTestPacket::GetNonce() const {
  return m_Nonce;
}

void SSUPeerTestPacket::SetIpAddress(uint32_t ipAddress) {
  m_IpAddress = ipAddress;
}

uint32_t SSUPeerTestPacket::GetIpAddress() const {
  return m_IpAddress;
}

void SSUPeerTestPacket::SetPort(uint16_t port) {
  m_Port = port;
}

uint16_t SSUPeerTestPacket::GetPort() const {
  return m_Port;
}

void SSUPeerTestPacket::SetIntroKey(uint8_t* introKey) {
  m_IntroKey = introKey;
}

uint8_t const* SSUPeerTestPacket::GetIntroKey() const {
  return m_IntroKey;
}

std::size_t SSUPeerTestPacket::GetSize() const {
  // Nonce, address (IPv4), port, intro key
  return SSUPacket::GetSize() + 1 + 4 + 2 + SSU_INTRO_KEY_SIZE;
}

void SSUPacketParser::ConsumeData(std::size_t amount) {
  if (amount > m_Length)
    throw std::length_error("SSUPacketParser: too many bytes to consume.");
  m_Data += amount;
  m_Length -= amount;
}

uint8_t* SSUPacketParser::ReadBytes(std::size_t amount) {
  uint8_t* ptr = m_Data;
  ConsumeData(amount);
  return ptr;
}

uint32_t SSUPacketParser::ReadUInt32() {
  return bufbe32toh(ReadBytes(4));
}

uint16_t SSUPacketParser::ReadUInt16() {
  return bufbe16toh(ReadBytes(2));
}

uint8_t SSUPacketParser::ReadUInt8() {
  return *ReadBytes(1);
}

SSUFragment SSUPacketParser::ParseFragment() {
  SSUFragment fragment;
  fragment.SetMessageId(ReadUInt32());
  // TODO(EinMByte): clean this up
  uint8_t infoBuf[4] = {};
  memcpy(infoBuf + 1, ReadBytes(3), 3);
  const uint32_t fragmentInfo = bufbe32toh(infoBuf);
  fragment.SetSize(fragmentInfo & 0x3FFF); // bits 0 - 13
  fragment.SetIsLast(fragmentInfo & 0x010000); // bit 16
  fragment.SetNumber(fragmentInfo >> 17); // bits 23 - 17
  // TODO(EinMByte): Check whether the size is correct
  fragment.SetData(ReadBytes(fragment.GetSize()));
  return fragment;
}

SSUPacketParser::SSUPacketParser(uint8_t* data, std::size_t len)
  : m_Data(data), m_Length(len) {

}

std::unique_ptr<SSUHeader> SSUPacketParser::ParseHeader() {
  if (m_Length < SSU_HEADER_SIZE_MIN)
    throw std::length_error("SSU header too small");
  std::unique_ptr<SSUHeader> header(new SSUHeader());
  // Set MAC and IV
  header->SetMac(ReadBytes(SSU_MAC_SIZE));
  header->SetIv(ReadBytes(SSU_IV_SIZE));

  // Extract information from flag (payload type and rekey/extened options)
  const uint8_t flag = ReadUInt8(); 
  header->SetRekey(flag & SSU_FLAG_REKEY);
  header->SetExtendedOptions(flag & SSU_FLAG_EXTENDED_OPTIONS);
  header->SetPayloadType(flag >> 4);

  // Extract the time
  header->SetTime(ReadUInt32());

  if (header->HasRekey()) {
    // TODO(EinMByte): Actually do something with the data
    // TODO(EinMByte): See issue #119, for some reason some rekey options
    //                 are sometimes set?
    ConsumeData(SSU_KEYING_MATERIAL_SIZE);  
  }

  if (header->HasExtendedOptions()) {
    const std::size_t optionsSize = ReadUInt8();
    header->SetExtendedOptionsData(ReadBytes(optionsSize), optionsSize);
  }
  return header;
}

std::unique_ptr<SSUPacket> SSUPacketParser::ParsePacket() {
  std::unique_ptr<SSUHeader> header(ParseHeader()); 

  std::unique_ptr<SSUPacket> packet;

  uint8_t* const dataOld = m_Data;
  const std::size_t lengthOld = m_Length;

  switch(header->GetPayloadType()) {
    case SSUHeader::PayloadType::SessionRequest:
      packet = ParseSessionRequest();
      break;
    case SSUHeader::PayloadType::SessionCreated:
      packet = ParseSessionCreated();
      break;
    case SSUHeader::PayloadType::SessionConfirmed:
      packet = ParseSessionConfirmed();
      break;
    case SSUHeader::PayloadType::RelayRequest:
      packet = ParseRelayRequest();
      break;
    case SSUHeader::PayloadType::RelayResponse:
      packet = ParseRelayResponse();
      break;
    case SSUHeader::PayloadType::RelayIntro:
      packet = ParseRelayIntro();
      break;
    case SSUHeader::PayloadType::Data:
      packet = ParseData();
      break;
    case SSUHeader::PayloadType::PeerTest:
      packet = ParsePeerTest();
      break;
    case SSUHeader::PayloadType::SessionDestroyed:
      packet = ParseSessionDestroyed();
      break;
  }
  // TODO(EinMByte): Get rid of this
  packet->m_RawDataLength = lengthOld;
  packet->m_RawData = dataOld;
  packet->SetHeader(std::move(header));

  return packet;
}

std::unique_ptr<SSUSessionRequestPacket> SSUPacketParser::ParseSessionRequest() {
  std::unique_ptr<SSUSessionRequestPacket> packet(
      new SSUSessionRequestPacket());
  packet->SetDhX(ReadBytes(SSU_DH_PUBLIC_SIZE));
  std::size_t size = ReadUInt8();
  packet->SetIpAddress(ReadBytes(size), size);
  return packet; 
}

std::unique_ptr<SSUSessionCreatedPacket> SSUPacketParser::ParseSessionCreated() {
  std::unique_ptr<SSUSessionCreatedPacket> packet(
      new SSUSessionCreatedPacket());
  packet->SetDhY(ReadBytes(SSU_DH_PUBLIC_SIZE));
  std::size_t addressSize = ReadUInt8();
  packet->SetIpAddress(ReadBytes(addressSize), addressSize);
  packet->SetPort(ReadUInt16());
  packet->SetRelayTag(ReadUInt32());
  packet->SetSignedOnTime(ReadUInt32());
  packet->SetSignature(m_Data, m_Length);
  return packet; 
}

std::unique_ptr<SSUSessionConfirmedPacket> SSUPacketParser::ParseSessionConfirmed() {
  const std::size_t initLength = m_Length;
  std::unique_ptr<SSUSessionConfirmedPacket> packet(
      new SSUSessionConfirmedPacket());

  ConsumeData(1);  // Skip info byte
  uint16_t identitySize = ReadUInt16();
  i2p::data::IdentityEx identity;
  identity.FromBuffer(ReadBytes(identitySize), identitySize);
  packet->SetRemoteRouterIdentity(identity);
  packet->SetSignedOnTime(ReadUInt32());
  const std::size_t paddingSize = ((m_Length - initLength) + identity.GetSignatureLen()) % 16;
  ConsumeData(paddingSize);  // Skip padding
  packet->SetSignature(m_Data);
  return packet;
}

std::unique_ptr<SSURelayRequestPacket> SSUPacketParser::ParseRelayRequest() {
  std::unique_ptr<SSURelayRequestPacket> packet(
      new SSURelayRequestPacket());
  packet->SetRelayTag(ReadUInt32());
  const std::size_t ipAddressSize = ReadUInt8();
  packet->SetIpAddress(ReadBytes(ipAddressSize), ipAddressSize);
  packet->SetPort(ReadUInt16());
  const std::size_t challengeSize = ReadUInt8();
  packet->SetChallenge(ReadBytes(challengeSize), challengeSize);
  packet->SetIntroKey(ReadBytes(SSU_INTRO_KEY_SIZE));
  packet->SetNonce(ReadUInt32());

  return packet;
}

std::unique_ptr<SSURelayResponsePacket> SSUPacketParser::ParseRelayResponse() {
  std::unique_ptr<SSURelayResponsePacket> packet(
      new SSURelayResponsePacket());
  const std::size_t ipAddressCharlieSize = ReadUInt8();
  packet->SetIpAddressCharlie(ReadBytes(ipAddressCharlieSize), ipAddressCharlieSize);
  packet->SetPortCharlie(ReadUInt16());
  const std::size_t ipAddressAliceSize = ReadUInt8();
  packet->SetIpAddressAlice(ReadBytes(ipAddressAliceSize), ipAddressAliceSize);
  packet->SetPortAlice(ReadUInt16());
  packet->SetNonce(ReadUInt32());

  return packet;
}

std::unique_ptr<SSURelayIntroPacket> SSUPacketParser::ParseRelayIntro() {
  std::unique_ptr<SSURelayIntroPacket> packet(
      new SSURelayIntroPacket());
  const std::size_t ipAddressSize = ReadUInt8();
  packet->SetIpAddress(ReadBytes(ipAddressSize), ipAddressSize);
  packet->SetPort(ReadUInt16());
  const std::size_t challengeSize = ReadUInt8();
  packet->SetChallenge(ReadBytes(challengeSize), challengeSize);
  return packet;
}

std::unique_ptr<SSUDataPacket> SSUPacketParser::ParseData() {
  std::unique_ptr<SSUDataPacket> packet(new SSUDataPacket());

  const uint8_t flags = ReadUInt8();

  // Read ACKS
  if(flags & DATA_FLAG_EXPLICIT_ACKS_INCLUDED) {
    const std::size_t nbExplicitACKs = ReadUInt8();
    for(std::size_t i = 0; i < nbExplicitACKs; ++i)
      packet->AddExplicitACK(ReadUInt32());
  }
  // Read ACK bifields
  if(flags & DATA_FLAG_ACK_BITFIELDS_INCLUDED) {
    const std::size_t nbACKs = ReadUInt8();
    // Read message IDs
    for(std::size_t i = 0; i < nbACKs; ++i)
      packet->AddACK(ReadUInt32());
    // Read bitfields
    uint8_t bitfield;
    do {
      bitfield = ReadUInt8();
      packet->AddACKBitfield(bitfield);
    } while(bitfield & DATA_FLAG_ACK_BITFIELD_HAS_NEXT);
  }
  // Ignore possible extended data
  if(flags & DATA_FLAG_EXTENDED_DATA_INCLUDED)
    ReadBytes(ReadUInt8());

  const std::size_t nbFlags = ReadUInt8();
  // Read fragments
  for(std::size_t i = 0; i < nbFlags; ++i)
    packet->AddFragment(ParseFragment());
  return packet;
}

std::unique_ptr<SSUPeerTestPacket> SSUPacketParser::ParsePeerTest() {
  std::unique_ptr<SSUPeerTestPacket> packet(
      new SSUPeerTestPacket());
  packet->SetNonce(ReadUInt32());
  // TODO(EinMByte): Handle other address sizes, or deal with the errors.
  packet->SetIpAddress(buf32toh(ReadBytes((ReadUInt8() == 4) ? 4 : 0)));
  packet->SetPort(ReadUInt16());
  packet->SetIntroKey(ReadBytes(SSU_INTRO_KEY_SIZE));
  return packet;

}

std::unique_ptr<SSUSessionDestroyedPacket> SSUPacketParser::ParseSessionDestroyed() {
  std::unique_ptr<SSUSessionDestroyedPacket> packet(
      new SSUSessionDestroyedPacket());
  return packet;
}

namespace SSUPacketBuilder {

void WriteData(uint8_t*& pos, const uint8_t* data, std::size_t len) {
  memcpy(pos, data, len);
  pos += len;
}

void WriteUInt8(uint8_t*& pos, uint8_t data) {
  *(pos++) = data;
}

void WriteUInt16(uint8_t*& pos, uint16_t data) {
  htobe16buf(pos, data);
  pos += 2;
}

void WriteUInt32(uint8_t*& pos, uint32_t data) {
  htobe32buf(pos, data);
  pos += 4;
}

void WriteHeader(uint8_t*& data, SSUHeader* header) {
  WriteData(data, header->GetMac(), SSU_MAC_SIZE);
  WriteData(data, header->GetIv(), SSU_IV_SIZE);
  const uint8_t flag =
      (static_cast<uint8_t>(header->GetPayloadType()) << 4)
      + (header->HasRekey() << 3)
      + (header->HasExtendedOptions() << 2);
  WriteUInt8(data, flag);
  WriteUInt32(data, header->GetTime());
  if(header->HasExtendedOptions()) {
    // TODO(EinMByte): Check for overflow
    WriteUInt8(data, header->GetExtendedOptionsSize());
    WriteData(
        data,
        header->GetExtendedOptionsData(),
        header->GetExtendedOptionsSize());
  }
}

std::unique_ptr<uint8_t> BuildSessionRequest(
    const SSUSessionRequestPacket& packet) {
  std::unique_ptr<uint8_t> buffer(new uint8_t[packet.GetSize()]);
  uint8_t* buf = buffer.get();
  if(packet.GetHeader())
    WriteHeader(buf, packet.GetHeader());
  WriteData(buf, packet.GetDhX(), SSU_DH_PUBLIC_SIZE);
  // TODO(EinMByte): Check for overflow
  WriteUInt8(buf, packet.GetIpAddressSize());
  WriteData(buf, packet.GetIpAddress(), packet.GetIpAddressSize());
  return buffer;
}

std::unique_ptr<uint8_t> BuildSessionCreated(
    const SSUSessionCreatedPacket& packet) {
  std::unique_ptr<uint8_t> buffer(new uint8_t[packet.GetSize()]);
  uint8_t* buf = buffer.get();
  if(packet.GetHeader())
    WriteHeader(buf, packet.GetHeader());
  WriteData(buf, packet.GetDhY(), SSU_DH_PUBLIC_SIZE);
  // TODO(EinMByte): Check for overflow
  WriteUInt8(buf, packet.GetIpAddressSize());
  WriteData(buf, packet.GetIpAddress(), packet.GetIpAddressSize());
  WriteUInt16(buf, packet.GetPort());
  WriteUInt32(buf, packet.GetRelayTag());
  WriteUInt32(buf, packet.GetSignedOnTime());
  WriteData(buf, packet.GetSignature(), packet.GetSignatureSize());
  return buffer;
}

std::unique_ptr<uint8_t> BuildSessionConfirmed(
    const SSUSessionConfirmedPacket& packet) {
  std::unique_ptr<uint8_t> buffer(new uint8_t[packet.GetSize()]);

}

std::unique_ptr<uint8_t> BuildRelayRequest(
    const SSURelayRequestPacket& packet) {
  std::unique_ptr<uint8_t> buffer(new uint8_t[packet.GetSize()]);

}

std::unique_ptr<uint8_t> BuildRelayResponse(
    const SSURelayResponsePacket& packet) {
  std::unique_ptr<uint8_t> buffer(new uint8_t[packet.GetSize()]);

}

std::unique_ptr<uint8_t> BuildRelayIntro(
    const SSURelayIntroPacket& packet) {
  std::unique_ptr<uint8_t> buffer(new uint8_t[packet.GetSize()]);

}

std::unique_ptr<uint8_t> BuildData(
    const SSUDataPacket& packet) {
  std::unique_ptr<uint8_t> buffer(new uint8_t[packet.GetSize()]);

}

std::unique_ptr<uint8_t> BuildPeerTest(
    const SSUPeerTestPacket& packet) {
  std::unique_ptr<uint8_t> buffer(new uint8_t[packet.GetSize()]);

}

std::unique_ptr<uint8_t> BuildSessionDestroyed(
    const SSUSessionDestroyedPacket& packet) {
  std::unique_ptr<uint8_t> buffer(new uint8_t[packet.GetSize()]);
}

}
}
}
