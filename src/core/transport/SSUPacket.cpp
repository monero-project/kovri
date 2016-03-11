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
#include "crypto/CryptoConst.h"

namespace i2p {
namespace transport {

constexpr std::size_t SSU_KEYING_MATERIAL_SIZE = 64;
const uint8_t SSU_FLAG_REKEY = 0x08;
const uint8_t SSU_FLAG_EXTENDED_OPTIONS = 0x04;

// Data message flags
const uint8_t DATA_FLAG_EXTENDED_DATA_INCLUDED = 0x02;
const uint8_t DATA_FLAG_WANT_REPLY = 0x04;
const uint8_t DATA_FLAG_REQUEST_PREVIOUS_ACKS = 0x08;
const uint8_t DATA_FLAG_EXPLICIT_CONGESTION_NOTIFICATION = 0x10;
const uint8_t DATA_FLAG_ACK_BITFIELDS_INCLUDED = 0x40;
const uint8_t DATA_FLAG_EXPLICIT_ACKS_INCLUDED = 0x80;
const uint8_t DATA_FLAG_ACK_BITFIELD_HAS_NEXT = 0x10;

void SSUHeader::SetMac(uint8_t* macPtr) {
  m_Mac = macPtr;
}
void SSUHeader::SetIv(uint8_t* ivPtr) {
  m_Iv = ivPtr;
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

void SSUPacket::SetHeader(std::unique_ptr<SSUHeader> header) {
  m_Header = std::move(header);
}

void SSUSessionRequestPacket::SetDhX(uint8_t* dhX) {
  m_DhX = dhX;
}

void SSUSessionRequestPacket::SetIpAddress(uint8_t* ip) {
  m_IpAddress = ip;
}

void SSUSessionCreatedPacket::SetDhY(uint8_t* dhY) {
  m_DhY = dhY;
}

void SSUSessionCreatedPacket::SetIpAddress(uint8_t* ip) {
  m_IpAddress = ip;
}

void SSUSessionCreatedPacket::SetPort(uint16_t port) {
  m_Port = port;
}

void SSUSessionCreatedPacket::SetRelayTag(uint32_t relayTag) {
  m_RelayTag = relayTag;
}

void SSUSessionCreatedPacket::SetSignature(uint8_t* signature) {
  m_Signature = signature;
}

void SSUSessionConfirmedPacket::SetRemoteRouterIdentity(
    const i2p::data::IdentityEx& identity) {
  m_RemoteIdentity = identity;
}

void SSURelayRequestPacket::SetRelayTag(uint32_t relayTag) {
  m_RelayTag = relayTag;
}

void SSURelayRequestPacket::SetIpAddress(uint8_t* ipAddress) {
  m_IpAddress = ipAddress;
}

void SSURelayRequestPacket::SetChallenge(uint8_t* challenge) {
  m_Challenge = challenge;
}

void SSURelayRequestPacket::SetPort(uint8_t port) {
  m_Port = port;
}

void SSURelayRequestPacket::SetIntroKey(uint8_t* key) {
  m_IntroKey = key;
}

void SSURelayRequestPacket::SetNonce(uint32_t nonce) {
  m_Nonce = nonce;
}

void SSURelayResponsePacket::SetNonce(uint32_t nonce) {
  m_Nonce = nonce;
}

void SSURelayResponsePacket::SetIpAddressAlice(uint8_t* ipAddress) {
  m_IpAddressAlice = ipAddress;
}

void SSURelayResponsePacket::SetIpAddressCharlie(uint8_t* ipAddress) {
  m_IpAddressCharlie = ipAddress;
}

void SSURelayResponsePacket::SetPortAlice(uint8_t port) {
  m_PortAlice = port;
}

void SSURelayResponsePacket::SetPortCharlie(uint8_t port) {
  m_PortCharlie = port;
}

void SSURelayIntroPacket::SetIpAddress(uint8_t* ipAddress) {
  m_IpAddress = ipAddress;
}

void SSURelayIntroPacket::SetChallenge(uint8_t* challenge) {
  m_Challenge = challenge;
}

void SSURelayIntroPacket::SetPort(uint8_t port) {
  m_Port = port;
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

void SSUDataPacket::AddACK(uint32_t messageId) {
  m_ACKs.push_back(messageId);
}

void SSUDataPacket::AddACKBitfield(uint8_t bitfield) {
  m_ACKBitfields.push_back(bitfield);
}

void SSUDataPacket::AddFragment(SSUFragment fragment) {
  m_Fragments.push_back(fragment);
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
    return nullptr; /// TODO(EinMByte): Do something meaningful
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
    ConsumeData(SSU_KEYING_MATERIAL_SIZE);  
  }

  if (header->HasExtendedOptions()) {
    // TODO(EinMByte): Actually do something with the options
    const std::size_t optionsSize = *m_Data;
    ConsumeData(optionsSize);
  }
  return header;
}

std::unique_ptr<SSUSessionRequestPacket> SSUPacketParser::ParseSessionRequest() {
  std::unique_ptr<SSUSessionRequestPacket> packet(
      new SSUSessionRequestPacket());
  packet->SetHeader(ParseHeader());
  packet->SetDhX(ReadBytes(16));
  packet->SetIpAddress(ReadBytes(ReadUInt8()));
  return packet; 
}

std::unique_ptr<SSUSessionCreatedPacket> SSUPacketParser::ParseSessionCreated() {
  std::unique_ptr<SSUSessionCreatedPacket> packet(
      new SSUSessionCreatedPacket());
  packet->SetHeader(ParseHeader());
  packet->SetDhY(ReadBytes(16));
  packet->SetIpAddress(ReadBytes(ReadUInt32()));
  packet->SetPort(ReadUInt16());
  packet->SetRelayTag(ReadUInt32());
  // Skip signed on time (4 bytes) 
  ConsumeData(4);
  packet->SetSignature(m_Data);
  return packet; 
}

std::unique_ptr<SSUSessionConfirmedPacket> SSUPacketParser::ParseSessionConfirmed() {
  const std::size_t initLength = m_Length;
  std::unique_ptr<SSUSessionConfirmedPacket> packet(
      new SSUSessionConfirmedPacket());
  packet->SetHeader(ParseHeader());

  ConsumeData(1);  // Skip info byte
  uint16_t identitySize = ReadUInt16();
  i2p::data::IdentityEx identity;
  identity.FromBuffer(ReadBytes(identitySize), identitySize);
  packet->SetRemoteRouterIdentity(identity);
  ConsumeData(4);  // Skip timestamp
  const std::size_t paddingSize = ((m_Length - initLength) + identity.GetSignatureLen()) % 16;
  ConsumeData(paddingSize);  // Skip padding

  return packet;
}

std::unique_ptr<SSURelayRequestPacket> SSUPacketParser::ParseRelayRequest() {
  std::unique_ptr<SSURelayRequestPacket> packet(
      new SSURelayRequestPacket());
  packet->SetHeader(ParseHeader());
  packet->SetRelayTag(ReadUInt32());
  packet->SetIpAddress(ReadBytes(ReadUInt8()));
  packet->SetPort(ReadUInt16());
  packet->SetChallenge(ReadBytes(ReadUInt8()));
  packet->SetIntroKey(ReadBytes(SSU_INTRO_KEY_SIZE));
  packet->SetNonce(ReadUInt32());

  return packet;
}

std::unique_ptr<SSURelayResponsePacket> SSUPacketParser::ParseRelayResponse() {
  std::unique_ptr<SSURelayResponsePacket> packet(
      new SSURelayResponsePacket());
  packet->SetHeader(ParseHeader());
  packet->SetIpAddressCharlie(ReadBytes(ReadUInt8()));
  packet->SetPortCharlie(ReadUInt16());
  packet->SetIpAddressAlice(ReadBytes(ReadUInt8()));
  packet->SetPortAlice(ReadUInt16());
  packet->SetNonce(ReadUInt32());

  return packet;
}

std::unique_ptr<SSURelayIntroPacket> SSUPacketParser::ParseRelayIntro() {
  std::unique_ptr<SSURelayIntroPacket> packet(
      new SSURelayIntroPacket());
  packet->SetHeader(ParseHeader());
  packet->SetIpAddress(ReadBytes(ReadUInt8()));
  packet->SetPort(ReadUInt16());
  packet->SetChallenge(ReadBytes(ReadUInt8()));
  return packet;
}

std::unique_ptr<SSUDataPacket> SSUPacketParser::ParseData() {
  std::unique_ptr<SSUDataPacket> packet(new SSUDataPacket());
  packet->SetHeader(ParseHeader());
  const uint8_t flags = ReadUInt8();

  // Read ACKS
  if(flags & DATA_FLAG_EXPLICIT_ACKS_INCLUDED) {
    for(std::size_t i = 0; i < ReadUInt8(); ++i)
      packet->AddACK(ReadUInt32());
  }
  // Read ACK bifields
  if(flags & DATA_FLAG_ACK_BITFIELDS_INCLUDED) {
    uint8_t bitfield;
    do {
      bitfield = ReadUInt8();
      packet->AddACKBitfield(bitfield);
    } while(bitfield & DATA_FLAG_ACK_BITFIELD_HAS_NEXT);
  }
  // Ignore possible extended data
  if(flags & DATA_FLAG_EXTENDED_DATA_INCLUDED)
    ReadBytes(ReadUInt8());
  // Read fragments
  for(std::size_t i = 0; i < ReadUInt8(); ++i)
    packet->AddFragment(ParseFragment());
  return packet;
}

std::unique_ptr<SSUPeerTestPacket> SSUPacketParser::ParsePeerTest() {
  std::unique_ptr<SSUPeerTestPacket> packet(
      new SSUPeerTestPacket());
  packet->SetHeader(ParseHeader());
  packet->SetNonce(ReadUInt32());
  packet->SetIpAddress(ReadBytes(ReadUInt8()));
  packet->SetPort(ReadUInt16());
  packet->SetIntroKey(ReadBytes(SSU_INTRO_KEY_SIZE));
  return packet;

}

std::unique_ptr<SSUSessionDestroyedPacket> SSUPacketParser::ParseSessionDestroyed() {
  std::unique_ptr<SSUSessionDestroyedPacket> packet(
      new SSUSessionDestroyedPacket());
  packet->SetHeader(ParseHeader());
  return packet;
}

}
}
