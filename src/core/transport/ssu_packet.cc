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

#include "ssu_packet.h"

#include <exception>

#include "ssu_data.h"
#include "crypto/rand.h"
#include "util/i2p_endian.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace transport {

/**
 *
 * Header processing
 *
 */

SSUHeader::SSUHeader()
    : SSUHeader(SSUPayloadType::Unknown) {}

SSUHeader::SSUHeader(SSUPayloadType type)
    : SSUHeader(type, nullptr, nullptr, 0) {}

SSUHeader::SSUHeader(
    SSUPayloadType type,
    std::uint8_t* mac,
    std::uint8_t* iv,
    std::uint32_t time)
    : m_MAC(mac),
      m_IV(iv),
      m_ExtendedOptions(nullptr),
      m_Rekey(false),
      m_Extended(false),
      m_Time(time),
      m_PayloadType(type),
      m_ExtendedOptionsSize(0) {}

void SSUHeader::SetMAC(
    std::uint8_t* mac) {
  m_MAC = mac;
}

std::uint8_t* SSUHeader::GetMAC() const {
  return m_MAC;
}

void SSUHeader::SetIV(
    std::uint8_t* iv) {
  m_IV = iv;
}

std::uint8_t const* SSUHeader::GetIV() const {
  return m_IV;
}

void SSUHeader::SetPayloadType(
    short type) {
  if (type < 0 || type > 8)
      throw std::invalid_argument("SSUHeader::SetPayloadType invalid type given");
  m_PayloadType = static_cast<SSUPayloadType>(type);
}

SSUPayloadType SSUHeader::GetPayloadType() const {
  return m_PayloadType;
}

void SSUHeader::SetRekey(
    bool rekey) {
  m_Rekey = rekey;
}

void SSUHeader::SetExtendedOptionsData(
    std::uint8_t* data,
    std::size_t size) {
  m_ExtendedOptionsSize = size;
  m_ExtendedOptions = data;
}

std::uint8_t const* SSUHeader::GetExtendedOptionsData() const {
  return m_ExtendedOptions;
}

std::size_t SSUHeader::GetExtendedOptionsSize() const {
  return m_ExtendedOptionsSize;
}

void SSUHeader::SetExtendedOptions(
    bool extended) {
  m_Extended = extended;
}

void SSUHeader::SetTime(
    std::uint32_t time) {
  m_Time = time;
}

std::uint32_t SSUHeader::GetTime() const {
  return m_Time;
}

bool SSUHeader::HasRekey() const {
  return m_Rekey;
}

bool SSUHeader::HasExtendedOptions() const {
  return m_Extended;
}

std::size_t SSUHeader::GetSize() const {
  auto size = static_cast<std::size_t>(SSUSize::HeaderMin);
  if (HasRekey())
    size += static_cast<std::size_t>(SSUSize::KeyingMaterial);
  if (HasExtendedOptions())
    size += m_ExtendedOptionsSize + 1;
  return size;
}

void SSUPacket::SetHeader(
    std::unique_ptr<SSUHeader> header) {
  m_Header = std::move(header);
}

SSUHeader* SSUPacket::GetHeader() const {
  return m_Header.get();
}

std::size_t SSUPacket::GetSize() const {
  return m_Header ? m_Header->GetSize() : 0;
}

/**
 *
 * Payload type 0: SessionRequest
 *
 */

void SSUSessionRequestPacket::SetDhX(
    std::uint8_t* dhX) {
  m_DhX = dhX;
}

std::uint8_t const* SSUSessionRequestPacket::GetDhX() const {
  return m_DhX;
}

void SSUSessionRequestPacket::SetIPAddress(
    std::uint8_t* address,
    std::size_t size) {
  m_IPAddress = address;
  m_IPAddressSize = size;
}

std::uint8_t const* SSUSessionRequestPacket::GetIPAddress() const {
  return m_IPAddress;
}

std::size_t SSUSessionRequestPacket::GetIPAddressSize() const {
  return m_IPAddressSize;
}

std::size_t SSUSessionRequestPacket::GetSize() const {
  return SSUPacket::GetSize()
         + static_cast<std::size_t>(SSUSize::DHPublic)  // DH X-parameter
         + 1                 // Bob's IP address size
         + m_IPAddressSize;  // That many byte representation of IP address
}

/**
 *
 * Payload type 1: SessionCreated
 *
 */

void SSUSessionCreatedPacket::SetDhY(
    std::uint8_t* dhY) {
  m_DhY = dhY;
}

std::uint8_t const* SSUSessionCreatedPacket::GetDhY() const {
  return m_DhY;
}

void SSUSessionCreatedPacket::SetIPAddress(
    std::uint8_t* address,
    std::size_t size) {
  m_IPAddress = address;
  m_AddressSize = size;
}

std::uint8_t const* SSUSessionCreatedPacket::GetIPAddress() const {
  return m_IPAddress;
}

std::size_t SSUSessionCreatedPacket::GetIPAddressSize() const {
  return m_AddressSize;
}

void SSUSessionCreatedPacket::SetPort(
    std::uint16_t port) {
  m_Port = port;
}

std::uint16_t SSUSessionCreatedPacket::GetPort() const {
  return m_Port;
}

void SSUSessionCreatedPacket::SetRelayTag(
    std::uint32_t relay_tag) {
  m_RelayTag = relay_tag;
}

std::uint32_t SSUSessionCreatedPacket::GetRelayTag() const {
  return m_RelayTag;
}

void SSUSessionCreatedPacket::SetSignature(
    std::uint8_t* signature,
    std::size_t size) {
  m_Signature = signature;
  m_SignatureSize = size;
}

std::uint8_t* SSUSessionCreatedPacket::GetSignature() const {
  return m_Signature;
}

std::size_t SSUSessionCreatedPacket::GetSignatureSize() const {
  return m_SignatureSize;
}

void SSUSessionCreatedPacket::SetSignedOnTime(
    std::uint32_t time) {
  m_SignedOnTime = time;
}

std::uint32_t SSUSessionCreatedPacket::GetSignedOnTime() const {
  return m_SignedOnTime;
}

std::size_t SSUSessionCreatedPacket::GetSize() const {
  return SSUPacket::GetSize()
         + static_cast<std::size_t>(SSUSize::DHPublic)  // Y to complete the DH agreement
         + 1 + m_AddressSize  // 1 byte address size, address size,
         + 2 + 4 + 4          // Port size (2 bytes), relay tag size, time size
         + m_SignatureSize;   // Signature size
}

/**
 *
 * Payload type 2: SessionConfirmed
 *
 */

void SSUSessionConfirmedPacket::SetRemoteRouterIdentity(
    const i2p::data::IdentityEx& identity) {
  m_RemoteIdentity = identity;
}

i2p::data::IdentityEx SSUSessionConfirmedPacket::GetRemoteRouterIdentity() const {
  return m_RemoteIdentity;
}

void SSUSessionConfirmedPacket::SetSignature(
    std::uint8_t* signature) {
  m_Signature = signature;
}

std::uint8_t const* SSUSessionConfirmedPacket::GetSignature() const {
  return m_Signature;
}

void SSUSessionConfirmedPacket::SetSignedOnTime(
    std::uint32_t time) {
  m_SignedOnTime = time;
}

std::uint32_t SSUSessionConfirmedPacket::GetSignedOnTime() const {
  return m_SignedOnTime;
}

std::size_t SSUSessionConfirmedPacket::GetSize() const {
  // This message must be a multiple of 16
  return SSUPacket::GetSize()
         + m_RemoteIdentity.GetFullLen()       // Identity size
         + m_RemoteIdentity.GetSignatureLen()  // Signature size
         + 4;                                  // Time size
}

/**
 *
 * Payload type 3: RelayRequest
 *
 */

void SSURelayRequestPacket::SetRelayTag(
    std::uint32_t relay_tag) {
  m_RelayTag = relay_tag;
}

std::uint32_t SSURelayRequestPacket::GetRelayTag() const {
  return m_RelayTag;
}

void SSURelayRequestPacket::SetIPAddress(
    std::uint8_t* address,
    std::size_t size) {
  m_IPAddress = address;
  m_IPAddressSize = size;
}

std::uint8_t const* SSURelayRequestPacket::GetIPAddress() const {
  return m_IPAddress;
}

void SSURelayRequestPacket::SetChallenge(
    std::uint8_t* challenge,
    std::size_t size) {
  m_Challenge = challenge;
  m_ChallengeSize = size;
}

std::uint8_t const* SSURelayRequestPacket::GetChallenge() const {
  return m_Challenge;
}

void SSURelayRequestPacket::SetPort(
    std::uint16_t port) {
  m_Port = port;
}

std::uint16_t SSURelayRequestPacket::GetPort() const {
  return m_Port;
}

void SSURelayRequestPacket::SetIntroKey(
    std::uint8_t* key) {
  m_IntroKey = key;
}

std::uint8_t const* SSURelayRequestPacket::GetIntroKey() const {
  return m_IntroKey;
}

void SSURelayRequestPacket::SetNonce(
    std::uint32_t nonce) {
  m_Nonce = nonce;
}

std::uint32_t SSURelayRequestPacket::GetNonce() const {
  return m_Nonce;
}

std::size_t SSURelayRequestPacket::GetSize() const {
  return SSUPacket::GetSize()
         + 4                // Relay tag
         + 1                // Alice's IP address size
         + m_IPAddressSize  // that many bytes representation of IP address
         + 2                // Alice's port number
         + 1                // Challenge size
         + m_ChallengeSize  // That many bytes to be relayed to Charlie in intro
         + static_cast<std::size_t>(SSUSize::IntroKey)  // Alice's 32-byte Intro key
         + 4;               // Nonce of Alice's relay request
}

/**
 *
 * Payload type 4: RelayResponse
 *
 */

void SSURelayResponsePacket::SetNonce(
    std::uint32_t nonce) {
  m_Nonce = nonce;
}

std::uint32_t SSURelayResponsePacket::GetNonce() const {
  return m_Nonce;
}

void SSURelayResponsePacket::SetIPAddressAlice(
    std::uint8_t* address,
    std::size_t size) {
  m_IPAddressAlice = address;
  m_IPAddressAliceSize = size;
}

std::uint8_t const* SSURelayResponsePacket::GetIPAddressAlice() const {
  return m_IPAddressAlice;
}

std::size_t SSURelayResponsePacket::GetIPAddressAliceSize() const {
  return m_IPAddressAliceSize;
}

void SSURelayResponsePacket::SetIPAddressCharlie(
    std::uint8_t* address,
    std::size_t size) {
  m_IPAddressCharlie = address;
  m_IPAddressCharlieSize = size;
}

std::uint8_t const* SSURelayResponsePacket::GetIPAddressCharlie() const {
  return m_IPAddressCharlie;
}

void SSURelayResponsePacket::SetPortAlice(
    std::uint16_t port) {
  m_PortAlice = port;
}

std::uint16_t SSURelayResponsePacket::GetPortAlice() const {
  return m_PortAlice;
}

void SSURelayResponsePacket::SetPortCharlie(
    std::uint16_t port) {
  m_PortCharlie = port;
}

std::uint16_t SSURelayResponsePacket::GetPortCharlie() const {
  return m_PortCharlie;
}

std::size_t SSURelayResponsePacket::GetSize() const {
  return SSUPacket::GetSize()
         + 1                       // Charlie's IP address size
         + m_IPAddressCharlieSize  // That many byte representation of IP address
         + 2                       // Charlie's port number
         + 1                       // Alice's IP address size
         + m_IPAddressAliceSize    // That many byte representation of IP address
         + 2                       // Alice's port number
         + 4;                      // Nonce sent by Alice
}

/**
 *
 * Payload type 5: RelayIntro
 *
 */

void SSURelayIntroPacket::SetIPAddress(
    std::uint8_t* address,
    std::size_t size) {
  m_IPAddress = address;
  m_IPAddressSize = size;
}

std::uint8_t const* SSURelayIntroPacket::GetIPAddress() const {
  return m_IPAddress;
}

std::size_t SSURelayIntroPacket::GetIPAddressSize() const {
  return m_IPAddressSize;
}

void SSURelayIntroPacket::SetChallenge(
    std::uint8_t* challenge,
    std::size_t size) {
  m_Challenge = challenge;
  m_ChallengeSize = size;
}

std::uint8_t const* SSURelayIntroPacket::GetChallenge() const {
  return m_Challenge;
}

void SSURelayIntroPacket::SetPort(
    std::uint16_t port) {
  m_Port = port;
}

std::uint16_t SSURelayIntroPacket::GetPort() const {
  return m_Port;
}

std::size_t SSURelayIntroPacket::GetSize() const {
  return SSUPacket::GetSize()
         + 1                 // Alice's IP address size
         + m_IPAddressSize   // that many bytes representation of IP address
         + 2                 // Alice's port number
         + 1                 // Challenge size
         + m_ChallengeSize;  // That many bytes related from Alice
}

/**
 *
 * Fragment implementation
 *
 */

std::size_t SSUFragment::GetSize() const {
  return m_Size;
}

void SSUFragment::SetMessageID(
    std::uint32_t message_ID) {
  m_MessageID = message_ID;
}

void SSUFragment::SetNumber(
    std::uint8_t number) {
  m_Number = number;
}

void SSUFragment::SetIsLast(
    bool is_last) {
  m_IsLast = is_last;
}

void SSUFragment::SetSize(
    std::size_t size) {
  m_Size = size;
}

void SSUFragment::SetData(
    std::uint8_t* data) {
  m_Data = data;
}

/**
 *
 * Payload type 6: Data
 *
 */

void SSUDataPacket::AddExplicitACK(
    std::uint32_t message_ID) {
  m_ExplicitACKs.push_back(message_ID);
}

void SSUDataPacket::AddACK(
    std::uint32_t message_ID) {
  m_ACKs.push_back(message_ID);
}

void SSUDataPacket::AddACKBitfield(
    std::uint8_t bitfield) {
  m_ACKBitfields.push_back(bitfield);
}

void SSUDataPacket::AddFragment(
    SSUFragment fragment) {
  m_Fragments.push_back(fragment);
}

std::size_t SSUDataPacket::GetSize() const {
  // Flag, number of fragments
  std::size_t size = SSUPacket::GetSize() + 1 + 1;
  // Explicit ACKs
  if (!m_ExplicitACKs.empty())
    size += 1 + m_ExplicitACKs.size() * 4;
  // ACK bitfields
  if (!m_ACKs.empty())
    size += 1 + m_ACKs.size() * (4 + 1);
  // TODO(EinMByte): Count extended data
  for (const SSUFragment& frag : m_Fragments)
    size += frag.GetSize() + 4 + 3;
  return size;
}

/**
 *
 * Payload type 7: PeerTest
 *
 */

void SSUPeerTestPacket::SetNonce(
    std::uint32_t nonce) {
  m_Nonce = nonce;
}

std::uint32_t SSUPeerTestPacket::GetNonce() const {
  return m_Nonce;
}

void SSUPeerTestPacket::SetIPAddress(
    std::uint32_t address) {
  m_IPAddress = address;
}

std::uint32_t SSUPeerTestPacket::GetIPAddress() const {
  return m_IPAddress;
}

void SSUPeerTestPacket::SetPort(
    std::uint16_t port) {
  m_Port = port;
}

std::uint16_t SSUPeerTestPacket::GetPort() const {
  return m_Port;
}

void SSUPeerTestPacket::SetIntroKey(
    std::uint8_t* intro_key) {
  m_IntroKey = intro_key;
}

std::uint8_t const* SSUPeerTestPacket::GetIntroKey() const {
  return m_IntroKey;
}

std::size_t SSUPeerTestPacket::GetSize() const {
  return SSUPacket::GetSize()
         + 4  // Nonce
         + 1  // Alice's IP address size
         // TODO(unassigned): that many byte representation of IP address (if size > 0)
         + 2  // Alice's port number
         + static_cast<std::size_t>(SSUSize::IntroKey);  // Alice's or Charlie's 32-byte introduction key
}

/**
 *
 * Packet parsing implementation
 *
 */

SSUPacketParser::SSUPacketParser(
    std::uint8_t* data,
    std::size_t len)
    : m_Data(data),
      m_Length(len) {}

void SSUPacketParser::ConsumeData(
    std::size_t amount) {
  if (amount > m_Length)
    throw std::length_error("SSUPacketParser: too many bytes to consume.");
  m_Data += amount;
  m_Length -= amount;
}

std::uint8_t* SSUPacketParser::ReadBytes(
    std::size_t amount) {
  std::uint8_t* ptr = m_Data;
  ConsumeData(amount);
  return ptr;
}

std::uint32_t SSUPacketParser::ReadUInt32() {
  return bufbe32toh(ReadBytes(4));
}

std::uint16_t SSUPacketParser::ReadUInt16() {
  return bufbe16toh(ReadBytes(2));
}

std::uint8_t SSUPacketParser::ReadUInt8() {
  return *ReadBytes(1);
}

SSUFragment SSUPacketParser::ParseFragment() {
  SSUFragment fragment;
  fragment.SetMessageID(ReadUInt32());
  // TODO(EinMByte): clean this up
  std::array<std::uint8_t, 4> info_buf {};
  memcpy(info_buf.data() + 1, ReadBytes(3), 3);
  const std::uint32_t fragment_info = bufbe32toh(info_buf.data());
  fragment.SetSize(fragment_info & 0x3FFF);  // bits 0 - 13
  // bits 15-14: unused, set to 0 for compatibility with future uses
  fragment.SetIsLast(fragment_info & 0x010000);  // bit 16
  fragment.SetNumber(fragment_info >> 17);  // bits 23 - 17
  // TODO(EinMByte): Check whether the size is correct
  fragment.SetData(ReadBytes(fragment.GetSize()));
  return fragment;
}

std::unique_ptr<SSUHeader> SSUPacketParser::ParseHeader() {
  if (m_Length < static_cast<std::size_t>(SSUSize::HeaderMin))
    throw std::length_error("SSU header too small");
  auto header = std::make_unique<SSUHeader>();
  // Set MAC and IV
  header->SetMAC(ReadBytes(static_cast<std::size_t>(SSUSize::MAC)));
  header->SetIV(ReadBytes(static_cast<std::size_t>(SSUSize::IV)));
  // Extract information from flag (payload type and rekey/extened options)
  const std::uint8_t flag = ReadUInt8();
  header->SetRekey(flag & static_cast<std::uint8_t>(SSUFlag::Rekey));
  header->SetExtendedOptions(flag & static_cast<std::uint8_t>(SSUFlag::ExtendedOptions));
  header->SetPayloadType(flag >> 4);
  // Extract the time
  header->SetTime(ReadUInt32());
  if (header->HasRekey()) {
    // TODO(EinMByte): Actually do something with the data
    // TODO(EinMByte): See issue #119, for some reason some rekey options
    //                 are sometimes set?
    ConsumeData(static_cast<std::size_t>(SSUSize::KeyingMaterial));
  }
  if (header->HasExtendedOptions()) {
    const std::size_t options_size = ReadUInt8();
    header->SetExtendedOptionsData(ReadBytes(options_size), options_size);
  }
  return header;
}

std::unique_ptr<SSUPacket> SSUPacketParser::ParsePacket() {
  std::unique_ptr<SSUHeader> header(ParseHeader());
  std::unique_ptr<SSUPacket> packet;
  std::uint8_t* const old_data = m_Data;
  const std::size_t old_length = m_Length;
  switch (header->GetPayloadType()) {
    case SSUPayloadType::SessionRequest:
      packet = ParseSessionRequest();
      break;
    case SSUPayloadType::SessionCreated:
      packet = ParseSessionCreated();
      break;
    case SSUPayloadType::SessionConfirmed:
      packet = ParseSessionConfirmed();
      break;
    case SSUPayloadType::RelayRequest:
      packet = ParseRelayRequest();
      break;
    case SSUPayloadType::RelayResponse:
      packet = ParseRelayResponse();
      break;
    case SSUPayloadType::RelayIntro:
      packet = ParseRelayIntro();
      break;
    case SSUPayloadType::Data:
      packet = ParseData();
      break;
    case SSUPayloadType::PeerTest:
      packet = ParsePeerTest();
      break;
    case SSUPayloadType::SessionDestroyed:
      packet = ParseSessionDestroyed();
      break;
  }
  // TODO(EinMByte): Get rid of this
  packet->m_RawDataLength = old_length;
  packet->m_RawData = old_data;
  packet->SetHeader(std::move(header));
  return packet;
}

std::unique_ptr<SSUSessionRequestPacket> SSUPacketParser::ParseSessionRequest() {
  auto packet = std::make_unique<SSUSessionRequestPacket>();
  packet->SetDhX(ReadBytes(static_cast<std::size_t>(SSUSize::DHPublic)));
  std::size_t size = ReadUInt8();
  packet->SetIPAddress(ReadBytes(size), size);
  return packet;
}

std::unique_ptr<SSUSessionCreatedPacket> SSUPacketParser::ParseSessionCreated() {
  auto packet = std::make_unique<SSUSessionCreatedPacket>();
  packet->SetDhY(ReadBytes(static_cast<std::size_t>(SSUSize::DHPublic)));
  std::size_t address_size = ReadUInt8();
  packet->SetIPAddress(ReadBytes(address_size), address_size);
  packet->SetPort(ReadUInt16());
  packet->SetRelayTag(ReadUInt32());
  packet->SetSignedOnTime(ReadUInt32());
  packet->SetSignature(m_Data, m_Length);
  return packet;
}

std::unique_ptr<SSUSessionConfirmedPacket> SSUPacketParser::ParseSessionConfirmed() {
  const std::size_t init_length = m_Length;
  auto packet = std::make_unique<SSUSessionConfirmedPacket>();
  ConsumeData(1);  // Skip info byte
  std::uint16_t identity_size = ReadUInt16();
  i2p::data::IdentityEx identity;
  identity.FromBuffer(ReadBytes(identity_size), identity_size);
  packet->SetRemoteRouterIdentity(identity);
  packet->SetSignedOnTime(ReadUInt32());
  const std::size_t padding_size = ((m_Length - init_length) + identity.GetSignatureLen()) % 16;
  ConsumeData(padding_size);  // Skip padding
  packet->SetSignature(m_Data);
  return packet;
}

std::unique_ptr<SSURelayRequestPacket> SSUPacketParser::ParseRelayRequest() {
  auto packet = std::make_unique<SSURelayRequestPacket>();
  packet->SetRelayTag(ReadUInt32());
  const std::size_t address_size = ReadUInt8();
  packet->SetIPAddress(ReadBytes(address_size), address_size);
  packet->SetPort(ReadUInt16());
  const std::size_t challenge_size = ReadUInt8();
  packet->SetChallenge(ReadBytes(challenge_size), challenge_size);
  packet->SetIntroKey(ReadBytes(static_cast<std::size_t>(SSUSize::IntroKey)));
  packet->SetNonce(ReadUInt32());
  return packet;
}

std::unique_ptr<SSURelayResponsePacket> SSUPacketParser::ParseRelayResponse() {
  auto packet = std::make_unique<SSURelayResponsePacket>();
  const std::size_t charlie_address_size = ReadUInt8();
  packet->SetIPAddressCharlie(ReadBytes(charlie_address_size), charlie_address_size);
  packet->SetPortCharlie(ReadUInt16());
  const std::size_t alice_address_size = ReadUInt8();
  packet->SetIPAddressAlice(ReadBytes(alice_address_size), alice_address_size);
  packet->SetPortAlice(ReadUInt16());
  packet->SetNonce(ReadUInt32());
  return packet;
}

std::unique_ptr<SSURelayIntroPacket> SSUPacketParser::ParseRelayIntro() {
  auto packet = std::make_unique<SSURelayIntroPacket>();
  const std::size_t address_size = ReadUInt8();
  packet->SetIPAddress(ReadBytes(address_size), address_size);
  packet->SetPort(ReadUInt16());
  const std::size_t challenge_size = ReadUInt8();
  packet->SetChallenge(ReadBytes(challenge_size), challenge_size);
  return packet;
}

std::unique_ptr<SSUDataPacket> SSUPacketParser::ParseData() {
  auto packet = std::make_unique<SSUDataPacket>();
  const std::uint8_t flags = ReadUInt8();
  // Read ACKS
  if (flags & static_cast<std::uint8_t>(SSUFlag::DataExplicitACKsIncluded)) {
    const std::size_t nb_explicit_ACKs = ReadUInt8();
    for(std::size_t i = 0; i < nb_explicit_ACKs; ++i)
      packet->AddExplicitACK(ReadUInt32());
  }
  // Read ACK bifields
  if (flags & static_cast<std::uint8_t>(SSUFlag::DataACKBitfieldsIncluded)) {
    const std::size_t nb_ACKs = ReadUInt8();
    // Read message IDs
    for (std::size_t i = 0; i < nb_ACKs; ++i)
      packet->AddACK(ReadUInt32());
    // Read bitfields
    std::uint8_t bitfield;
    do {
      bitfield = ReadUInt8();
      packet->AddACKBitfield(bitfield);
    } while (bitfield & static_cast<std::uint8_t>(SSUFlag::DataACKBitFieldHasNext));
  }
  // Ignore possible extended data
  if (flags & static_cast<std::uint8_t>(SSUFlag::DataExtendedIncluded))
    ReadBytes(ReadUInt8());
  const std::size_t nb_flags = ReadUInt8();
  // Read fragments
  for(std::size_t i = 0; i < nb_flags; ++i)
    packet->AddFragment(ParseFragment());
  return packet;
}

std::unique_ptr<SSUPeerTestPacket> SSUPacketParser::ParsePeerTest() {
  auto packet = std::make_unique<SSUPeerTestPacket>();
  packet->SetNonce(ReadUInt32());
  // TODO(EinMByte): Handle other address sizes, or deal with the errors.
  packet->SetIPAddress(buf32toh(ReadBytes((ReadUInt8() == 4) ? 4 : 0)));
  packet->SetPort(ReadUInt16());
  packet->SetIntroKey(ReadBytes(static_cast<std::size_t>(SSUSize::IntroKey)));
  return packet;
}

/**
 *
 *  Payload type 8: SessionDestroyed
 *
 */

std::unique_ptr<SSUSessionDestroyedPacket> SSUPacketParser::ParseSessionDestroyed() {
  auto packet = std::make_unique<SSUSessionDestroyedPacket>();
  return packet;
}

namespace SSUPacketBuilder {

void WriteData(
    std::uint8_t*& pos,
    const std::uint8_t* data,
    std::size_t len) {
  memcpy(pos, data, len);
  pos += len;
}

void WriteUInt8(
    std::uint8_t*& pos,
    std::uint8_t data) {
  *(pos++) = data;
}

void WriteUInt16(
    std::uint8_t*& pos,
    std::uint16_t data) {
  htobe16buf(pos, data);
  pos += 2;
}

void WriteUInt32(
    std::uint8_t*& pos,
    std::uint32_t data) {
  htobe32buf(pos, data);
  pos += 4;
}

std::size_t GetPaddingSize(
    std::size_t size) {
  return 16 - size % 16;
}

std::size_t GetPaddedSize(
    std::size_t size) {
  size += static_cast<std::size_t>(SSUSize::BufferMargin);
  return size + GetPaddingSize(size);
}

void WriteHeader(
    std::uint8_t*& data,
    SSUHeader* header) {
  if (header->GetMAC())
    WriteData(data, header->GetMAC(), static_cast<std::size_t>(SSUSize::MAC));
  else
    data += static_cast<std::size_t>(SSUSize::MAC);  // Write MAC later
  WriteData(data, header->GetIV(), static_cast<std::size_t>(SSUSize::IV));
  const std::uint8_t flag =
      (static_cast<std::uint8_t>(header->GetPayloadType()) << 4) +
      (header->HasRekey() << 3) +
      (header->HasExtendedOptions() << 2);
  WriteUInt8(data, flag);
  WriteUInt32(data, header->GetTime());
  if (header->HasExtendedOptions()) {
    // TODO(EinMByte): Check for overflow
    WriteUInt8(data, header->GetExtendedOptionsSize());
    WriteData(
        data,
        header->GetExtendedOptionsData(),
        header->GetExtendedOptionsSize());
  }
}

void WriteSessionRequest(
    std::uint8_t*& buf,
    SSUSessionRequestPacket* packet) {
  WriteData(buf, packet->GetDhX(), static_cast<std::size_t>(SSUSize::DHPublic));
  // TODO(EinMByte): Check for overflow
  WriteUInt8(buf, packet->GetIPAddressSize());
  WriteData(buf, packet->GetIPAddress(), packet->GetIPAddressSize());
}

void WriteSessionCreated(
    std::uint8_t*& buf,
    SSUSessionCreatedPacket* packet) {
  WriteData(buf, packet->GetDhY(), static_cast<std::size_t>(SSUSize::DHPublic));
  // TODO(EinMByte): Check for overflow
  WriteUInt8(buf, packet->GetIPAddressSize());
  WriteData(buf, packet->GetIPAddress(), packet->GetIPAddressSize());
  WriteUInt16(buf, packet->GetPort());
  WriteUInt32(buf, packet->GetRelayTag());
  WriteUInt32(buf, packet->GetSignedOnTime());
  WriteData(buf, packet->GetSignature(), packet->GetSignatureSize());
}

void WriteSessionConfirmed(
    std::uint8_t*& buf,
    SSUSessionConfirmedPacket* packet) {
  std::uint8_t* const begin = buf;
  WriteUInt8(buf, 0x00);  // 1 byte info
  const std::size_t identity_size = packet->GetRemoteRouterIdentity().GetFullLen();
  WriteUInt8(buf, identity_size);
  packet->GetRemoteRouterIdentity().ToBuffer(buf, identity_size);
  WriteUInt32(buf, packet->GetSignedOnTime());
  // Padding is assumed to be present
  const std::size_t signature_size = packet->GetRemoteRouterIdentity().GetSignatureLen();
  //const std::size_t padding_size = GetPaddingSize(buf - begin + signature_size);
  //i2p::crypto::RandBytes(buf, padding_size);
  //buf += padding_size;
  WriteData(buf, packet->GetSignature(), signature_size);
}

void WriteRelayRequest(
    std::uint8_t*& buf,
    SSURelayRequestPacket* packet) {}

void WriteRelayResponse(
    std::uint8_t*& buf,
    SSURelayResponsePacket* packet) {}

void WriteRelayIntro(
    std::uint8_t*& buf,
    SSURelayIntroPacket* packet) {}

void WriteData(
    std::uint8_t*& buf,
    SSUDataPacket* packet) {}

void WritePeerTest(
    std::uint8_t*& buf,
    SSUPeerTestPacket* packet) {}

void WriteSessionDestroyed(
    std::uint8_t*& buf,
    SSUSessionDestroyedPacket* packet) {}

void WritePacket(
    std::uint8_t*& buf,
    SSUPacket* packet) {
  switch (packet->GetHeader()->GetPayloadType()) {
    case SSUPayloadType::SessionRequest:
      WriteSessionRequest(buf, static_cast<SSUSessionRequestPacket*>(packet));
      break;
    case SSUPayloadType::SessionCreated:
      WriteSessionCreated(buf, static_cast<SSUSessionCreatedPacket*>(packet));
      break;
    case SSUPayloadType::SessionConfirmed:
      WriteSessionConfirmed(buf, static_cast<SSUSessionConfirmedPacket*>(packet));
      break;
    case SSUPayloadType::RelayRequest:
      WriteRelayRequest(buf, static_cast<SSURelayRequestPacket*>(packet));
      break;
    case SSUPayloadType::RelayResponse:
      WriteRelayResponse(buf, static_cast<SSURelayResponsePacket*>(packet));
      break;
    case SSUPayloadType::RelayIntro:
      WriteRelayIntro(buf, static_cast<SSURelayIntroPacket*>(packet));
      break;
    case SSUPayloadType::Data:
      WriteData(buf, static_cast<SSUDataPacket*>(packet));
      break;
    case SSUPayloadType::PeerTest:
      WritePeerTest(buf, static_cast<SSUPeerTestPacket*>(packet));
      break;
    case SSUPayloadType::SessionDestroyed:
      WriteSessionDestroyed(buf, static_cast<SSUSessionDestroyedPacket*>(packet));
      break;
  }
}
}  // namespace SSUPacketBuilder

}  // namespace transport
}  // namespace i2p
