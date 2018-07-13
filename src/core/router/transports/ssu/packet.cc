/**
 * Copyright (c) 2015-2018, The Kovri I2P Router Project
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

#include "core/router/transports/ssu/packet.h"

#include <exception>

#include "core/crypto/rand.h"

#include "core/router/transports/ssu/data.h"

#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {
// TODO(unassigned): move out of unit file
std::size_t SSUSessionConfirmedPacket::GetSize() const
{
  // This message must be a multiple of 16
  return SSUPacketBuilder::GetPaddedSize(
      SSUPacket::GetSize() + 3  // Info and identity size
      + m_RemoteIdentity.GetFullLen()  // Identity
      + m_RemoteIdentity.GetSignatureLen()  // Signature
      + 4);  // Time size
}

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

/**
 *
 * Packet parsing implementation
 *
 */

SSUPacketParser::SSUPacketParser(
    std::uint8_t* data,
    std::size_t len)
    : InputByteStream(data, len) {}

SSUFragment SSUPacketParser::ParseFragment() {
  SSUFragment fragment;
  fragment.SetMessageID(Read<std::uint32_t>());
  // TODO(EinMByte): clean this up
  std::array<std::uint8_t, 4> info_buf {{}};
  memcpy(info_buf.data() + 1, ReadBytes(3), 3);
  const std::uint32_t fragment_info = Read<std::uint32_t>(info_buf.data());
  fragment.SetSize(fragment_info & 0x3FFF);  // bits 0 - 13
  // bits 15-14: unused, set to 0 for compatibility with future uses
  fragment.SetIsLast(fragment_info & 0x010000);  // bit 16
  fragment.SetNumber(fragment_info >> 17);  // bits 23 - 17
  // End session if fragmented size is greater than buffer size
  if (fragment.GetSize() > size())
    {
      // TODO(anonimal): invalid size could be an implementation issue rather
      //   than an attack. Reconsider how we mitigate invalid fragment size.
      throw std::length_error("SSUPacketParser: invalid fragment size");
    }
  fragment.SetData(ReadBytes(fragment.GetSize()));
  return fragment;
}

std::unique_ptr<SSUHeader> SSUPacketParser::ParseHeader() {
  if (m_Length < SSUSize::HeaderMin)
    throw std::length_error("SSU header too small");
  auto header = std::make_unique<SSUHeader>();
  // Set MAC and IV
  header->SetMAC(ReadBytes(SSUSize::MAC));
  header->SetIV(ReadBytes(SSUSize::IV));
  // Extract information from flag (payload type and rekey/extened options)
  const std::uint8_t flag = Read<std::uint8_t>();
  header->SetRekey(flag & SSUFlag::Rekey);
  header->SetExtendedOptions(flag & SSUFlag::ExtendedOptions);
  header->SetPayloadType(flag >> 4);
  // Extract the time
  header->SetTime(Read<std::uint32_t>());
  if (header->HasRekey()) {
    // TODO(EinMByte): Actually do something with the data
    // TODO(EinMByte): See issue #119, for some reason some rekey options
    //                 are sometimes set?
    SkipBytes(SSUSize::KeyingMaterial);
  }
  if (header->HasExtendedOptions()) {
    const std::size_t options_size = Read<std::uint8_t>();
    header->SetExtendedOptionsData(ReadBytes(options_size), options_size);
  }
  return header;
}

std::unique_ptr<SSUPacket> SSUPacketParser::ParsePacket() {
  m_Header = ParseHeader();
  std::unique_ptr<SSUPacket> packet;
  std::uint8_t* const old_data = m_DataPtr;
  const std::size_t old_length = m_Length;
  switch (m_Header->GetPayloadType()) {
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
    case SSUPayloadType::Unknown:
    default:
      throw std::runtime_error("SSUPacketParser: unknown payload type");
  }
  // TODO(EinMByte): Get rid of this
  packet->m_RawDataLength = old_length;
  packet->m_RawData = old_data;
  packet->SetHeader(std::move(m_Header));
  return packet;
}

std::unique_ptr<SSUSessionRequestPacket> SSUPacketParser::ParseSessionRequest() {
  auto packet = std::make_unique<SSUSessionRequestPacket>();
  packet->SetDhX(ReadBytes(SSUSize::DHPublic));
  std::uint8_t const size = Read<std::uint8_t>();
  packet->SetIPAddress(ReadBytes(size), size);
  return packet;
}

std::unique_ptr<SSUSessionCreatedPacket> SSUPacketParser::ParseSessionCreated() {
  auto packet = std::make_unique<SSUSessionCreatedPacket>();
  packet->SetDhY(ReadBytes(SSUSize::DHPublic));
  std::uint8_t const address_size = Read<std::uint8_t>();
  packet->SetIPAddress(ReadBytes(address_size), address_size);
  packet->SetPort(Read<std::uint16_t>());
  packet->SetRelayTag(Read<std::uint32_t>());
  packet->SetSignedOnTime(Read<std::uint32_t>());
  packet->SetSignature(m_DataPtr, m_Length);
  return packet;
}

std::unique_ptr<SSUSessionConfirmedPacket> SSUPacketParser::ParseSessionConfirmed() {
  const std::size_t init_length = m_Length;
  auto packet = std::make_unique<SSUSessionConfirmedPacket>();
  SkipBytes(1);  // Info byte
  std::uint16_t identity_size = Read<std::uint16_t>();
  kovri::core::IdentityEx identity;
  if (!identity.FromBuffer(ReadBytes(identity_size), identity_size))
    throw std::length_error("SSUPacketParser: invalid length within identity");
  packet->SetRemoteRouterIdentity(identity);
  packet->SetSignedOnTime(Read<std::uint32_t>());
  const std::size_t padding_size = SSUPacketBuilder::GetPaddingSize(
      m_Header->GetSize() + init_length - m_Length
      + identity.GetSignatureLen());
  SkipBytes(padding_size);  // Padding
  packet->SetSignature(m_DataPtr);
  return packet;
}

std::unique_ptr<SSURelayRequestPacket> SSUPacketParser::ParseRelayRequest() {
  auto packet = std::make_unique<SSURelayRequestPacket>();
  packet->SetRelayTag(Read<std::uint32_t>());
  std::uint8_t const address_size = Read<std::uint8_t>();
  packet->SetIPAddress(ReadBytes(address_size), address_size);
  packet->SetPort(Read<std::uint16_t>());
  const std::size_t challenge_size = Read<std::uint8_t>();
  packet->SetChallenge(ReadBytes(challenge_size), challenge_size);
  packet->SetIntroKey(ReadBytes(SSUSize::IntroKey));
  packet->SetNonce(Read<std::uint32_t>());
  return packet;
}

std::unique_ptr<SSURelayResponsePacket> SSUPacketParser::ParseRelayResponse() {
  auto packet = std::make_unique<SSURelayResponsePacket>();
  std::uint8_t const charlie_address_size = Read<std::uint8_t>();
  packet->SetIPAddressCharlie(ReadBytes(charlie_address_size), charlie_address_size);
  packet->SetPortCharlie(Read<std::uint16_t>());
  std::uint8_t const alice_address_size = Read<std::uint8_t>();
  packet->SetIPAddressAlice(ReadBytes(alice_address_size), alice_address_size);
  packet->SetPortAlice(Read<std::uint16_t>());
  packet->SetNonce(Read<std::uint32_t>());
  return packet;
}

std::unique_ptr<SSURelayIntroPacket> SSUPacketParser::ParseRelayIntro() {
  auto packet = std::make_unique<SSURelayIntroPacket>();
  std::uint8_t const address_size = Read<std::uint8_t>();
  packet->SetIPAddress(ReadBytes(address_size), address_size);
  packet->SetPort(Read<std::uint16_t>());
  const std::size_t challenge_size = Read<std::uint8_t>();
  packet->SetChallenge(ReadBytes(challenge_size), challenge_size);
  return packet;
}

std::unique_ptr<SSUDataPacket> SSUPacketParser::ParseData() {
  auto packet = std::make_unique<SSUDataPacket>();
  const std::uint8_t flags = Read<std::uint8_t>();
  // Read ACKS
  if (flags & SSUFlag::DataExplicitACKsIncluded) {
    const std::size_t nb_explicit_ACKs = Read<std::uint8_t>();
    for(std::size_t i = 0; i < nb_explicit_ACKs; ++i)
      packet->AddExplicitACK(Read<std::uint32_t>());
  }
  // Read ACK bifields
  if (flags & SSUFlag::DataACKBitfieldsIncluded) {
    const std::size_t nb_ACKs = Read<std::uint8_t>();
    // Read message IDs
    for (std::size_t i = 0; i < nb_ACKs; ++i)
      packet->AddACK(Read<std::uint32_t>());
    // Read bitfields
    std::uint8_t bitfield;
    do {
      bitfield = Read<std::uint8_t>();
      packet->AddACKBitfield(bitfield);
    } while (bitfield & SSUFlag::DataACKBitFieldHasNext);
  }
  // Ignore possible extended data
  if (flags & SSUFlag::DataExtendedIncluded)
    SkipBytes(Read<std::uint8_t>());
  const std::size_t nb_flags = Read<std::uint8_t>();
  // Read fragments
  for(std::size_t i = 0; i < nb_flags; ++i)
    packet->AddFragment(ParseFragment());
  return packet;
}

std::unique_ptr<SSUPeerTestPacket> SSUPacketParser::ParsePeerTest() {
  auto packet = std::make_unique<SSUPeerTestPacket>();
  packet->SetNonce(Read<std::uint32_t>());
  std::uint8_t const size(Read<std::uint8_t>());
  if (size)  // Bob or Charlie
    packet->SetIPAddress(core::BytesToAddress(ReadBytes(size), size));
  packet->SetIPAddressSize(size);
  packet->SetPort(Read<std::uint16_t>());
  packet->SetIntroKey(ReadBytes(SSUSize::IntroKey));
  return packet;
}

std::unique_ptr<SSUSessionDestroyedPacket> SSUPacketParser::ParseSessionDestroyed() {
  auto packet = std::make_unique<SSUSessionDestroyedPacket>();
  return packet;
}

SSUPacketBuilder::SSUPacketBuilder(
      std::uint8_t* data,
      std::size_t len)
  : OutputByteStream(data, len) {}

void SSUPacketBuilder::WriteHeader(SSUHeader* header) {
  if (header->GetMAC())
    WriteData(header->GetMAC(), SSUSize::MAC);
  else
    SkipBytes(SSUSize::MAC);  // Write real MAC later
  WriteData(header->GetIV(), SSUSize::IV);
  const std::uint8_t flag =
      (header->GetPayloadType() << 4) +
      (header->HasRekey() << 3) +
      (header->HasExtendedOptions() << 2);
  Write<std::uint8_t>(flag);
  Write<std::uint32_t>(header->GetTime());
  if (header->HasExtendedOptions()) {
    Write<std::uint8_t>(header->GetExtendedOptionsSize());
    WriteData(
        header->GetExtendedOptionsData(),
        header->GetExtendedOptionsSize());
  }
}

void SSUPacketBuilder::WriteSessionRequest(SSUSessionRequestPacket* packet) {
  WriteData(packet->GetDhX(), SSUSize::DHPublic);
  Write<std::uint8_t>(packet->GetIPAddressSize());
  WriteData(packet->GetIPAddress(), packet->GetIPAddressSize());
}

void SSUPacketBuilder::WriteSessionCreated(SSUSessionCreatedPacket* packet) {
  WriteData(packet->GetDhY(), SSUSize::DHPublic);
  Write<std::uint8_t>(packet->GetIPAddressSize());
  WriteData(packet->GetIPAddress(), packet->GetIPAddressSize());
  Write<std::uint16_t>(packet->GetPort());
  Write<std::uint32_t>(packet->GetRelayTag());
  Write<std::uint32_t>(packet->GetSignedOnTime());
  WriteData(packet->GetSignature(), packet->GetSignatureSize());
}

void SSUPacketBuilder::WriteSessionConfirmed(
    SSUSessionConfirmedPacket* packet) {
  const std::uint8_t* const begin = tellp();
  Write<std::uint8_t>(0x01);  // 1 byte info, with 1 fragment
  const std::size_t identity_size = packet->GetRemoteRouterIdentity().GetFullLen();
  Write<std::uint16_t>(identity_size);
  std::uint8_t* const identity = m_DataPtr;
  SkipBytes(identity_size);
  packet->GetRemoteRouterIdentity().ToBuffer(identity, identity_size);

  Write<std::uint32_t>(packet->GetSignedOnTime());
  // Write padding here (rather than later), because it is in the middle of the
  // message
  const std::size_t signature_size = packet->GetRemoteRouterIdentity().GetSignatureLen();
  const std::size_t padding_size = GetPaddingSize(
      packet->GetHeader()->GetSize() + tellp() - begin + signature_size);
  std::uint8_t* const padding = m_DataPtr;
  SkipBytes(padding_size);
  kovri::core::RandBytes(padding, padding_size);
  WriteData(packet->GetSignature(), signature_size);
}

void SSUPacketBuilder::WriteRelayRequest(
    SSURelayRequestPacket* /*packet*/) {}

void SSUPacketBuilder::WriteRelayResponse(
    SSURelayResponsePacket* /*packet*/) {}

void SSUPacketBuilder::WriteRelayIntro(
    SSURelayIntroPacket* /*packet*/) {}

void SSUPacketBuilder::WriteDataMessage(
    SSUDataPacket* /*packet*/) {}

void SSUPacketBuilder::WritePeerTest(
    SSUPeerTestPacket* /*packet*/) {}

void SSUPacketBuilder::WriteSessionDestroyed(
    SSUSessionDestroyedPacket* /*packet*/) {}

void SSUPacketBuilder::WritePacket(SSUPacket* packet) {
  switch (packet->GetHeader()->GetPayloadType()) {
    case SSUPayloadType::SessionRequest:
      WriteSessionRequest(static_cast<SSUSessionRequestPacket*>(packet));
      break;
    case SSUPayloadType::SessionCreated:
      WriteSessionCreated(static_cast<SSUSessionCreatedPacket*>(packet));
      break;
    case SSUPayloadType::SessionConfirmed:
      WriteSessionConfirmed(static_cast<SSUSessionConfirmedPacket*>(packet));
      break;
    case SSUPayloadType::RelayRequest:
      WriteRelayRequest(static_cast<SSURelayRequestPacket*>(packet));
      break;
    case SSUPayloadType::RelayResponse:
      WriteRelayResponse(static_cast<SSURelayResponsePacket*>(packet));
      break;
    case SSUPayloadType::RelayIntro:
      WriteRelayIntro(static_cast<SSURelayIntroPacket*>(packet));
      break;
    case SSUPayloadType::Data:
      WriteDataMessage(static_cast<SSUDataPacket*>(packet));
      break;
    case SSUPayloadType::PeerTest:
      WritePeerTest(static_cast<SSUPeerTestPacket*>(packet));
      break;
    case SSUPayloadType::SessionDestroyed:
      WriteSessionDestroyed(static_cast<SSUSessionDestroyedPacket*>(packet));
      break;
    case SSUPayloadType::Unknown:
    default:
      throw std::runtime_error("SSUPacketBuilder: unknown payload type");
  }
}

}  // namespace core
}  // namespace kovri
