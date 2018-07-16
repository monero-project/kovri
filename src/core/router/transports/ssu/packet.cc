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
std::size_t SSUSessionConfirmedPacket::get_size() const noexcept
{
  // This message must be a multiple of 16
  return SSUPacketBuilder::get_padded_size(
      SSUPacket::get_size() + 3  // Info and identity size
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

SSUHeader::SSUHeader(const SSUPayloadType type)
    : SSUHeader(type, nullptr, nullptr, 0) {}

SSUHeader::SSUHeader(
    const SSUPayloadType type,
    std::uint8_t* mac,
    std::uint8_t* iv,
    const std::uint32_t time)
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
    const std::size_t len)
    : InputByteStream(data, len) {}

SSUFragment SSUPacketParser::ParseFragment()
{
  // Patch for #823 so we can keep running with assertions
  if (gcount() < 4 /* message ID */ + 3 /* fragment info */)
    throw std::length_error(
        "SSUPacketParser: invalid packet size, fragment unavailable");

  SSUFragment fragment;
  fragment.set_msg_id(Read<std::uint32_t>());

  // TODO(unassigned): we should not setup a 4 byte array to parse 3 bytes
  //   and ByteStream should consider having a std::bitset implementation.
  std::array<std::uint8_t, 4> info_buf {{}};
  memcpy(info_buf.data() + 1, ReadBytes(3), 3);
  const std::uint32_t fragment_info = Read<std::uint32_t>(info_buf.data());
  fragment.set_size(fragment_info & 0x3FFF);  // bits 0 - 13
  // bits 15-14: unused, set to 0 for compatibility with future uses
  fragment.set_is_last(fragment_info & 0x010000);  // bit 16
  fragment.set_num(fragment_info >> 17);  // bits 23 - 17

  std::uint16_t const frag_size = fragment.get_size();

  // End session if fragmented size is greater than buffer size
  if (frag_size > size())
    {
      // TODO(anonimal): invalid size could be an implementation issue rather
      //   than an attack. Reconsider how we mitigate invalid fragment size.
      throw std::length_error("SSUPacketParser: invalid fragment size");
    }

  // Don't read if purported size is 0
  if (frag_size)
    fragment.set_data(ReadBytes(frag_size));

  return fragment;
}

std::unique_ptr<SSUHeader> SSUPacketParser::ParseHeader() {
  if (m_Length < SSUSize::HeaderMin)
    throw std::length_error("SSU header too small");
  auto header = std::make_unique<SSUHeader>();
  // Set MAC and IV
  header->set_mac(ReadBytes(SSUSize::MAC));
  header->set_iv(ReadBytes(SSUSize::IV));
  // Extract information from flag (payload type and rekey/extened options)
  const std::uint8_t flag = Read<std::uint8_t>();
  header->set_rekey(flag & SSUFlag::Rekey);
  header->set_ext_opts(flag & SSUFlag::ExtendedOptions);
  header->set_payload_type(flag >> 4);
  // Extract the time
  header->set_time(Read<std::uint32_t>());
  if (header->has_rekey()) {
    // TODO(EinMByte): Actually do something with the data
    // TODO(EinMByte): See issue #119, for some reason some rekey options
    //                 are sometimes set?
    SkipBytes(SSUSize::KeyingMaterial);
  }
  if (header->has_ext_opts()) {
    const std::size_t options_size = Read<std::uint8_t>();
    header->set_ext_opts_data(ReadBytes(options_size), options_size);
  }
  return header;
}

std::unique_ptr<SSUPacket> SSUPacketParser::ParsePacket() {
  m_Header = ParseHeader();
  std::unique_ptr<SSUPacket> packet;
  std::uint8_t* const old_data = m_DataPtr;
  const std::size_t old_length = m_Length;
  switch (m_Header->get_payload_type()) {
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
  packet->set_header(std::move(m_Header));
  return packet;
}

std::unique_ptr<SSUSessionRequestPacket> SSUPacketParser::ParseSessionRequest() {
  auto packet = std::make_unique<SSUSessionRequestPacket>();
  packet->set_dh_x(ReadBytes(SSUSize::DHPublic));
  std::uint8_t const size = Read<std::uint8_t>();
  packet->set_ip(ReadBytes(size), size);
  return packet;
}

std::unique_ptr<SSUSessionCreatedPacket> SSUPacketParser::ParseSessionCreated() {
  auto packet = std::make_unique<SSUSessionCreatedPacket>();
  packet->set_dh_y(ReadBytes(SSUSize::DHPublic));
  std::uint8_t const address_size = Read<std::uint8_t>();
  packet->set_ip(ReadBytes(address_size), address_size);
  packet->set_port(Read<std::uint16_t>());
  packet->set_relay_tag(Read<std::uint32_t>());
  packet->set_time(Read<std::uint32_t>());
  packet->set_sig(m_DataPtr, m_Length);
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
  packet->set_remote_ident(identity);
  packet->set_time(Read<std::uint32_t>());
  const std::size_t padding_size = SSUPacketBuilder::get_padding_size(
      m_Header->get_size() + init_length - m_Length
      + identity.GetSignatureLen());
  SkipBytes(padding_size);  // Padding
  packet->set_sig(m_DataPtr);
  return packet;
}

std::unique_ptr<SSURelayRequestPacket> SSUPacketParser::ParseRelayRequest() {
  auto packet = std::make_unique<SSURelayRequestPacket>();
  packet->set_relay_tag(Read<std::uint32_t>());
  std::uint8_t const address_size = Read<std::uint8_t>();
  packet->set_ip(ReadBytes(address_size), address_size);
  packet->set_port(Read<std::uint16_t>());
  const std::size_t challenge_size = Read<std::uint8_t>();
  packet->set_challenge(ReadBytes(challenge_size), challenge_size);
  packet->set_intro_key(ReadBytes(SSUSize::IntroKey));
  packet->set_nonce(Read<std::uint32_t>());
  return packet;
}

std::unique_ptr<SSURelayResponsePacket> SSUPacketParser::ParseRelayResponse() {
  auto packet = std::make_unique<SSURelayResponsePacket>();
  std::uint8_t const charlie_address_size = Read<std::uint8_t>();
  packet->set_charlie_ip(ReadBytes(charlie_address_size), charlie_address_size);
  packet->set_charlie_port(Read<std::uint16_t>());
  std::uint8_t const alice_address_size = Read<std::uint8_t>();
  packet->set_alice_ip(ReadBytes(alice_address_size), alice_address_size);
  packet->set_alice_port(Read<std::uint16_t>());
  packet->set_nonce(Read<std::uint32_t>());
  return packet;
}

std::unique_ptr<SSURelayIntroPacket> SSUPacketParser::ParseRelayIntro() {
  auto packet = std::make_unique<SSURelayIntroPacket>();
  std::uint8_t const address_size = Read<std::uint8_t>();
  packet->set_ip(ReadBytes(address_size), address_size);
  packet->set_port(Read<std::uint16_t>());
  const std::size_t challenge_size = Read<std::uint8_t>();
  packet->set_challenge(ReadBytes(challenge_size), challenge_size);
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
  packet->set_nonce(Read<std::uint32_t>());
  std::uint8_t const size(Read<std::uint8_t>());
  if (size)  // Bob or Charlie
    packet->set_ip(core::BytesToAddress(ReadBytes(size), size));
  packet->set_ip_size(size);
  packet->set_port(Read<std::uint16_t>());
  packet->set_intro_key(ReadBytes(SSUSize::IntroKey));
  return packet;
}

std::unique_ptr<SSUSessionDestroyedPacket> SSUPacketParser::ParseSessionDestroyed() {
  auto packet = std::make_unique<SSUSessionDestroyedPacket>();
  return packet;
}

SSUPacketBuilder::SSUPacketBuilder(
      std::uint8_t* data,
      const std::size_t len)
  : OutputByteStream(data, len) {}

void SSUPacketBuilder::WriteHeader(SSUHeader* header) {
  if (header->get_mac())
    WriteData(header->get_mac(), SSUSize::MAC);
  else
    SkipBytes(SSUSize::MAC);  // Write real MAC later
  WriteData(header->get_iv(), SSUSize::IV);
  const std::uint8_t flag =
      (header->get_payload_type() << 4) +
      (header->has_rekey() << 3) +
      (header->has_ext_opts() << 2);
  Write<std::uint8_t>(flag);
  Write<std::uint32_t>(header->get_time());
  if (header->has_ext_opts()) {
    Write<std::uint8_t>(header->get_ext_opts_size());
    WriteData(
        header->get_ext_opts_data(),
        header->get_ext_opts_size());
  }
}

void SSUPacketBuilder::WriteSessionRequest(SSUSessionRequestPacket* packet) {
  WriteData(packet->get_dh_x(), SSUSize::DHPublic);
  Write<std::uint8_t>(packet->get_ip_size());
  WriteData(packet->get_ip(), packet->get_ip_size());
}

void SSUPacketBuilder::WriteSessionCreated(SSUSessionCreatedPacket* packet) {
  WriteData(packet->get_dh_y(), SSUSize::DHPublic);
  Write<std::uint8_t>(packet->get_ip_size());
  WriteData(packet->get_ip(), packet->get_ip_size());
  Write<std::uint16_t>(packet->get_port());
  Write<std::uint32_t>(packet->get_relay_tag());
  Write<std::uint32_t>(packet->get_time());
  WriteData(packet->get_sig(), packet->get_sig_size());
}

void SSUPacketBuilder::WriteSessionConfirmed(
    SSUSessionConfirmedPacket* packet) {
  const std::uint8_t* const begin = tellp();
  Write<std::uint8_t>(0x01);  // 1 byte info, with 1 fragment
  const std::size_t identity_size = packet->get_remote_ident().GetFullLen();
  Write<std::uint16_t>(identity_size);
  std::uint8_t* const identity = m_DataPtr;
  SkipBytes(identity_size);
  packet->get_remote_ident().ToBuffer(identity, identity_size);

  Write<std::uint32_t>(packet->get_time());
  // Write padding here (rather than later), because it is in the middle of the
  // message
  const std::size_t signature_size = packet->get_remote_ident().GetSignatureLen();
  const std::size_t padding_size = get_padding_size(
      packet->get_header()->get_size() + tellp() - begin + signature_size);
  std::uint8_t* const padding = m_DataPtr;
  SkipBytes(padding_size);
  kovri::core::RandBytes(padding, padding_size);
  WriteData(packet->get_sig(), signature_size);
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
  switch (packet->get_header()->get_payload_type()) {
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
