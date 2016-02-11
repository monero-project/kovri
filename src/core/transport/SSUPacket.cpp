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


void SSUPacketParser::ConsumeData(std::size_t amount) {
  if (amount > m_Length)
    throw std::length_error("SSUPacketParser: too many bytes to consume.");
  m_Data += amount;
  m_Length -= amount;
}

SSUPacketParser::SSUPacketParser(uint8_t* data, std::size_t len)
  : m_Data(data), m_Length(len) {

}

std::unique_ptr<SSUHeader> SSUPacketParser::ParseHeader() {
  if (m_Length < SSU_HEADER_SIZE_MIN)
    return nullptr; /// TODO(EinMByte): Do something meaningful
  std::unique_ptr<SSUHeader> header(new SSUHeader());
  // Set MAC and IV
  header->SetMac(m_Data);
  ConsumeData(SSU_MAC_SIZE);
  header->SetIv(m_Data);
  ConsumeData(SSU_IV_SIZE);

  // Extract information from flag (payload type and rekey/extened options)
  const uint8_t flag = *m_Data;
  header->SetRekey(flag & SSU_FLAG_REKEY);
  header->SetExtendedOptions(flag & SSU_FLAG_EXTENDED_OPTIONS);
  header->SetPayloadType(flag >> 4);
  ConsumeData(1);

  // Extract the time
  header->SetTime(bufbe32toh(m_Data));
  ConsumeData(4);

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
  if (m_Length < 16 + 1)
    return nullptr; /// TODO(EinMByte): Do something meaningful
  packet->SetDhX(m_Data);
  ConsumeData(16);
  packet->SetIpAddress(m_Data);
  return packet; 
}

}
}
