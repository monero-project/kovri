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

#ifndef SRC_CORE_TRANSPORT_SSUPACKET_H_
#define SRC_CORE_TRANSPORT_SSUPACKET_H_

#include <cinttypes>
#include <memory>

namespace i2p {
namespace transport {

const std::size_t SSU_HEADER_SIZE_MIN = 37;
const std::size_t SSU_MAC_SIZE = 16;
const std::size_t SSU_IV_SIZE = 16;

class SSUHeader {
public:
  enum class PayloadType {
    SessionRequest = 0,
    SessionCreated,
    SessionConfirmed,
    RelayRequest,
    RelayResponse,
    RelayIntro,
    Data,
    PeerTest,
    SessionDestroyed
  };

  void SetMac(uint8_t* macPtr);
  void SetIv(uint8_t* ivPtr);

  /// Sets the type of the payload
  /// @param type nonnegative integer between 0 and 8 
  /// @throw std::invalid_argument if the type is invalid
  void SetPayloadType(short type);
  PayloadType GetPayloadType() const;

  void SetRekey(bool rekey);
  void SetExtendedOptions(bool extended);

  void SetTime(uint32_t time);
  uint32_t GetTime() const;

  bool HasRekey() const;
  bool HasExtendedOptions() const;

private:
  uint8_t* m_Mac, * m_Iv;
  bool m_Rekey, m_Extended;
  uint32_t m_Time;
  PayloadType m_PayloadType;
};

class SSUPacket {
public:
  void SetHeader(std::unique_ptr<SSUHeader> header);
protected:
  std::unique_ptr<SSUHeader> m_Header;
};

class SSUSessionRequestPacket : public SSUPacket {
public:
  void SetDhX(uint8_t* dhX);
  void SetIpAddress(uint8_t* ip);
private:
  uint8_t* m_DhX, * m_IpAddress;
};

class SSUSessionCreatedPacket : public SSUPacket {
public:
  void SetDhY(uint8_t* dhY);
  void SetIpAddress(uint8_t* ip);
  void SetPort(uint16_t port);
  void SetRelayTag(uint32_t relayTag);
  void SetSignature(uint8_t* signature);
private:
  uint8_t* m_DhY, * m_IpAddress, * m_Signature;
  uint16_t m_Port;
  uint32_t m_RelayTag;
};

class SSUPacketParser {
  /// Advances the internal data pointer by the given amount
  /// @param amount the amount by which to advance the data pointer
  /// @throw std::length_error if amount exceeds the remaining data length
  void ConsumeData(std::size_t amount);

public:
  SSUPacketParser() = default;
  SSUPacketParser(uint8_t* data, std::size_t len);
 
  /// Parses an SSU header.
  /// @return a pointer to the newly constructed SSUHeader object
  std::unique_ptr<SSUHeader> ParseHeader();
 
  std::unique_ptr<SSUSessionRequestPacket> ParseSessionRequest();
  std::unique_ptr<SSUSessionCreatedPacket> ParseSessionCreated();
  SSUPacket* ParseSessionConfirmed();
  SSUPacket* ParseRelayRequest();
  SSUPacket* ParseRelayResponse();
  SSUPacket* ParseRelayIntro();
  SSUPacket* ParseData();
  SSUPacket* ParsePeerTest();
  SSUPacket* ParseSessionDestroyed();

private:
  uint8_t* m_Data;
  std::size_t m_Length;
};

}
}

#endif  // SRC_CORE_TRANSPORT_SSUPACKET_H_
