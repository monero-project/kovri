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

#include "RouterInfo.h"

namespace i2p {
namespace transport {

const std::size_t SSU_HEADER_SIZE_MIN = 37;
const std::size_t SSU_MAC_SIZE = 16;
const std::size_t SSU_IV_SIZE = 16;
const std::size_t SSU_INTRO_KEY_SIZE = 32;

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


class SSUSessionConfirmedPacket : public SSUPacket {
public:
  void SetRemoteRouterIdentity(const i2p::data::IdentityEx& identity);
private:
  i2p::data::IdentityEx m_RemoteIdentity;
};

class SSURelayRequestPacket : public SSUPacket {
public:
  void SetRelayTag(uint32_t tag);
  void SetIpAddress(uint8_t* ipAddress);
  void SetChallenge(uint8_t* challenge);
  void SetPort(uint8_t port);
  void SetIntroKey(uint8_t* key);
  void SetNonce(uint32_t nonce);
private:
  uint32_t m_RelayTag, m_Nonce;
  uint8_t* m_IpAddress, * m_Challenge, * m_IntroKey;
  uint16_t m_Port;
};

class SSURelayResponsePacket : public SSUPacket {
public:
  void SetNonce(uint32_t nonce);
  void SetIpAddressAlice(uint8_t* ipAddress);
  void SetIpAddressCharlie(uint8_t* ipAddress);
  void SetPortAlice(uint8_t port);
  void SetPortCharlie(uint8_t port);
private:
  uint32_t m_Nonce;
  uint8_t* m_IpAddressAlice, * m_IpAddressCharlie;
  uint16_t m_PortAlice, m_PortCharlie;
};

class SSURelayIntroPacket : public SSUPacket {
public:
  void SetIpAddress(uint8_t* ipAddress);
  void SetChallenge(uint8_t* challenge);
  void SetPort(uint8_t port);
private:
  uint8_t* m_IpAddress, * m_Challenge;
  uint16_t m_Port;
};


class SSUFragment {
public:
  std::size_t GetSize() const;

  void SetMessageId(uint32_t messageId);
  void SetNumber(uint8_t number);
  void SetIsLast(bool isLast);
  void SetSize(std::size_t size);
  void SetData(uint8_t* data);
private:
  uint8_t m_MessageId;
  uint8_t m_Number;
  bool m_IsLast;
  std::size_t m_Size;
  uint8_t* m_Data;
};

class SSUDataPacket : public SSUPacket {
public:
  void AddACK(uint32_t messageId);
  void AddACKBitfield(uint8_t bitfield);
  void AddFragment(SSUFragment fragment);
private:
  uint8_t m_Flag;
  std::vector<uint32_t> m_ACKs;
  std::vector<uint8_t> m_ACKBitfields;
  std::vector<SSUFragment> m_Fragments;
};

class SSUPeerTestPacket : public SSUPacket {
public:
  void SetNonce(uint32_t nonce);
  void SetIpAddress(uint8_t* ipAddress);
  void SetPort(uint8_t port);
  void SetIntroKey(uint8_t* key);
private:
  uint32_t m_Nonce;
  uint8_t* m_IpAddress, * m_IntroKey;
  uint16_t m_Port;

};

class SSUSessionDestroyedPacket : public SSUPacket { };

class SSUPacketParser {
  /// Advances the internal data pointer by the given amount
  /// @param amount the amount by which to advance the data pointer
  /// @throw std::length_error if amount exceeds the remaining data length
  void ConsumeData(std::size_t amount);

  /// Consume a given amount of bytes, and return a pointer to first consumed
  ///  byte.
  /// @return a pointer to the first byte that was consumed (m_Data + amount)
  /// @throw std::length_error if amount exceeds the remaining data length
  uint8_t* ReadBytes(std::size_t amount);

  /// Reads a uint32_t, i.e. a 4 byte unsigned integer
  /// @return the newly read uint32_t
  /// @throw std::length_error if less than 4 bytes are available for reading
  uint32_t ReadUInt32();

  /// Reads a uint16_t, i.e. a 2 byte unsigned integer
  /// @return the newly read uint16_t
  /// @throw std::length_error if less than 2 bytes are available for reading
  uint16_t ReadUInt16();

  /// Reads a uint8_t, i.e. a single byte
  /// @return the newly read byte as a uint8_t
  /// @throw std::length_error if no bytes are available for reading 
  uint8_t ReadUInt8();

  SSUFragment ParseFragment();
public:
  SSUPacketParser() = default;
  SSUPacketParser(uint8_t* data, std::size_t len);
 
  /// Parses an SSU header.
  /// @return a pointer to the newly constructed SSUHeader object
  std::unique_ptr<SSUHeader> ParseHeader();
 
  std::unique_ptr<SSUSessionRequestPacket> ParseSessionRequest();
  std::unique_ptr<SSUSessionCreatedPacket> ParseSessionCreated();
  /// TODO: Support multiple fragments?
  std::unique_ptr<SSUSessionConfirmedPacket> ParseSessionConfirmed();
  std::unique_ptr<SSURelayRequestPacket> ParseRelayRequest();
  std::unique_ptr<SSURelayResponsePacket> ParseRelayResponse();
  std::unique_ptr<SSURelayIntroPacket> ParseRelayIntro();
  std::unique_ptr<SSUDataPacket> ParseData();
  std::unique_ptr<SSUPeerTestPacket> ParsePeerTest();
  std::unique_ptr<SSUSessionDestroyedPacket> ParseSessionDestroyed();

private:
  uint8_t* m_Data;
  std::size_t m_Length;
};

}
}

#endif  // SRC_CORE_TRANSPORT_SSUPACKET_H_
