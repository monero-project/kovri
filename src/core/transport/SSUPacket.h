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
const uint8_t SSU_FLAG_EXTENDED_OPTIONS = 0x04;

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

  SSUHeader() = default;
  SSUHeader(PayloadType type, uint8_t* mac, uint8_t* iv,
      uint32_t time);

  void SetMac(uint8_t* macPtr);
  uint8_t const* GetMac() const;
  void SetIv(uint8_t* ivPtr);
  uint8_t const* GetIv() const;

  /// Sets the type of the payload
  /// @param type nonnegative integer between 0 and 8 
  /// @throw std::invalid_argument if the type is invalid
  void SetPayloadType(short type);
  PayloadType GetPayloadType() const;

  void SetRekey(bool rekey);
  void SetExtendedOptions(bool extended);
  void SetExtendedOptionsData(uint8_t* data, std::size_t size);
  uint8_t const* GetExtendedOptionsData() const;
  std::size_t GetExtendedOptionsSize() const;

  void SetTime(uint32_t time);
  uint32_t GetTime() const;

  bool HasRekey() const;
  bool HasExtendedOptions() const;

  /// @brief Computes the header size based on which options are set.
  /// @return The size (in bytes) of this header.
  std::size_t GetSize() const;

private:
  uint8_t* m_Mac, * m_Iv, * m_ExtendedOptions;
  bool m_Rekey, m_Extended;
  uint32_t m_Time;
  PayloadType m_PayloadType;
  std::size_t m_ExtendedOptionsSize;
};

class SSUPacket {
public:
  /// @brief Sets the header of this packet to the given unique pointer,
  ///        ownership of the pointer is transferred
  void SetHeader(std::unique_ptr<SSUHeader> header);

  /// @brief Getter for the header of this packet.
  /// @return A raw pointer to the header of this packet.
  SSUHeader* GetHeader() const;

  std::size_t GetSize() const;

  // TODO(EinMByte): Get rid of this
  uint8_t* m_RawData;
  std::size_t m_RawDataLength;
protected:
  std::unique_ptr<SSUHeader> m_Header;
};

class SSUSessionRequestPacket : public SSUPacket {
public:
  void SetDhX(uint8_t* dhX);
  uint8_t const* GetDhX() const;
  void SetIpAddress(uint8_t* ip, std::size_t size);
  std::size_t GetIpAddressSize() const;
  std::size_t GetSize() const;
private:
  std::size_t m_IpAddressSize;
  uint8_t* m_DhX, * m_IpAddress;
};

class SSUSessionCreatedPacket : public SSUPacket {
public:
  void SetDhY(uint8_t* dhY);
  uint8_t const* GetDhY() const;
  void SetIpAddress(uint8_t* ip, std::size_t size);
  uint8_t const* GetIpAddress() const;
  std::size_t GetIpAddressSize() const;
  void SetPort(uint16_t port);
  uint16_t GetPort() const;
  void SetRelayTag(uint32_t relayTag);
  uint32_t GetRelayTag() const;
  void SetSignature(uint8_t* signature, std::size_t size);
  uint8_t* GetSignature() const;
  void SetSignedOnTime(uint32_t time);
  uint32_t GetSignedOnTime() const;
  std::size_t GetSize() const;
private:
  std::size_t m_AddressSize, m_SignatureSize;
  uint8_t* m_DhY, * m_IpAddress, * m_Signature;
  uint16_t m_Port;
  uint32_t m_RelayTag, m_SignedOnTime;
};


class SSUSessionConfirmedPacket : public SSUPacket {
public:
  void SetRemoteRouterIdentity(const i2p::data::IdentityEx& identity);
  i2p::data::IdentityEx GetRemoteRouterIdentity() const;
  void SetSignature(uint8_t* signature);
  uint8_t const* GetSignature() const;
  void SetSignedOnTime(uint32_t time);
  uint32_t GetSignedOnTime() const;
  std::size_t GetSize() const;
private:
  i2p::data::IdentityEx m_RemoteIdentity;
  uint8_t* m_Signature;
  uint32_t m_SignedOnTime;
};

class SSURelayRequestPacket : public SSUPacket {
public:
  void SetRelayTag(uint32_t tag);
  uint32_t GetRelayTag() const;
  void SetIpAddress(uint8_t* ipAddress, std::size_t size);
  uint8_t const* GetIpAddress() const;
  void SetChallenge(uint8_t* challenge, std::size_t size);
  uint8_t const* GetChallenge() const;
  void SetPort(uint16_t port);
  uint16_t GetPort() const;
  void SetIntroKey(uint8_t* key);
  uint8_t const* GetIntroKey() const;
  void SetNonce(uint32_t nonce);
  uint32_t GetNonce() const;
  std::size_t GetSize() const;
private:
  uint32_t m_RelayTag, m_Nonce;
  std::size_t m_IpAddressSize, m_ChallengeSize;
  uint8_t* m_IpAddress, * m_Challenge, * m_IntroKey;
  uint16_t m_Port;
};

class SSURelayResponsePacket : public SSUPacket {
public:
  void SetNonce(uint32_t nonce);
  uint32_t GetNonce() const;
  void SetIpAddressAlice(uint8_t* ipAddress, std::size_t size);
  uint8_t const* GetIpAddressAlice() const;
  std::size_t GetIpAddressAliceSize() const;
  void SetIpAddressCharlie(uint8_t* ipAddress, std::size_t size);
  uint8_t const* GetIpAddressCharlie() const;
  void SetPortAlice(uint16_t port);
  uint16_t GetPortAlice() const;
  void SetPortCharlie(uint16_t port);
  uint16_t GetPortCharlie() const;
  std::size_t GetSize() const;
private:
  std::size_t m_IpAddressAliceSize, m_IpAddressCharlieSize;
  uint32_t m_Nonce;
  uint8_t* m_IpAddressAlice, * m_IpAddressCharlie;
  uint16_t m_PortAlice, m_PortCharlie;
};

class SSURelayIntroPacket : public SSUPacket {
public:
  void SetIpAddress(uint8_t* ipAddress, std::size_t size);
  uint8_t const* GetIpAddress() const;
  std::size_t GetIpAddressSize() const;
  void SetChallenge(uint8_t* challenge, std::size_t size);
  uint8_t const* GetChallenge() const;
  void SetPort(uint16_t port);
  uint16_t GetPort() const;
  std::size_t GetSize() const;
private:
  std::size_t m_IpAddressSize, m_ChallengeSize;
  uint8_t* m_IpAddress, * m_Challenge;
  uint16_t m_Port;
};


class SSUFragment {
public:
  void SetMessageId(uint32_t messageId);
  void SetNumber(uint8_t number);
  void SetIsLast(bool isLast);
  void SetSize(std::size_t size);
  std::size_t GetSize() const;
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
  void AddExplicitACK(uint32_t messageId);
  void AddACK(uint32_t messageId);
  void AddACKBitfield(uint8_t bitfield);
  void AddFragment(SSUFragment fragment);
  std::size_t GetSize() const;
private:
  uint8_t m_Flag;
  std::vector<uint32_t> m_ExplicitACKs;
  std::vector<uint32_t> m_ACKs;
  std::vector<uint8_t> m_ACKBitfields;
  std::vector<SSUFragment> m_Fragments;
};

class SSUPeerTestPacket : public SSUPacket {
public:
  void SetNonce(uint32_t nonce);
  uint32_t GetNonce() const;
  void SetIpAddress(uint32_t ipAddress);
  uint32_t GetIpAddress() const;
  void SetPort(uint16_t port);
  uint16_t GetPort() const;
  void SetIntroKey(uint8_t* key);
  uint8_t const* GetIntroKey() const;
  std::size_t GetSize() const;
private:
  uint32_t m_Nonce, m_IpAddress;
  uint8_t* m_IntroKey;
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
 
  /// @brief Parses an SSU header.
  /// @return a pointer to the newly constructed SSUHeader object
  /// @throw std::length_error if the buffer contains less data than the
  //         minimum SSU header size SSU_HEADER_SIZE_MIN
  std::unique_ptr<SSUHeader> ParseHeader();

  /// @brief Parses an SSUPacket, including the header
  /// @return a pointer to the newly constructed SSUPacket object
  std::unique_ptr<SSUPacket> ParsePacket();

  /// @brief Parses a session request packet, without the header
  std::unique_ptr<SSUSessionRequestPacket> ParseSessionRequest();
  /// @brief Parses a session created packet, without the header
  std::unique_ptr<SSUSessionCreatedPacket> ParseSessionCreated();
  /// @brief Parses a session confirmed packet, without the header
  /// TODO: Support multiple fragments?
  std::unique_ptr<SSUSessionConfirmedPacket> ParseSessionConfirmed();
  /// @brief Parses a relay request packet, without the header
  std::unique_ptr<SSURelayRequestPacket> ParseRelayRequest();
  /// @brief Parses a relay response packet, without the header
  std::unique_ptr<SSURelayResponsePacket> ParseRelayResponse();
  /// @brief Parses a relay intro packet, without the header
  std::unique_ptr<SSURelayIntroPacket> ParseRelayIntro();
  /// @brief Parses a data packet, without the header
  std::unique_ptr<SSUDataPacket> ParseData();
  /// @brief Parses a peer test packet, without the header
  std::unique_ptr<SSUPeerTestPacket> ParsePeerTest();
  /// @brief Parses a session destroyed packet, without the header
  std::unique_ptr<SSUSessionDestroyedPacket> ParseSessionDestroyed();

private:
  uint8_t* m_Data;
  std::size_t m_Length;
};

namespace SSUPacketBuilder {

  void WriteData(uint8_t*& pos, const uint8_t* data, std::size_t len);
  void WriteUInt8(uint8_t*& pos, uint8_t data);
  void WriteUInt32(uint8_t*& pos, uint32_t data);

  /// @brief Writes an SSU header into a data buffer.
  /// @pre The data buffer must be sufficiently large.
  void WriteHeader(uint8_t*& data, SSUHeader* header);

  std::unique_ptr<uint8_t> BuildSessionRequest(
      const SSUSessionRequestPacket& packet);
  std::unique_ptr<uint8_t> BuildSessionCreated(
      const SSUSessionCreatedPacket& packet);
  std::unique_ptr<uint8_t> BuildSessionConfirmed(
      const SSUSessionConfirmedPacket& packet);
  std::unique_ptr<uint8_t> BuildRelayRequest(
      const SSURelayRequestPacket& packet);
  std::unique_ptr<uint8_t> BuildRelayResponse(
      const SSURelayResponsePacket& packet);
  std::unique_ptr<uint8_t> BuildRelayIntro(
      const SSURelayIntroPacket& packet);
  std::unique_ptr<uint8_t> BuildData(
      const SSUDataPacket& packet);
  std::unique_ptr<uint8_t> BuildPeerTest(
      const SSUPeerTestPacket& packet);
  std::unique_ptr<uint8_t> BuildSessionDestroyed(
      const SSUSessionDestroyedPacket& packet);
}

}
}

#endif  // SRC_CORE_TRANSPORT_SSUPACKET_H_
