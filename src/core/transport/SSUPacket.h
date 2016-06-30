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
#include <vector>

#include "RouterInfo.h"

namespace i2p {
namespace transport {

/// @enum SSUSize
/// @brief Constants used to represent sizes in SSU including
///   packet, crypto, and implementation
enum struct SSUSize : const std::size_t {
  MTUv4 = 1484,
  MTUv6 = 1472,
  HeaderIPv4 = 20,
  HeaderIPv6 = 40,
  HeaderUDP = 8,
  PacketMaxIPv4 = MTUv4 - HeaderIPv4 - HeaderUDP,  // Total: 1456
  PacketMaxIPv6 = MTUv6 - HeaderIPv6 - HeaderUDP,  // Total: 1424
  HeaderMin = 37,
  MAC = 16,
  IV = 16,
  IntroKey = 32,
  BufferMargin = 18,
  KeyingMaterial = 64,
  DHPublic = 256,
  MaxReceivedMessages = 1000,  // TODO(unassigned): research this value
};

/// @enum SSUFlag
/// @brief Constants used to represent flags used at the packet level
enum struct SSUFlag : const std::uint8_t {
  ExtendedOptions = 0x04,
  Rekey = 0x08,
  DataExtendedIncluded = 0x02,
  DataWantReply = 0x04,
  DataRequestPreviousACKs = 0x08,  // TODO(unassigned): unimplemented
  DataExplicitCongestionNotification = 0x10,  // TODO(unassigned): unimplemented
  DataACKBitfieldsIncluded = 0x40,
  DataExplicitACKsIncluded = 0x80,
  DataACKBitFieldHasNext = 0x80,
};

/// @enum SSUPayloadType
/// @brief SSU payload types assigned with spec-specific value
/// @note 4 bits
enum struct SSUPayloadType : const std::uint8_t {
  SessionRequest = 0,
  SessionCreated,
  SessionConfirmed,
  RelayRequest,
  RelayResponse,
  RelayIntro,
  Data,
  PeerTest,
  SessionDestroyed,
  Unknown  // TODO(unassigned): fully implement
};

/// @class SSUHeader
/// @brief Constitutes all SSU headers
class SSUHeader {
 public:
  SSUHeader();

  explicit SSUHeader(
      SSUPayloadType type);

  SSUHeader(
      SSUPayloadType type,
      std::uint8_t* mac,
      std::uint8_t* iv,
      std::uint32_t time);

  void SetMAC(
      std::uint8_t* mac);

  std::uint8_t* GetMAC() const;

  void SetIV(
      std::uint8_t* iv);

  std::uint8_t const* GetIV() const;

  /// Sets the type of the payload
  /// @param type nonnegative integer between 0 and 8
  /// @throw std::invalid_argument if the type is invalid
  void SetPayloadType(
      short type);  // TODO(unassigned): replace this C-style type

  SSUPayloadType GetPayloadType() const;

  void SetRekey(
      bool rekey);

  void SetExtendedOptions(
      bool extended);

  void SetExtendedOptionsData(
      std::uint8_t* data,
      std::size_t size);

  std::uint8_t const* GetExtendedOptionsData() const;

  std::size_t GetExtendedOptionsSize() const;

  void SetTime(
      std::uint32_t time);

  std::uint32_t GetTime() const;

  bool HasRekey() const;

  bool HasExtendedOptions() const;

  /// @brief Computes the header size based on which options are set.
  /// @return The size (in bytes) of this header.
  std::size_t GetSize() const;

 private:
  std::uint8_t* m_MAC, *m_IV, *m_ExtendedOptions;
  bool m_Rekey, m_Extended;
  std::uint32_t m_Time;
  SSUPayloadType m_PayloadType;
  std::size_t m_ExtendedOptionsSize;
};

/// @class SSUPacket
/// @brief Constitutes all SSU packets
class SSUPacket {
 public:
  /// @brief Sets the header of this packet to the given unique pointer
  /// @param header SSU packet header
  /// @note Ownership of the pointer is transferred
  void SetHeader(
      std::unique_ptr<SSUHeader> header);

  /// @brief Getter for the header of this packet.
  /// @return A raw pointer to the header of this packet.
  SSUHeader* GetHeader() const;

  std::size_t GetSize() const;

  // TODO(EinMByte): Get rid of this
  std::uint8_t* m_RawData;
  std::size_t m_RawDataLength;

 protected:
  std::unique_ptr<SSUHeader> m_Header;
};

/// @class SSUSessionRequestPacket
/// @brief Payload type 0: SessionRequest
class SSUSessionRequestPacket : public SSUPacket {
 public:
  void SetDhX(
      std::uint8_t* dhX);

  std::uint8_t const* GetDhX() const;

  void SetIPAddress(
      std::uint8_t* address,
      std::size_t size);

  std::uint8_t const* GetIPAddress() const;

  std::size_t GetIPAddressSize() const;

  std::size_t GetSize() const;

 private:
  std::size_t m_IPAddressSize;
  std::uint8_t* m_DhX, *m_IPAddress;
};

/// @class SSUSessionCreatedPacket
/// @brief Payload type 1: SessionCreated
class SSUSessionCreatedPacket : public SSUPacket {
 public:
  void SetDhY(
      std::uint8_t* dhY);

  std::uint8_t const* GetDhY() const;

  void SetIPAddress(
      std::uint8_t* address,
      std::size_t size);

  std::uint8_t const* GetIPAddress() const;

  std::size_t GetIPAddressSize() const;

  void SetPort(
      std::uint16_t port);

  std::uint16_t GetPort() const;

  void SetRelayTag(
      std::uint32_t relay_tag);

  std::uint32_t GetRelayTag() const;

  void SetSignature(
      std::uint8_t* signature,
      std::size_t size);

  std::uint8_t* GetSignature() const;

  std::size_t GetSignatureSize() const;

  void SetSignedOnTime(
      std::uint32_t time);

  std::uint32_t GetSignedOnTime() const;

  std::size_t GetSize() const;

 private:
  std::size_t m_AddressSize, m_SignatureSize;
  std::uint8_t* m_DhY, *m_IPAddress, *m_Signature;
  std::uint16_t m_Port;
  std::uint32_t m_RelayTag, m_SignedOnTime;
};

/// @class SSUSessionConfirmedPacket
/// @brief Payload type 2: SessionConfirmed
class SSUSessionConfirmedPacket : public SSUPacket {
 public:
  void SetRemoteRouterIdentity(
      const i2p::data::IdentityEx& identity);

  i2p::data::IdentityEx GetRemoteRouterIdentity() const;

  void SetSignature(
      std::uint8_t* signature);

  std::uint8_t const* GetSignature() const;

  void SetSignedOnTime(
      std::uint32_t time);

  std::uint32_t GetSignedOnTime() const;

  std::size_t GetSize() const;

 private:
  i2p::data::IdentityEx m_RemoteIdentity;
  std::uint8_t* m_Signature;
  std::uint32_t m_SignedOnTime;
};

/// @class SSURelayRequestPacket
/// @brief Payload type 3: RelayRequest
class SSURelayRequestPacket : public SSUPacket {
 public:
  void SetRelayTag(
      std::uint32_t tag);

  std::uint32_t GetRelayTag() const;

  void SetIPAddress(
      std::uint8_t* address,
      std::size_t size);

  std::uint8_t const* GetIPAddress() const;

  void SetChallenge(
      std::uint8_t* challenge,
      std::size_t size);

  std::uint8_t const* GetChallenge() const;

  void SetPort(
      std::uint16_t port);

  std::uint16_t GetPort() const;

  void SetIntroKey(
      std::uint8_t* key);

  std::uint8_t const* GetIntroKey() const;

  void SetNonce(
      std::uint32_t nonce);

  std::uint32_t GetNonce() const;

  std::size_t GetSize() const;

 private:
  std::uint32_t m_RelayTag, m_Nonce;
  std::size_t m_IPAddressSize, m_ChallengeSize;
  std::uint8_t* m_IPAddress, *m_Challenge, *m_IntroKey;
  std::uint16_t m_Port;
};

/// @class SSURelayResponsePacket
/// @brief Payload type 4: RelayResponse
class SSURelayResponsePacket : public SSUPacket {
 public:
  void SetNonce(
      std::uint32_t nonce);

  std::uint32_t GetNonce() const;

  void SetIPAddressAlice(
      std::uint8_t* address,
      std::size_t size);

  std::uint8_t const* GetIPAddressAlice() const;

  std::size_t GetIPAddressAliceSize() const;

  void SetIPAddressCharlie(
      std::uint8_t* address,
      std::size_t size);

  std::uint8_t const* GetIPAddressCharlie() const;

  void SetPortAlice(
      std::uint16_t port);

  std::uint16_t GetPortAlice() const;

  void SetPortCharlie(
      std::uint16_t port);

  std::uint16_t GetPortCharlie() const;

  std::size_t GetSize() const;

 private:
  std::size_t m_IPAddressAliceSize, m_IPAddressCharlieSize;
  std::uint32_t m_Nonce;
  std::uint8_t* m_IPAddressAlice, *m_IPAddressCharlie;
  std::uint16_t m_PortAlice, m_PortCharlie;
};

/// @class SSURelayIntroPacket
/// @brief Payload type 5: RelayIntro
class SSURelayIntroPacket : public SSUPacket {
 public:
  void SetIPAddress(
      std::uint8_t* address,
      std::size_t size);

  std::uint8_t const* GetIPAddress() const;

  std::size_t GetIPAddressSize() const;

  void SetChallenge(
      std::uint8_t* challenge,
      std::size_t size);

  std::uint8_t const* GetChallenge() const;

  void SetPort(
      std::uint16_t port);

  std::uint16_t GetPort() const;

  std::size_t GetSize() const;

 private:
  std::size_t m_IPAddressSize, m_ChallengeSize;
  std::uint8_t* m_IPAddress, *m_Challenge;
  std::uint16_t m_Port;
};

/// @class SSUFragment
/// @brief Constitutes all SSU fragments
class SSUFragment {
 public:
  void SetMessageID(
      std::uint32_t message_ID);

  void SetNumber(
      std::uint8_t number);

  void SetIsLast(
      bool is_last);

  void SetSize(
      std::size_t size);

  std::size_t GetSize() const;

  void SetData(
      std::uint8_t* data);

 private:
  std::uint8_t m_MessageID;
  std::uint8_t m_Number;
  bool m_IsLast;
  std::size_t m_Size;
  std::uint8_t* m_Data;
};

/// @class SSUDataPacket
/// @brief Payload type 6: Data
class SSUDataPacket : public SSUPacket {
 public:
  void AddExplicitACK(
      std::uint32_t message_ID);

  void AddACK(
      std::uint32_t message_ID);

  void AddACKBitfield(
      std::uint8_t bitfield);

  void AddFragment(
      SSUFragment fragment);

  std::size_t GetSize() const;

 private:
  std::uint8_t m_Flag;
  std::vector<std::uint32_t> m_ExplicitACKs;
  std::vector<std::uint32_t> m_ACKs;
  std::vector<std::uint8_t> m_ACKBitfields;
  std::vector<SSUFragment> m_Fragments;
};

/// @class SSUPeerTestPacket
/// @brief Payload type 7: PeerTest
class SSUPeerTestPacket : public SSUPacket {
 public:
  void SetNonce(
      std::uint32_t nonce);

  std::uint32_t GetNonce() const;

  void SetIPAddress(
      std::uint32_t address);

  std::uint32_t GetIPAddress() const;

  void SetPort(
      std::uint16_t port);

  std::uint16_t GetPort() const;

  void SetIntroKey(
      std::uint8_t* key);

  std::uint8_t const* GetIntroKey() const;

  std::size_t GetSize() const;

 private:
  std::uint32_t m_Nonce, m_IPAddress;
  std::uint8_t* m_IntroKey;
  std::uint16_t m_Port;
};

/// @class SSUSessionDestroyedPacket
/// @brief Payload type 8: SessionDestroyed
class SSUSessionDestroyedPacket : public SSUPacket {};

/// @class SSUPacketParser
/// @brief Constitutes SSU packet parsing
class SSUPacketParser {
 public:
  SSUPacketParser() = default;

  SSUPacketParser(
      std::uint8_t* data,
      std::size_t len);

  /// @brief Parses an SSU header.
  /// @return a pointer to the newly constructed SSUHeader object
  /// @throw std::length_error if the buffer contains less data than the
  //    minimum SSU header size
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
  /// @brief Advances the internal data pointer by the given amount
  /// @param amount the amount by which to advance the data pointer
  /// @throw std::length_error if amount exceeds the remaining data length
  void ConsumeData(
      std::size_t amount);

  /// @brief Consume a given amount of bytes, and return a pointer to first consumed
  ///   byte.
  /// @return a pointer to the first byte that was consumed (m_Data + amount)
  /// @throw std::length_error if amount exceeds the remaining data length
  std::uint8_t* ReadBytes(
      std::size_t amount);

  /// @brief Reads a std::uint32_t, i.e. a 4 byte unsigned integer
  /// @return the newly read std::uint32_t
  /// @throw std::length_error if less than 4 bytes are available for reading
  std::uint32_t ReadUInt32();

  /// @brief Reads a std::uint16_t, i.e. a 2 byte unsigned integer
  /// @return the newly read std::uint16_t
  /// @throw std::length_error if less than 2 bytes are available for reading
  std::uint16_t ReadUInt16();

  /// @brief Reads a std::uint8_t, i.e. a single byte
  /// @return the newly read byte as a std::uint8_t
  /// @throw std::length_error if no bytes are available for reading
  std::uint8_t ReadUInt8();

  SSUFragment ParseFragment();

 private:
  std::uint8_t* m_Data;
  std::size_t m_Length;
};

namespace SSUPacketBuilder {

void WriteData(
    std::uint8_t*& pos,
    const std::uint8_t* data,
    std::size_t len);

void WriteUInt8(
    std::uint8_t*& pos,
    std::uint8_t data);

void WriteUInt16(
    std::uint8_t*& pos,
    std::uint16_t data);

void WriteUInt32(
    std::uint8_t*& pos,
    std::uint32_t data);

std::size_t GetPaddingSize(
    std::size_t size);

std::size_t GetPaddedSize(
    std::size_t size);

/// @brief Writes an SSU header into a data buffer.
/// @pre The data buffer must be sufficiently large.
void WriteHeader(
    std::uint8_t*& data,
    SSUHeader* header);

void WriteSessionRequest(
    std::uint8_t*& buf,
    SSUSessionRequestPacket* packet);

void WriteSessionCreated(
    std::uint8_t*& buf,
    SSUSessionCreatedPacket* packet);

void WriteSessionConfirmed(
    std::uint8_t*& buf,
    SSUSessionConfirmedPacket* packet);

void WriteRelayRequest(
    std::uint8_t*& buf,
    SSURelayRequestPacket* packet);

void WriteRelayResponse(
    std::uint8_t*& buf,
    SSURelayResponsePacket* packet);

void WriteRelayIntro(
    std::uint8_t*& buf,
    SSURelayIntroPacket* packet);

void WriteData(
    std::uint8_t*& buf,
    SSUDataPacket* packet);

void WritePeerTest(
    std::uint8_t*& buf,
    SSUPeerTestPacket* packet);

void WriteSessionDestroyed(
    std::uint8_t*& buf,
    SSUSessionDestroyedPacket* packet);

void WritePacket(
    std::uint8_t*& buf,
    SSUPacket* packet);
}  // namespace SSUPacketBuilder

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_SSUPACKET_H_
