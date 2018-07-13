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

#ifndef SRC_CORE_ROUTER_TRANSPORTS_SSU_PACKET_H_
#define SRC_CORE_ROUTER_TRANSPORTS_SSU_PACKET_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "core/router/info.h"

#include "core/util/byte_stream.h"

namespace kovri {
namespace core {
/// @enum SSUSize
/// @brief Constants used to represent sizes in SSU
enum SSUSize : std::uint16_t
{
  MTUv4 = 1484,
  MTUv6 = 1488,
  HeaderIPv4 = 20,
  HeaderIPv6 = 40,
  HeaderUDP = 8,
  PacketMaxIPv4 = MTUv4 - HeaderIPv4 - HeaderUDP,  // Total: 1456
  PacketMaxIPv6 = MTUv6 - HeaderIPv6 - HeaderUDP,  // Total: 1440
  HeaderMin = 37,
  MAC = 16,
  IV = 16,
  IntroKey = 32,
  BufferMargin = IV + 2,  // IV + 2 bytes size are appended on validation
  RawPacketBuffer = (MTUv4 > MTUv6 ? MTUv4 : MTUv6) + BufferMargin,
  FragmentBuffer =
      (PacketMaxIPv4 > PacketMaxIPv6 ? PacketMaxIPv4 : PacketMaxIPv6)
      + BufferMargin,
  KeyingMaterial = 64,
  DHPublic = 256,
  MaxReceivedMessages = 1000,  // TODO(unassigned): research this value
  MaxIntroducers = 3,
  // Session buffer sizes imply *before* non-mod-16 padding. See SSU spec.
  RelayRequestBuffer = 96,  ///< 96 bytes (no Alice IP included) or 112 bytes (4-byte Alice IP included)
  RelayResponseBuffer = 80,  ///< 64 (Alice IPv4) or 80 (Alice IPv6) bytes
  RelayIntroBuffer = 48,
  PeerTestBuffer = 80,
  SessionDestroyedBuffer = 48,
};

/// @enum SSUFlag
/// @brief Constants used to represent flags used at the packet level
enum SSUFlag : std::uint8_t
{
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
enum SSUPayloadType : std::uint8_t
{
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

// TODO(unassigned): finish SSU refactor, see notes in #140 (especially regarding excessive getters/setters, and const correct pointers)

/// @class SSUHeader
/// @brief Constitutes all SSU headers
class SSUHeader
{
 public:
  SSUHeader();

  /// @brief Constructs SSU header with pre-determined payload type
  explicit SSUHeader(const SSUPayloadType type);

  /// @brief Constructs SSU header with pre-determined payload type and content
  /// @note Assumes content is valid
  /// @param SSUPayloadType SSU payload type
  /// @param mac Pointer to header's MAC material
  /// @param iv Pointer to header's IV material
  /// @param time Header's timestamp
  SSUHeader(
      const SSUPayloadType type,
      std::uint8_t* mac,
      std::uint8_t* iv,
      const std::uint32_t time);

  /// @brief Sets MAC from appointed position within header
  /// @note Assumes content is valid (based on position)
  void SetMAC(std::uint8_t* mac) noexcept
  {
    m_MAC = mac;
  }

  /// @brief Gets acquired MAC after it has been set when parsed
  /// @return Pointer to MAC material
  std::uint8_t* GetMAC() const noexcept
  {
    return m_MAC;
  }

  /// @brief Sets IV from appointed position within header
  /// @note Assumes content is valid (based on position)
  /// @param Pointer to header's IV material
  void SetIV(std::uint8_t* iv) noexcept
  {
    m_IV = iv;
  }

  /// @brief Gets acquired IV after it has been set when parsed
  /// @return Pointer to IV material
  std::uint8_t const* GetIV() const noexcept
  {
    return m_IV;
  }

  /// @brief Sets the type of SSU payload
  /// @note Assumes content is valid (based on position)
  /// @param type nonnegative integer between 0 and 8
  /// @throw std::invalid_argument if the type is invalid
  // TODO(unassigned): replace this C-style type
  void SetPayloadType(const short type)
  {
    if (type < 0 || type > 8)
      throw std::invalid_argument("SetPayloadType invalid type given");
    m_PayloadType = static_cast<SSUPayloadType>(type);
  }

  /// @brief Gets SSU header payload type
  /// @return SSU header payload type
  SSUPayloadType GetPayloadType() const noexcept
  {
    return m_PayloadType;
  }

  /// @brief Sets timestamp from appointed position within header
  /// @note Assumes content is valid (based on position)
  void SetTime(const std::uint32_t time) noexcept
  {
    m_Time = time;
  }

  /// @return Timestamp that was previously set when parsed
  std::uint32_t GetTime() const noexcept
  {
    return m_Time;
  }

  /// @brief Sets rekey after testing if flag has been set
  /// @note Assumes content is valid (based on position)
  /// @param rekey True if rekey is set, false if not
  void SetRekey(const bool rekey) noexcept
  {
    m_Rekey = rekey;
  }

  /// @brief Returns bool of rekey that was set when parsed
  /// @return True if rekey is set, false if not
  bool HasRekey() const noexcept
  {
    return m_Rekey;
  }

  /// @brief Sets extended options after testing if flag is set
  /// @param extended True if extended options are set, false if not
  void SetExtendedOptions(const bool extended) noexcept
  {
    m_Extended = extended;
  }

  /// @brief Sets extended options data from appointed position within header
  /// @note Assumes content is extended options material based on bit being set
  /// @param data Extended options to write
  /// @param size Size of extended options (in bytes)
  void SetExtendedOptionsData(std::uint8_t* data, const std::uint8_t size) noexcept
  {
    m_ExtendedOptions = data;
    m_ExtendedOptionsSize = size;
  }

  /// @return Pointer to extended options data that was previously set when parsed
  std::uint8_t const* GetExtendedOptionsData() const noexcept
  {
    return m_ExtendedOptions;
  }

  /// @return Extended options size that was previously set when parsed
  std::uint8_t GetExtendedOptionsSize() const noexcept
  {
    return m_ExtendedOptionsSize;
  }

  /// @return Extended options bool that was previously set when parsed
  bool HasExtendedOptions() const noexcept
  {
    return m_Extended;
  }

  /// @brief Computes the header size based on which options are set.
  /// @return The size (in bytes) of this header.
  std::size_t GetSize() const noexcept
  {
    std::uint16_t size = SSUSize::HeaderMin;
    if (HasRekey())
      size += SSUSize::KeyingMaterial;
    if (HasExtendedOptions())
      size +=
          1  // 1 byte value of extended options size followed by that many bytes
          + m_ExtendedOptionsSize;
    return size;
  }

 private:
  std::uint8_t *m_MAC, *m_IV, *m_ExtendedOptions;
  bool m_Rekey, m_Extended;
  std::uint32_t m_Time;
  SSUPayloadType m_PayloadType;

  /// @brief Size of extended options (in bytes)
  /// @details "If the extended options flag is set, a one byte option size value is appended,
  ///  followed by that many extended option bytes." This is 'that many' number of bytes.
  /// @notes The 1 byte value of size is parsed/written in builder implementation, not here.
  std::uint8_t m_ExtendedOptionsSize;
};

/// @class SSUPacket
/// @brief Constitutes all SSU packets
class SSUPacket
{
 public:
  /// @brief Sets the header of this packet to the given unique pointer
  /// @param header SSU packet header
  /// @note Ownership of the pointer is transferred
  void SetHeader(std::unique_ptr<SSUHeader> header)
  {
    m_Header = std::move(header);
  }

  /// @brief Getter for the header of this packet.
  /// @return A raw pointer to the header of this packet.
  SSUHeader* GetHeader() const noexcept
  {
    return m_Header.get();
  }

  /// @return Header size if available, else 0
  std::size_t GetSize() const noexcept
  {
    return m_Header ? m_Header->GetSize() : 0;
  }

  // TODO(EinMByte): Get rid of this
  std::uint8_t* m_RawData;
  std::size_t m_RawDataLength;

 protected:
  std::unique_ptr<SSUHeader> m_Header;
};

/// @class SSUSessionRequestPacket
/// @brief Payload type 0: SessionRequest
/// @details This is the first message sent to establish a session
class SSUSessionRequestPacket : public SSUPacket
{
 public:
  /// @brief Sets Diffie-Hellman X to begin the DH agreement
  /// @note Assumes content is valid (based on position)
  /// @param dhX Pointer to DH X
  void SetDhX(std::uint8_t* dhX) noexcept
  {
    m_DhX = dhX;
  }

  /// @return Pointer to DH X that was previously set when parsed
  std::uint8_t const* GetDhX() const noexcept
  {
    return m_DhX;
  }

  /// @brief Sets Bob's 1 byte IP address and byte size representation
  ///   of Bob's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Bob's IP address
  /// @param size Bob's IP address size (in bytes)
  void SetIPAddress(std::uint8_t* address, const std::uint8_t size)
  {
    assert(size == 4 || size == 16);
    if (size != 4 && size != 16)
      throw std::length_error("invalid IP address size");
    m_IPAddress = address;
    m_IPAddressSize = size;
  }

  /// @return Pointer to Bob's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddress() const noexcept
  {
    return m_IPAddress;
  }

  /// @return Bob's IP address size that was previously set when parsed
  std::uint8_t GetIPAddressSize() const noexcept
  {
    return m_IPAddressSize;
  }

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const noexcept
  {
    return SSUPacket::GetSize() + SSUSize::DHPublic  // DH X-parameter
           + 1  // Bob's IP address size
           + m_IPAddressSize;  // That many byte representation of IP address
  }

 private:
  std::uint8_t m_IPAddressSize;
  std::uint8_t* m_DhX, *m_IPAddress;
};

/// @class SSUSessionCreatedPacket
/// @brief Payload type 1: SessionCreated
/// @details This is the response to a SessionRequest
class SSUSessionCreatedPacket : public SSUPacket
{
 public:
  /// @brief Sets Diffie-Hellman Y to begin the DH agreement
  /// @note Assumes content is valid (based on position)
  /// @param dhY Pointer to DH Y
  void SetDhY(std::uint8_t* dhY) noexcept
  {
    m_DhY = dhY;
  }

  /// @return Pointer to DH Y that was previously set when parsed
  std::uint8_t const* GetDhY() const noexcept
  {
    return m_DhY;
  }

  /// @brief Sets Alice's 1 byte IP address and byte size representation
  ///   of Alice's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Alice's IP address
  /// @param size Alice's IP address size (in bytes)
  void SetIPAddress(std::uint8_t* address, const std::uint8_t size)
  {
    assert(size == 4 || size == 16);
    if (size != 4 && size != 16)
      throw std::length_error("invalid IP address size");
    m_IPAddress = address;
    m_AddressSize = size;
  }

  /// @return Pointer to Alice's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddress() const noexcept
  {
    return m_IPAddress;
  }

  /// @return Alice's IP address size that was previously set when parsed
  std::uint8_t GetIPAddressSize() const noexcept
  {
    return m_AddressSize;
  }

  /// @brief Sets Alice's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPort(const std::uint16_t port) noexcept
  {
    m_Port = port;
  }

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPort() const noexcept
  {
    return m_Port;
  }

  /// @brief Sets 4 byte relay (introduction) tag which Alice can publish
  /// @note Assumes content is valid (based on position)
  void SetRelayTag(const std::uint32_t relay_tag) noexcept
  {
    m_RelayTag = relay_tag;
  }

  /// @return Relay tag that was previously set when parsed
  std::uint32_t GetRelayTag() const noexcept
  {
    return m_RelayTag;
  }

  /// @brief Sets 4 byte timestamp (seconds from the epoch) for use
  ///   in the signature
  /// @note Assumes content is valid (based on position)
  void SetSignedOnTime(const std::uint32_t time) noexcept
  {
    m_SignedOnTime = time;
  }

  /// @return Timestamp that was previously set when parsed
  std::uint32_t GetSignedOnTime() const noexcept
  {
    return m_SignedOnTime;
  }

  /// @brief Sets Bob's signature of the critical exchanged data
  /// @details (DH X + DH Y + Alice's IP + Alice's port + Bob's IP + Bob's port
  ///   + Alice's new relay tag + Bob's signed on time)
  /// @note Assumes content is valid (based on position)
  /// @param signature Pointer to Bob's signature
  /// @param size Bob's signature size
  void SetSignature(std::uint8_t* signature, const std::size_t size) noexcept
  {
    m_Signature = signature;
    m_SignatureSize = size;
  }

  /// @return Pointer to Bob's signature that was previously set when parsed
  std::uint8_t* GetSignature() const noexcept
  {
    return m_Signature;
  }

  /// @return Bob's signature size that was previously set when parsed
  std::size_t GetSignatureSize() const noexcept
  {
    return m_SignatureSize;
  }

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const noexcept
  {
    return SSUPacket::GetSize()
           + SSUSize::DHPublic  // Y to complete the DH agreement
           + 1 + m_AddressSize  // 1 byte address size, address size,
           + 2 + 4 + 4  // Port size (2 bytes), relay tag size, time size
           + m_SignatureSize;  // Signature size
  }

 private:
  std::size_t m_SignatureSize;
  std::uint8_t m_AddressSize;
  std::uint8_t *m_DhY, *m_Signature, *m_IPAddress;
  std::uint16_t m_Port;
  std::uint32_t m_RelayTag, m_SignedOnTime;
};

/// @class SSUSessionConfirmedPacket
/// @brief Payload type 2: SessionConfirmed
/// @details This is the response to a SessionCreated message and the
///   last step in establishing a session. There may be multiple
///   SessionConfirmed messages required if the Router Identity must be fragmented
/// @note 1 byte identity fragment info is currently skipped
class SSUSessionConfirmedPacket : public SSUPacket
{
 public:
  SSUSessionConfirmedPacket() : m_Signature(nullptr), m_SignedOnTime(0) {}

  /// @brief Sets Alice's remote router identity fragment
  /// @note Assumes content is valid (based on position)
  void SetRemoteRouterIdentity(const kovri::core::IdentityEx& identity)
  {
    m_RemoteIdentity = identity;
  }

  /// @return Reference to the router identity to be included in the
  ///         SessionConfirmed message
  const kovri::core::IdentityEx& GetRemoteRouterIdentity() const noexcept
  {
    return m_RemoteIdentity;
  }

  /// @brief Sets 4 byte signed-on timestamp
  /// @note Assumes content is valid (based on position)
  void SetSignedOnTime(const std::uint32_t time) noexcept
  {
    m_SignedOnTime = time;
  }

  /// @return Timestamp that was previously set when parsed
  std::uint32_t GetSignedOnTime() const noexcept
  {
    return m_SignedOnTime;
  }

  /// @brief Sets Alice's signature of the critical exchanged data
  /// @details (X + Y + Alice's IP + Alice's port + Bob's IP + Bob's port
  ///   + Alice's new relay tag + Alice's signed on time)
  /// @note Assumes content is valid (based on position)
  /// @param signature Pointer to Alice's signature
  void SetSignature(std::uint8_t* signature) noexcept
  {
    m_Signature = signature;
  }
  /// @return Pointer to Alices's signature size that was previously set when parsed
  std::uint8_t const* GetSignature() const noexcept
  {
    return m_Signature;
  }

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const noexcept;

 private:
  kovri::core::IdentityEx m_RemoteIdentity;
  std::uint8_t* m_Signature;
  std::uint32_t m_SignedOnTime;
};

/// @class SSURelayRequestPacket
/// @brief Payload type 3: RelayRequest
/// @details This is the first message sent from Alice to Bob
///   to request an introduction to Charlie.
class SSURelayRequestPacket : public SSUPacket
{
 public:
  /// @brief Sets 4 byte relay (introduction) tag, nonzero, as received by Alice
  ///   in the SessionCreated message from Bob
  /// @note Assumes content is valid (based on position)
  /// @param tag Relay tag
  void SetRelayTag(const std::uint32_t relay_tag) noexcept
  {
    m_RelayTag = relay_tag;
  }

  /// @return Relay tag that was previously set when parsed
  std::uint32_t GetRelayTag() const noexcept
  {
    return m_RelayTag;
  }

  /// @brief Sets Alice's 1 byte IP address and byte size representation
  ///   of Alice's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Alice's IP address
  /// @param size Alice's IP address size (in bytes)
  void SetIPAddress(std::uint8_t* address, const std::uint8_t size)
  {
    assert(!size || size == 4);  // See spec for details
    if (size && size != 4)
      throw std::length_error("invalid IP address size");
    m_IPAddress = address;
    m_IPAddressSize = size;
  }

  /// @return Pointer to Alice's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddress() const noexcept
  {
    return m_IPAddress;
  }

  // TODO(unassigned): GetIPAddressSize() ?

  /// @brief Sets Alice's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPort(const std::uint16_t port) noexcept
  {
    m_Port = port;
  }

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPort() const noexcept
  {
    return m_Port;
  }

  /// @brief Sets 1 byte challenge size and that many bytes to be relayed
  ///   to Charlie in the intro
  /// @note Assumes content is valid (based on position)
  /// @param challenge Pointer to challenge size
  /// @param size Size of challenge size
  void SetChallenge(std::uint8_t* challenge, const std::size_t size) noexcept
  {
    m_Challenge = challenge;
    m_ChallengeSize = size;
  }

  /// @return Pointer to challenge that was previously set when parsed
  std::uint8_t const* GetChallenge() const noexcept
  {
    return m_Challenge;
  }

  /// @brief Sets Alice's 32-byte introduction key
  ///   (so Bob can reply with Charlie's info)
  /// @note Assumes content is valid (based on position)
  /// @param key Pointer to intro key
  void SetIntroKey(std::uint8_t* intro_key) noexcept
  {
    m_IntroKey = intro_key;
  }

  /// @return Pointer to intro key that was previously set when parsed
  std::uint8_t const* GetIntroKey() const noexcept
  {
    return m_IntroKey;
  }

  /// @brief Sets 4 byte nonce of Alice's relay request
  /// @note Assumes content is valid (based on position)
  /// @param nonce 4 byte nonce
  void SetNonce(const std::uint32_t nonce) noexcept
  {
    m_Nonce = nonce;
  }

  /// @return Nonce that was previously set when parsed
  std::uint32_t GetNonce() const noexcept
  {
    return m_Nonce;
  }

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const noexcept
  {
    return SSUPacket::GetSize() + 4  // Relay tag
           + 1  // Alice's IP address size
           + m_IPAddressSize  // that many bytes representation of IP address
           + 2  // Alice's port number
           + 1  // Challenge size
           + m_ChallengeSize  // That many bytes to be relayed to Charlie in intro
           + SSUSize::IntroKey  // Alice's 32-byte Intro key
           + 4;  // Nonce of Alice's relay request
  }

 private:
  std::uint32_t m_RelayTag, m_Nonce;
  std::size_t m_ChallengeSize;
  std::uint8_t m_IPAddressSize;
  std::uint8_t *m_IPAddress, *m_Challenge, *m_IntroKey;
  std::uint16_t m_Port;
};

/// @class SSURelayResponsePacket
/// @brief Payload type 4: RelayResponse
/// @details This is the response to a RelayRequest and is sent from Bob to Alice
class SSURelayResponsePacket : public SSUPacket
{
 public:
  /// @brief Sets Charlie's 1 byte IP address and byte size representation
  ///   of Charlie's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Charlie's IP address
  /// @param size Charlie's IP address size (in bytes)
  void SetIPAddressCharlie(std::uint8_t* address, const std::uint8_t size)
  {
    // Must be IPv4 because Alice will send SessionRequest after HolePunch
    assert(size == 4);
    if (size != 4)
      throw std::length_error("invalid IP address size");
    m_IPAddressCharlie = address;
    m_IPAddressCharlieSize = size;
  }

  /// @return Pointer to Charlie's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddressCharlie() const noexcept
  {
    return m_IPAddressCharlie;
  }

  /// @brief Sets Charlies's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Charlie's port number
  void SetPortCharlie(const std::uint16_t port) noexcept
  {
    m_PortCharlie = port;
  }

  /// @return Charlie's IP port that was previously set when parsed
  std::uint16_t GetPortCharlie() const noexcept
  {
    return m_PortCharlie;
  }

  /// @brief Sets Alice's 1 byte IP address and byte size representation
  ///   of Alice's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Alice's IP address
  /// @param size Alice's IP address size (in bytes)
  void SetIPAddressAlice(std::uint8_t* address, const std::uint8_t size)
  {
    assert(size == 4 || size == 16);
    if (size != 4 && size != 16)
      throw std::length_error("invalid IP address size");
    m_IPAddressAlice = address;
    m_IPAddressAliceSize = size;
  }

  /// @return Pointer to Alice's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddressAlice() const noexcept
  {
    return m_IPAddressAlice;
  }

  /// @return Alice's IP address size that was previously set when parsed
  std::uint8_t GetIPAddressAliceSize() const noexcept
  {
    return m_IPAddressAliceSize;
  }

  /// @brief Sets Alices's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPortAlice(const std::uint16_t port) noexcept
  {
    m_PortAlice = port;
  }

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPortAlice() const noexcept
  {
    return m_PortAlice;
  }

  /// @brief Sets 4 byte nonce sent by Alice
  /// @param nonce 4 byte nonce
  void SetNonce(const std::uint32_t nonce) noexcept
  {
    m_Nonce = nonce;
  }
  /// @return Nonce that was previously set when parsed
  std::uint32_t GetNonce() const noexcept
  {
    return m_Nonce;
  }

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const noexcept
  {
    return SSUPacket::GetSize() + 1  // Charlie's IP address size
           + m_IPAddressCharlieSize  // That many byte representation of IP address
           + 2  // Charlie's port number
           + 1  // Alice's IP address size
           + m_IPAddressAliceSize  // That many byte representation of IP address
           + 2  // Alice's port number
           + 4;  // Nonce sent by Alice
  }

 private:
  std::uint8_t m_IPAddressAliceSize, m_IPAddressCharlieSize;
  std::uint32_t m_Nonce;
  std::uint8_t *m_IPAddressAlice, *m_IPAddressCharlie;
  std::uint16_t m_PortAlice, m_PortCharlie;
};

/// @class SSURelayIntroPacket
/// @brief Payload type 5: RelayIntro
/// @details This is the introduction for Alice, which is sent from Bob to Charlie
class SSURelayIntroPacket : public SSUPacket
{
 public:
  /// @brief Sets Alice's 1 byte IP address and byte size representation
  ///   of Alice's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Alice's IP address
  /// @param size Alice's IP address size (in bytes)
  void SetIPAddress(std::uint8_t* address, const std::uint8_t size)
  {
    // Alice's is always 4 bytes because she is trying to connect to Charlie via IPv4
    assert(size == 4);
    if (size != 4)
      throw std::length_error("invalid IP address size");
    m_IPAddress = address;
    m_IPAddressSize = size;
  }

  /// @return Pointer to Alice's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddress() const noexcept
  {
    return m_IPAddress;
  }

  /// @return Alice's IP address size that was previously set when parsed
  std::uint8_t GetIPAddressSize() const noexcept
  {
    return m_IPAddressSize;
  }

  /// @brief Sets Alice's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPort(const std::uint16_t port) noexcept
  {
    m_Port = port;
  }

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPort() const noexcept
  {
    return m_Port;
  }

  /// @brief Sets 1 byte challenge size and that many bytes to be relayed
  ///   from Alice
  /// @note Assumes content is valid (based on position)
  /// @param challenge Pointer to challenge size
  /// @param size Size of challenge size
  void SetChallenge(std::uint8_t* challenge, const std::size_t size) noexcept
  {
    m_Challenge = challenge;
    m_ChallengeSize = size;
  }

  /// @return Pointer to challenge that was previously set when parsed
  std::uint8_t const* GetChallenge() const noexcept
  {
    return m_Challenge;
  }

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const noexcept
  {
    return SSUPacket::GetSize() + 1  // Alice's IP address size
           + m_IPAddressSize  // that many bytes representation of IP address
           + 2  // Alice's port number
           + 1  // Challenge size
           + m_ChallengeSize;  // That many bytes related from Alice
  }

 private:
  std::size_t m_ChallengeSize;
  std::uint8_t m_IPAddressSize;
  std::uint8_t *m_IPAddress, *m_Challenge;
  std::uint16_t m_Port;
};

/// @class SSUFragment
/// @brief Constitutes all SSU fragments
/// @note Used exclusively for payload type 6: Data
class SSUFragment
{
 public:
  /// @brief Sets 4 byte message ID
  /// @note Assumes content is valid (based on position)
  /// @param message_id 4 byte message ID
  void SetMessageID(const std::uint32_t message_ID) noexcept
  {
    m_MessageID = message_ID;
  }

  /// @brief Sets fragment size (0 - 16383)
  /// @param size Fragment size
  void SetSize(const std::size_t size) noexcept
  {
    m_Size = size;
  }

  /// @return Fragment size that was set when parsed
  std::size_t GetSize() const noexcept
  {
    return m_Size;
  }

  /// @brief Sets 'is last' bit
  /// @param bool True if last, false if not
  void SetIsLast(const bool is_last) noexcept
  {
    m_IsLast = is_last;
  }

  /// @brief Sets fragment number (0 - 127)
  /// @param number Fragment number
  void SetNumber(const std::uint8_t number) noexcept
  {
    m_Number = number;
  }

  /// @brief Sets whole fragment data
  /// @param Pointer to fragment size
  void SetData(std::uint8_t* data) noexcept
  {
    m_Data = data;
  }

 private:
  std::uint8_t m_MessageID;
  std::uint8_t m_Number;
  bool m_IsLast;
  std::size_t m_Size;
  std::uint8_t* m_Data;
};

/// @class SSUDataPacket
/// @brief Payload type 6: Data
/// @details This message is used for data transport and acknowledgment
class SSUDataPacket : public SSUPacket
{
 public:
  /// @brief Add explicit acks if they are included
  /// @param message_id The message ID being fully ACK'd
  void AddExplicitACK(const std::uint32_t message_ID)
  {
    m_ExplicitACKs.push_back(message_ID);
  }

  /// @brief Add ACK if included (not including bitfield)
  /// @param message_id The message ID being fully ACK'd
  void AddACK(const std::uint32_t message_ID)
  {
    m_ACKs.push_back(message_ID);
  }

  /// @brief Add ACK bitfield if ACK is included
  /// @note Called after ACK is included
  /// @param bitfield ACK bitfield
  void AddACKBitfield(const std::uint8_t bitfield)
  {
    m_ACKBitfields.push_back(bitfield);
  }

  /// @brief Add fragment for parsing
  /// @param fragment Fragment to be parsed
  void AddFragment(const SSUFragment fragment)
  {
    m_Fragments.push_back(fragment);
  }

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const
  {
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

 private:
  std::vector<std::uint32_t> m_ExplicitACKs;
  std::vector<std::uint32_t> m_ACKs;
  std::vector<std::uint8_t> m_ACKBitfields;
  std::vector<SSUFragment> m_Fragments;
};

/// @class SSUPeerTestPacket
/// @brief Payload type 7: PeerTest
/// @details Implements packet for collaborative reachability testing for peers
class SSUPeerTestPacket : public SSUPacket
{
 public:
  /// @brief Sets 4 byte nonce
  /// @note Assumes content is valid (based on position)
  /// @param nonce 4 byte nonce
  void SetNonce(const std::uint32_t nonce) noexcept
  {
    m_Nonce = nonce;
  }

  /// @return Nonce that was previously set when parsed
  std::uint32_t GetNonce() const noexcept
  {
    return m_Nonce;
  }

  /// @brief Sets IP address as set by message owner (see SSU spec)
  /// @note Assumes content is valid (based on position)
  /// @param address IP address
  void SetIPAddress(const boost::asio::ip::address& address) noexcept
  {
    m_IPAddress = address;
  }

  /// @return IP address that was previously set when parsed
  const boost::asio::ip::address& GetIPAddress() const noexcept
  {
    return m_IPAddress;
  }

  /// @brief Sets IP address size as set by message owner (see SSU spec)
  // TODO(anonimal): use or remove
  void SetIPAddressSize(const std::uint8_t size) noexcept
  {
    m_IPAddressSize = size;
  }

  /// @return IP address size that was previously set when parsed
  std::uint8_t GetIPAddressSize() const noexcept
  {
    return m_IPAddressSize;
  }

  /// @brief Sets Alice's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPort(const std::uint16_t port) noexcept
  {
    m_Port = port;
  }

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPort() const noexcept
  {
    return m_Port;
  }

  /// @brief Alice's or Charlie's 32-byte introduction key
  /// @note Assumes content is valid (based on position)
  /// @param key Pointer to intro key
  void SetIntroKey(std::uint8_t* intro_key) noexcept
  {
    m_IntroKey = intro_key;
  }

  /// @return Pointer to intro key that was previously set when parsed
  std::uint8_t const* GetIntroKey() const noexcept
  {
    return m_IntroKey;
  }

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const noexcept
  {
    return SSUPacket::GetSize() + 4  // Nonce
           + 1  // Alice's IP address size
           + m_IPAddressSize  // Bob or Charlie: 4 or 16 (IPv4/6), Alice: 0, see spec
           + 2  // Alice's port number
           // Alice's or Charlie's 32-byte introduction key
           + SSUSize::IntroKey;
  }

 private:
  std::uint32_t m_Nonce;
  boost::asio::ip::address m_IPAddress;
  std::uint8_t m_IPAddressSize;
  std::uint8_t* m_IntroKey;
  std::uint16_t m_Port;
};

/// @class SSUSessionDestroyedPacket
/// @brief Payload type 8: SessionDestroyed
/// @details This message does not contain any data. Its typical size
///   (including header) in current implementation is 48 bytes (before non-mod-16 padding)
class SSUSessionDestroyedPacket : public SSUPacket {};

/// @class SSUPacketParser
/// @brief Constitutes SSU packet parsing
class SSUPacketParser : private kovri::core::InputByteStream {
 public:
  SSUPacketParser() = default;

  /// @brief Constructs packet parser from message/packet
  /// @param data Pointer to message/packet
  /// @param len Length of message/packet
  SSUPacketParser(std::uint8_t* data, const std::size_t len);

  /// @brief Parses an SSU header.
  /// @return a pointer to the newly constructed SSUHeader object
  /// @throw std::length_error if the buffer contains less data than the
  ///    minimum SSU header size
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
  /// @brief Parses data fragment
  /// @return A parsed data fragment
  SSUFragment ParseFragment();

  /// @brief Parsed header
  std::unique_ptr<SSUHeader> m_Header;
};

/// @class SSUPacketBuilder
/// @brief Constitutes SSU packet building
class SSUPacketBuilder final : public kovri::core::OutputByteStream {
 public:
  SSUPacketBuilder() = default;

  /// @brief Constructs packet builder with a given buffer
  /// @param data Pointer to the first byte of the buffer 
  /// @param len Length of the buffer
  SSUPacketBuilder(std::uint8_t* data, const std::size_t len);

  /// @brief Calculates padding size needed for message
  /// @details All messages contain 0 or more bytes of padding.
  ///   Each message must be padded to a 16 byte boundary,
  ///   as required by the AES256 encryption layer
  /// @param size Size of message
  // TODO(anonimal): we only need to pass 2 bytes and return 1 byte
  static std::size_t GetPaddingSize(const std::size_t size)
  {
    return (size % 16) ? 16 - size % 16 : 0;
  }

  /// @brief Gets padded size of message
  /// @param size Size of message
  // TODO(anonimal): we only need to pass 2 bytes and return 2 bytes
  static std::size_t GetPaddedSize(const std::size_t size)
  {
    return size + GetPaddingSize(size);
  }

  /// @brief Writes an SSU header into a data buffer.
  /// @pre The data buffer must be sufficiently large.
  /// @param data Reference to pointer to data
  /// @param header Pointer to SSU header
  void WriteHeader(SSUHeader* header);

  /// @brief Writes SessionRequest message
  /// @param packet SessionRequest packet to write
  void WriteSessionRequest(SSUSessionRequestPacket* packet);

  /// @brief Writes SessionCreated message
  /// @param packet SessionCreated packet to write
  void WriteSessionCreated(SSUSessionCreatedPacket* packet);

  /// @brief Writes SessionConfirmed message
  /// @param packet SessionConfirmed packet to write
  void WriteSessionConfirmed(SSUSessionConfirmedPacket* packet);

  /// @brief Writes RelayRequest message
  /// @param packet RelayRequest packet to write
  void WriteRelayRequest(SSURelayRequestPacket* packet);

  /// @brief Writes RelayResponse message
  /// @param packet RelayResponse packet to write
  void WriteRelayResponse(SSURelayResponsePacket* packet);

  /// @brief Writes RelayIntro message
  /// @param packet RelayIntro packet to write
  void WriteRelayIntro(SSURelayIntroPacket* packet);

  /// @brief Writes Data message
  /// @param packet Data packet to write
  void WriteDataMessage(SSUDataPacket* packet);

  /// @brief Writes PeerTest message
  /// @param packet PeerTest packet to write
  void WritePeerTest(SSUPeerTestPacket* packet);

  /// @brief Writes SessionDestroyed message
  /// @param packet SessionDestroyed packet to write
  void WriteSessionDestroyed(SSUSessionDestroyedPacket* packet);

  /// @brief Writes SSU packet for SSU session
  /// @param packet SSU packet to write
  /// @note packet is one of any payload types
  void WritePacket(SSUPacket* packet);
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_TRANSPORTS_SSU_PACKET_H_
