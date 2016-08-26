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

#include "router_info.h"

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
  MaxIntroducers = 3,
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

  /// @brief Constructs SSU header with pre-determined payload type
  explicit SSUHeader(
      SSUPayloadType type);

  /// @brief Constructs SSU header with pre-determined payload type and content
  /// @note Assumes content is valid
  /// @param SSUPayloadType SSU payload type
  /// @param mac Pointer to header's MAC material
  /// @param iv Pointer to header's IV material
  /// @param time Header's timestamp
  SSUHeader(
      SSUPayloadType type,
      std::uint8_t* mac,
      std::uint8_t* iv,
      std::uint32_t time);

  /// @brief Sets MAC from appointed position within header
  /// @note Assumes content is valid (based on position)
  void SetMAC(
      std::uint8_t* mac);

  /// @brief Gets acquired MAC after it has been set when parsed
  /// @return Pointer to MAC material
  std::uint8_t* GetMAC() const;

  /// @brief Sets IV from appointed position within header
  /// @note Assumes content is valid (based on position)
  /// @param Pointer to header's IV material
  void SetIV(
      std::uint8_t* iv);

  /// @brief Gets acquired IV after it has been set when parsed
  /// @return Pointer to IV material
  std::uint8_t const* GetIV() const;

  /// @brief Sets the type of SSU payload
  /// @note Assumes content is valid (based on position)
  /// @param type nonnegative integer between 0 and 8
  /// @throw std::invalid_argument if the type is invalid
  void SetPayloadType(
      short type);  // TODO(unassigned): replace this C-style type

  /// @brief Gets SSU header payload type
  /// @return SSU header payload type
  SSUPayloadType GetPayloadType() const;

  /// @brief Sets timestamp from appointed position within header
  /// @note Assumes content is valid (based on position)
  void SetTime(
      std::uint32_t time);

  /// @return Timestamp that was previously set when parsed
  std::uint32_t GetTime() const;

  /// @brief Sets rekey after testing if flag has been set
  /// @note Assumes content is valid (based on position)
  /// @param rekey True if rekey is set, false if not
  void SetRekey(
      bool rekey);

  /// @brief Returns bool of rekey that was set when parsed
  /// @return True if rekey is set, false if not
  bool HasRekey() const;

  /// @brief Sets extended options after testing if flag is set
  /// @param extended True if extended options are set, false if not
  void SetExtendedOptions(
      bool extended);

  /// @brief Sets extended options data from appointed position within header
  /// @note Assumes content is extended options material based on bit being set
  void SetExtendedOptionsData(
      std::uint8_t* data,
      std::size_t size);

  /// @return Pointer to extended options data that was previously set when parsed
  std::uint8_t const* GetExtendedOptionsData() const;

  /// @return Extended options size that was previously set when parsed
  std::size_t GetExtendedOptionsSize() const;

  /// @return Extended options bool that was previously set when parsed
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

  /// @return Header size if available, else 0
  std::size_t GetSize() const;

  // TODO(EinMByte): Get rid of this
  std::uint8_t* m_RawData;
  std::size_t m_RawDataLength;

 protected:
  std::unique_ptr<SSUHeader> m_Header;
};

/// @class SSUSessionRequestPacket
/// @brief Payload type 0: SessionRequest
/// @details This is the first message sent to establish a session
class SSUSessionRequestPacket : public SSUPacket {
 public:
  /// @brief Sets Diffie-Hellman X to begin the DH agreement
  /// @note Assumes content is valid (based on position)
  /// @param dhX Pointer to DH X
  void SetDhX(
      std::uint8_t* dhX);

  /// @return Pointer to DH X that was previously set when parsed
  std::uint8_t const* GetDhX() const;

  /// @brief Sets Bob's 1 byte IP address and byte size representation
  ///   of Bob's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Bob's IP address
  /// @param size Bob's IP address size
  void SetIPAddress(
      std::uint8_t* address,
      std::size_t size);

  /// @return Pointer to Bob's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddress() const;

  /// @return Bob's IP address size that was previously set when parsed
  std::size_t GetIPAddressSize() const;

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const;

 private:
  std::size_t m_IPAddressSize;
  std::uint8_t* m_DhX, *m_IPAddress;
};

/// @class SSUSessionCreatedPacket
/// @brief Payload type 1: SessionCreated
/// @details This is the response to a SessionRequest
class SSUSessionCreatedPacket : public SSUPacket {
 public:
  /// @brief Sets Diffie-Hellman Y to begin the DH agreement
  /// @note Assumes content is valid (based on position)
  /// @param dhY Pointer to DH Y
  void SetDhY(
      std::uint8_t* dhY);

  /// @return Pointer to DH Y that was previously set when parsed
  std::uint8_t const* GetDhY() const;

  /// @brief Sets Alice's 1 byte IP address and byte size representation
  ///   of Alice's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Alice's IP address
  /// @param size Alice's IP address size
  void SetIPAddress(
      std::uint8_t* address,
      std::size_t size);

  /// @return Pointer to Alice's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddress() const;

  /// @return Alice's IP address size that was previously set when parsed
  std::size_t GetIPAddressSize() const;

  /// @brief Sets Alice's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPort(
      std::uint16_t port);

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPort() const;

  /// @brief Sets 4 byte relay (introduction) tag which Alice can publish
  /// @note Assumes content is valid (based on position)
  void SetRelayTag(
      std::uint32_t relay_tag);

  /// @return Relay tag that was previously set when parsed
  std::uint32_t GetRelayTag() const;

  /// @brief Sets 4 byte timestamp (seconds from the epoch) for use
  ///   in the signature
  /// @note Assumes content is valid (based on position)
  void SetSignedOnTime(
      std::uint32_t time);

  /// @return Timestamp that was previously set when parsed
  std::uint32_t GetSignedOnTime() const;

  /// @brief Sets Bob's signature of the critical exchanged data
  /// @details (DH X + DH Y + Alice's IP + Alice's port + Bob's IP + Bob's port
  ///   + Alice's new relay tag + Bob's signed on time)
  /// @note Assumes content is valid (based on position)
  /// @param signature Pointer to Bob's signature
  /// @param size Bob's signature size
  void SetSignature(
      std::uint8_t* signature,
      std::size_t size);

  /// @return Pointer to Bob's signature that was previously set when parsed
  std::uint8_t* GetSignature() const;

  /// @return Bob's signature size that was previously set when parsed
  std::size_t GetSignatureSize() const;

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const;

 private:
  std::size_t m_AddressSize, m_SignatureSize;
  std::uint8_t* m_DhY, *m_IPAddress, *m_Signature;
  std::uint16_t m_Port;
  std::uint32_t m_RelayTag, m_SignedOnTime;
};

/// @class SSUSessionConfirmedPacket
/// @brief Payload type 2: SessionConfirmed
/// @details This is the response to a SessionCreated message and the
///   last step in establishing a session. There may be multiple
///   SessionConfirmed messages required if the Router Identity must be fragmented
/// @note 1 byte identity fragment info is currently skipped
class SSUSessionConfirmedPacket : public SSUPacket {
 public:
  /// @brief Sets Alice's remote router identity fragment
  /// @note Assumes content is valid (based on position)
  void SetRemoteRouterIdentity(
      const i2p::data::IdentityEx& identity);

  /// @return Router identity that was previously set when parsed
  i2p::data::IdentityEx GetRemoteRouterIdentity() const;

  /// @brief Sets 4 byte signed-on timestamp
  /// @note Assumes content is valid (based on position)
  void SetSignedOnTime(
      std::uint32_t time);

  /// @return Timestamp that was previously set when parsed
  std::uint32_t GetSignedOnTime() const;

  /// @brief Sets Alice's signature of the critical exchanged data
  /// @details (X + Y + Alice's IP + Alice's port + Bob's IP + Bob's port
  ///   + Alice's new relay tag + Alice's signed on time)
  /// @note Assumes content is valid (based on position)
  /// @param signature Pointer to Alice's signature
  void SetSignature(
      std::uint8_t* signature);

  /// @return Pointer to Alices's signature size that was previously set when parsed
  std::uint8_t const* GetSignature() const;

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const;

 private:
  i2p::data::IdentityEx m_RemoteIdentity;
  std::uint8_t* m_Signature;
  std::uint32_t m_SignedOnTime;
};

/// @class SSURelayRequestPacket
/// @brief Payload type 3: RelayRequest
/// @details This is the first message sent from Alice to Bob
///   to request an introduction to Charlie.
class SSURelayRequestPacket : public SSUPacket {
 public:
  /// @brief Sets 4 byte relay (introduction) tag, nonzero, as received by Alice
  ///   in the SessionCreated message from Bob
  /// @note Assumes content is valid (based on position)
  /// @param tag Relay tag
  void SetRelayTag(
      std::uint32_t tag);

  /// @return Relay tag that was previously set when parsed
  std::uint32_t GetRelayTag() const;

  /// @brief Sets Alice's 1 byte IP address and byte size representation
  ///   of Alice's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Alice's IP address
  /// @param size Alice's IP address size
  void SetIPAddress(
      std::uint8_t* address,
      std::size_t size);

  /// @return Pointer to Alice's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddress() const;

  // TODO(unassigned): GetIPAddressSize() ?

  /// @brief Sets Alice's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPort(
      std::uint16_t port);

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPort() const;

  /// @brief Sets 1 byte challenge size and that many bytes to be relayed
  ///   to Charlie in the intro
  /// @note Assumes content is valid (based on position)
  /// @param challenge Pointer to challenge size
  /// @param size Size of challenge size
  void SetChallenge(
      std::uint8_t* challenge,
      std::size_t size);

  /// @return Pointer to challenge that was previously set when parsed
  std::uint8_t const* GetChallenge() const;

  /// @brief Sets Alice's 32-byte introduction key
  ///   (so Bob can reply with Charlie's info)
  /// @note Assumes content is valid (based on position)
  /// @param key Pointer to intro key
  void SetIntroKey(
      std::uint8_t* key);

  /// @return Pointer to intro key that was previously set when parsed
  std::uint8_t const* GetIntroKey() const;

  /// @brief Sets 4 byte nonce of Alice's relay request
  /// @note Assumes content is valid (based on position)
  /// @param nonce 4 byte nonce
  void SetNonce(
      std::uint32_t nonce);

  /// @return Nonce that was previously set when parsed
  std::uint32_t GetNonce() const;

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const;

 private:
  std::uint32_t m_RelayTag, m_Nonce;
  std::size_t m_IPAddressSize, m_ChallengeSize;
  std::uint8_t* m_IPAddress, *m_Challenge, *m_IntroKey;
  std::uint16_t m_Port;
};

/// @class SSURelayResponsePacket
/// @brief Payload type 4: RelayResponse
/// @details This is the response to a RelayRequest and is sent from Bob to Alice
class SSURelayResponsePacket : public SSUPacket {
 public:
  /// @brief Sets Charlie's 1 byte IP address and byte size representation
  ///   of Charlie's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Charlie's IP address
  /// @param size Charlie's IP address size
  void SetIPAddressCharlie(
      std::uint8_t* address,
      std::size_t size);

  /// @return Pointer to Charlie's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddressCharlie() const;

  /// @brief Sets Charlies's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Charlie's port number
  void SetPortCharlie(
      std::uint16_t port);

  /// @return Charlie's IP port that was previously set when parsed
  std::uint16_t GetPortCharlie() const;

  /// @brief Sets Alice's 1 byte IP address and byte size representation
  ///   of Alice's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Alice's IP address
  /// @param size Alice's IP address size
  void SetIPAddressAlice(
      std::uint8_t* address,
      std::size_t size);

  /// @return Pointer to Alice's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddressAlice() const;

  /// @return Alice's IP address size that was previously set when parsed
  std::size_t GetIPAddressAliceSize() const;

  /// @brief Sets Alices's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPortAlice(
      std::uint16_t port);

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPortAlice() const;

  /// @brief Sets 4 byte nonce sent by Alice
  /// @param nonce 4 byte nonce
  void SetNonce(
      std::uint32_t nonce);

  /// @return Nonce that was previously set when parsed
  std::uint32_t GetNonce() const;

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const;

 private:
  std::size_t m_IPAddressAliceSize, m_IPAddressCharlieSize;
  std::uint32_t m_Nonce;
  std::uint8_t* m_IPAddressAlice, *m_IPAddressCharlie;
  std::uint16_t m_PortAlice, m_PortCharlie;
};

/// @class SSURelayIntroPacket
/// @brief Payload type 5: RelayIntro
/// @details This is the introduction for Alice, which is sent from Bob to Charlie
class SSURelayIntroPacket : public SSUPacket {
 public:
  /// @brief Sets Alice's 1 byte IP address and byte size representation
  ///   of Alice's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Pointer to Alice's IP address
  /// @param size Alice's IP address size
  void SetIPAddress(
      std::uint8_t* address,
      std::size_t size);

  /// @return Pointer to Alice's IP address that was previously set when parsed
  std::uint8_t const* GetIPAddress() const;

  /// @return Alice's IP address size that was previously set when parsed
  std::size_t GetIPAddressSize() const;

  /// @brief Sets Alice's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPort(
      std::uint16_t port);

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPort() const;

  /// @brief Sets 1 byte challenge size and that many bytes to be relayed
  ///   from Alice
  /// @note Assumes content is valid (based on position)
  /// @param challenge Pointer to challenge size
  /// @param size Size of challenge size
  void SetChallenge(
      std::uint8_t* challenge,
      std::size_t size);

  /// @return Pointer to challenge that was previously set when parsed
  std::uint8_t const* GetChallenge() const;

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const;

 private:
  std::size_t m_IPAddressSize, m_ChallengeSize;
  std::uint8_t* m_IPAddress, *m_Challenge;
  std::uint16_t m_Port;
};

/// @class SSUFragment
/// @brief Constitutes all SSU fragments
/// @note Used exclusively for payload type 6: Data
class SSUFragment {
 public:
  /// @brief Sets 4 byte message ID
  /// @note Assumes content is valid (based on position)
  /// @param message_id 4 byte message ID
  void SetMessageID(
      std::uint32_t message_id);

  /// @brief Sets fragment size (0 - 16383)
  /// @param size Fragment size
  void SetSize(
      std::size_t size);

  /// @return Fragment size that was set when parsed
  std::size_t GetSize() const;

  /// @brief Sets 'is last' bit
  /// @param bool True if last, false if not
  void SetIsLast(
      bool is_last);

  /// @brief Sets fragment number (0 - 127)
  /// @param number Fragment number
  void SetNumber(
      std::uint8_t number);

  /// @brief Sets whole fragment data
  /// @param Pointer to fragment size
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
/// @details This message is used for data transport and acknowledgment
class SSUDataPacket : public SSUPacket {
 public:
  /// @brief Add explicit acks if they are included
  /// @param message_id The message ID being fully ACK'd
  void AddExplicitACK(
      std::uint32_t message_id);

  /// @brief Add ACK if included (not including bitfield)
  /// @param message_id The message ID being fully ACK'd
  void AddACK(
      std::uint32_t message_id);

  /// @brief Add ACK bitfield if ACK is included
  /// @note Called after ACK is included
  /// @param bitfield ACK bitfield
  void AddACKBitfield(
      std::uint8_t bitfield);

  /// @brief Add fragment for parsing
  /// @param fragment Fragment to be parsed
  void AddFragment(
      SSUFragment fragment);

  /// @return The size (in bytes) of this header + message
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
/// @details Implements packet for collaborative reachability testing for peers
class SSUPeerTestPacket : public SSUPacket {
 public:
  /// @brief Sets 4 byte nonce
  /// @note Assumes content is valid (based on position)
  /// @param nonce 4 byte nonce
  void SetNonce(
      std::uint32_t nonce);

  /// @return Nonce that was previously set when parsed
  std::uint32_t GetNonce() const;

  // TODO(unassigned): implement SetIPAddress() like others (see spec)?
  /// @brief Sets Alice's 1 byte IP address and byte size representation
  ///   of Alice's IP address
  /// @note Assumes content is valid (based on position)
  /// @param address Alice's IP address
  void SetIPAddress(
      std::uint32_t address);

  // TODO(unassigned): implement GetIPAddress() like others (see spec)?
  /// @return Alice's IP address that was previously set when parsed
  std::uint32_t GetIPAddress() const;

  /// @brief Sets Alice's 2 byte port number
  /// @note Assumes content is valid (based on position)
  /// @param port Alice's port number
  void SetPort(
      std::uint16_t port);

  /// @return Alice's IP port that was previously set when parsed
  std::uint16_t GetPort() const;

  /// @brief Alice's or Charlie's 32-byte introduction key
  /// @note Assumes content is valid (based on position)
  /// @param key Pointer to intro key
  void SetIntroKey(
      std::uint8_t* key);

  /// @return Pointer to intro key that was previously set when parsed
  std::uint8_t const* GetIntroKey() const;

  /// @return The size (in bytes) of this header + message
  std::size_t GetSize() const;

 private:
  std::uint32_t m_Nonce, m_IPAddress;
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
class SSUPacketParser {
 public:
  SSUPacketParser() = default;

  /// @brief Constructs packet parser from message/packet
  /// @param data Pointer to message/packet
  /// @param len Length of message/packet
  SSUPacketParser(
      std::uint8_t* data,
      std::size_t len);

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

  /// @brief Parses data fragment
  /// @return A parsed data fragment
  SSUFragment ParseFragment();

 private:
  std::uint8_t* m_Data;
  std::size_t m_Length;
};

/// @namespace SSUPacketBuilder
/// @brief Packet building implementation
namespace SSUPacketBuilder {

/// @brief Writes data into buffer
/// @note Increments buffer pointer position after writing data
/// @param pos Reference to pointer to buffer position
/// @param data Pointer to data to write
/// @param len Length of data
void WriteData(
    std::uint8_t*& pos,
    const std::uint8_t* data,
    std::size_t len);

/// @brief Writes an 8-bit unsigned integer type into buffer
/// @note Increments buffer pointer position after writing data
/// @param pos Reference to pointer to buffer position
/// @param data Data to write
void WriteUInt8(
    std::uint8_t*& pos,
    std::uint8_t data);

/// @brief Writes a 16-bit unsigned integer type into buffer
/// @note Converts bytes from host to big-endian order
/// @note Increments buffer pointer position after writing data
/// @param pos Reference to pointer to buffer position
/// @param data Data to write
void WriteUInt16(
    std::uint8_t*& pos,
    std::uint16_t data);

/// @brief Writes a 32-bit unsigned integer type into buffer
/// @note Converts bytes from host to big-endian order
/// @note Increments buffer pointer position after writing data
/// @param pos Reference to pointer to buffer position
/// @param data Data to write
void WriteUInt32(
    std::uint8_t*& pos,
    std::uint32_t data);

/// @brief Calculates padding size needed for message
/// @details All messages contain 0 or more bytes of padding.
///   Each message must be padded to a 16 byte boundary,
///   as required by the AES256 encryption layer
/// @param size Size of message
std::size_t GetPaddingSize(
    std::size_t size);

/// @brief Gets padded size of message
/// @param size Size of message
std::size_t GetPaddedSize(
    std::size_t size);

/// @brief Writes an SSU header into a data buffer.
/// @pre The data buffer must be sufficiently large.
/// @param data Reference to pointer to data
/// @param header Pointer to SSU header
void WriteHeader(
    std::uint8_t*& data,
    SSUHeader* header);

/// @brief Writes SessionRequest message
/// @param buf Reference to pointer to buffer to write into
/// @param packet SessionRequest packet to write
void WriteSessionRequest(
    std::uint8_t*& buf,
    SSUSessionRequestPacket* packet);

/// @brief Writes SessionCreated message
/// @param buf Reference to pointer to buffer to write into
/// @param packet SessionCreated packet to write
void WriteSessionCreated(
    std::uint8_t*& buf,
    SSUSessionCreatedPacket* packet);

/// @brief Writes SessionConfirmed message
/// @param buf Reference to pointer to buffer to write into
/// @param packet SessionConfirmed packet to write
void WriteSessionConfirmed(
    std::uint8_t*& buf,
    SSUSessionConfirmedPacket* packet);

/// @brief Writes RelayRequest message
/// @param buf Reference to pointer to buffer to write into
/// @param packet RelayRequest packet to write
void WriteRelayRequest(
    std::uint8_t*& buf,
    SSURelayRequestPacket* packet);

/// @brief Writes RelayResponse message
/// @param buf Reference to pointer to buffer to write into
/// @param packet RelayResponse packet to write
void WriteRelayResponse(
    std::uint8_t*& buf,
    SSURelayResponsePacket* packet);

/// @brief Writes RelayIntro message
/// @param buf Reference to pointer to buffer to write into
/// @param packet RelayIntro packet to write
void WriteRelayIntro(
    std::uint8_t*& buf,
    SSURelayIntroPacket* packet);

/// @brief Writes Data message
/// @param buf Reference to pointer to buffer to write into
/// @param packet Data packet to write
void WriteData(
    std::uint8_t*& buf,
    SSUDataPacket* packet);

/// @brief Writes PeerTest message
/// @param buf Reference to pointer to buffer to write into
/// @param packet PeerTest packet to write
void WritePeerTest(
    std::uint8_t*& buf,
    SSUPeerTestPacket* packet);

/// @brief Writes SessionDestroyed message
/// @param buf Reference to pointer to buffer to write into
/// @param packet SessionDestroyed packet to write
void WriteSessionDestroyed(
    std::uint8_t*& buf,
    SSUSessionDestroyedPacket* packet);

/// @brief Writes SSU packet for SSU session
/// @param buf Reference to pointer to buffer to write into
/// @param packet SSU packet to write
/// @note packet is one of any payload types
void WritePacket(
    std::uint8_t*& buf,
    SSUPacket* packet);
}  // namespace SSUPacketBuilder

}  // namespace transport
}  // namespace i2p

#endif  // SRC_CORE_TRANSPORT_SSUPACKET_H_
