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

#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>
#include <memory>
#include "transport/SSUPacket.h"

/**
 *
 * Global fixtures
 *
 */

struct SSUTestVectorsFixture {

  std::uint8_t header_plain[37] = {
    // 16 byte MAC (not an actual one)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 16 byte IV
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    // 1 byte flag
    0x00,
    // 4 bytes time (2864434397)
    0xAA, 0xBB, 0xCC, 0xDD
  };

  std::uint8_t header_extended_options[41] = {
    // 16 byte MAC (not an actual one)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 16 byte IV
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    // 1 byte flag (has extended options)
    0x04,
    // Time
    0xAA, 0xBB, 0xCC, 0xDD,
    // Extended options size
    0x03,
    // Extended options data
    0x11, 0x12, 0x13
  };

  std::uint8_t session_request[261] = {
    // 256 bytes X (as in DH)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 1 byte IP address size
    0x04,
    // 4 bytes IP address
    0x0A, 0x0B, 0x0C, 0x0D
  };

  std::uint8_t session_created[310] = {
    // 256 bytes Y (as in DH)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 1 byte IP address size
    0x03,
    // 3 bytes IP address
    0x0A, 0x0B, 0x0C,
    // Port (9000)
    0x23, 0x28,
    // Relay tag (1234567890) 
    0x49, 0x96, 0x02, 0xD2,
    // Signed on time (1466500266)
    0x57, 0x69, 0x04, 0xAA,
    // Signature (non-realistic example)
    // 40 bytes (DSA)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  std::uint8_t session_confirmed[64] = {
    // TODO(EinMByte): Make this more realistic so it will parse
    // 1 byte info
    0x00,
    // 2 byte fragment size (8)
    0x08,
    // 8 byte fragment
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Signed on time (1466500266)
    0x57, 0x69, 0x04, 0xAA,
    // Padding to reach multiple of 16 bytes
    0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // Signature (non-realistic example)
    // 40 bytes (DSA)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  std::uint8_t relay_request[52] = {
    // 4 byte relay tag
    0x01, 0x02, 0x03, 0x04,
    // 1 byte address size
    0x04,
    // 4 byte IP address
    0x0A, 0x0B, 0x0C, 0x0D,
    // 2 byte port (9000)
    0x23, 0x28,
    // 1 byte challenge size
    0x04,
    // 4 byte challenge
    0x00, 0x00, 0x00, 0x00,
    // 32 byte intro key
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 4 byte nonce
    0x01, 0x01, 0x01, 0x01
  };

  std::uint8_t relay_response[18] = {
    // 1 byte address size (4)
    0x04,
    // 4 byte address
    0x0A, 0x0B, 0x0C, 0x0D,
    // 2 byte port (9000)
    0x23, 0x28,
    // 1 byte address size (4)
    0x04,
    // 4 byte address
    0x0A, 0x0B, 0x0C, 0x0D,
    // 2 byte port (9000)
    0x23, 0x28,
    // 4 byte nonce
    0x01, 0x01, 0x01, 0x01
  };

  std::uint8_t relay_intro[12] = {
    // 1 byte address size (4)
    0x04,
    // 4 byte address
    0x0A, 0x0B, 0x0C, 0x0D,
    // 2 byte port (9000)
    0x23, 0x28,
    // 1 byte challenge size (4)
    0x04,
    // 4 byte challenge
    0x00, 0x00, 0x00, 0x00
  };

  std::uint8_t data_single_fragment[61] = {
    // 1 byte flags (11000100)
    0xC4,
    // 1 byte number of ACKs (2)
    0x02,
    // 2 x 4 byte message ID being ACKed
    0x10, 0x20, 0x30, 0x40, //  270544960
    0x50, 0x60, 0x70, 0x80, // 1348497536
    // 1 byte number of ACK bitfields (2)
    0x02,
    // 2 x 4 byte message ID + 1 byte bitfield
    0x01, 0x02, 0x03, 0x04, //  16909060
    0x05, 0x06, 0x07, 0x08, //  84281096
    // 2 x 1 byte ACK bitfield (10100101 00000100)
    0xA5, 0x04,
    // 1 byte number of fragments (1)
    0x01,
    // 4 byte message ID
    0x0A, 0x0B, 0x0C, 0x0D,
    // 3 byte fragment info
    0x01,       // Fragment number and isLast = 1
    0x00, 0x20, // Fragment size 32
    // 32 bytes of fragment data
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  std::uint8_t data_multi_fragment[80] = {
    // 1 byte flags (00000100)
    0x04,
    // 1 byte number of fragments (2)
    0x02,
    // 4 byte message ID
    0x0A, 0x0B, 0x0C, 0x0D,
    // 3 byte fragment info
    0x01,       // Fragment number and isLast = 1
    0x00, 0x20, // Fragment size 32
    // 32 bytes of fragment data
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 4 byte message ID
    0x0A, 0x0B, 0x0C, 0x0D,
    // 3 byte fragment info
    0x01,       // Fragment number and isLast = 1
    0x00, 0x20, // Fragment size 32
    // 32 bytes of fragment data
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
};

/**
 *
 * Header tests
 *
 */

BOOST_AUTO_TEST_SUITE(SSUHeaderTests)

BOOST_AUTO_TEST_CASE(GetPayloadType) {
  using i2p::transport::SSUHeader;
  SSUHeader header;
  header.SetPayloadType(0);
  BOOST_CHECK(header.GetPayloadType() == SSUHeader::PayloadType::SessionRequest);
  header.SetPayloadType(1);
  BOOST_CHECK(header.GetPayloadType() == SSUHeader::PayloadType::SessionCreated);
  header.SetPayloadType(2);
  BOOST_CHECK(header.GetPayloadType() == SSUHeader::PayloadType::SessionConfirmed);
  header.SetPayloadType(3);
  BOOST_CHECK(header.GetPayloadType() == SSUHeader::PayloadType::RelayRequest);
  header.SetPayloadType(4);
  BOOST_CHECK(header.GetPayloadType() == SSUHeader::PayloadType::RelayResponse);
  header.SetPayloadType(5);
  BOOST_CHECK(header.GetPayloadType() == SSUHeader::PayloadType::RelayIntro);
  header.SetPayloadType(6);
  BOOST_CHECK(header.GetPayloadType() == SSUHeader::PayloadType::Data);
  header.SetPayloadType(7);
  BOOST_CHECK(header.GetPayloadType() == SSUHeader::PayloadType::PeerTest);
  header.SetPayloadType(8);
  BOOST_CHECK(header.GetPayloadType() == SSUHeader::PayloadType::SessionDestroyed);
}

BOOST_AUTO_TEST_CASE(SetPayloadTypeInvalid) {
  i2p::transport::SSUHeader header;
  BOOST_CHECK_THROW(header.SetPayloadType(9);, std::invalid_argument);
  BOOST_CHECK_THROW(header.SetPayloadType(-1);, std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

/**
 *
 * Packet parsing tests
 *
 */

BOOST_FIXTURE_TEST_SUITE(SSUPacketParserTests, SSUTestVectorsFixture)

BOOST_AUTO_TEST_CASE(SSUHeaderPlain) {
  i2p::transport::SSUPacketParser parser(header_plain, sizeof(header_plain));
  std::unique_ptr<i2p::transport::SSUHeader> header;
  BOOST_CHECK_NO_THROW(header = parser.ParseHeader());
  BOOST_CHECK(!header->HasRekey());
  BOOST_CHECK(!header->HasExtendedOptions());
  BOOST_CHECK_EQUAL(header->GetTime(), 0xAABBCCDD);
  BOOST_CHECK(
    header->GetPayloadType() ==
      i2p::transport::SSUHeader::PayloadType::SessionRequest);
  BOOST_CHECK_EQUAL(header->GetSize(), sizeof(header_plain));
}

BOOST_AUTO_TEST_CASE(SSUHeaderExtendedOptions) {
  i2p::transport::SSUPacketParser parser(header_extended_options, sizeof(header_extended_options));
  std::unique_ptr<i2p::transport::SSUHeader> header;
  BOOST_CHECK_NO_THROW(header = parser.ParseHeader());
  BOOST_CHECK(!header->HasRekey());
  BOOST_CHECK(header->HasExtendedOptions());
  BOOST_CHECK_EQUAL(header->GetTime(), 0xAABBCCDD);
  BOOST_CHECK(
    header->GetPayloadType() ==
      i2p::transport::SSUHeader::PayloadType::SessionRequest);
  BOOST_CHECK_EQUAL(header->GetSize(), sizeof(header_extended_options));
}

BOOST_AUTO_TEST_CASE(SessionRequestPlain) {
  i2p::transport::SSUPacketParser parser(session_request, sizeof(session_request));
  std::unique_ptr<i2p::transport::SSUSessionRequestPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseSessionRequest());
  BOOST_CHECK_EQUAL(packet->GetSize(), sizeof(session_request));
}

BOOST_AUTO_TEST_CASE(SessionCreatedPlain) {
  i2p::transport::SSUPacketParser parser(session_created, sizeof(session_created));
  std::unique_ptr<i2p::transport::SSUSessionCreatedPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseSessionCreated());
  BOOST_CHECK_EQUAL(packet->GetIPAddressSize(), 3);
  BOOST_CHECK_EQUAL(*packet->GetIPAddress(), 0x0A);
  BOOST_CHECK_EQUAL(packet->GetPort(), 9000);
  BOOST_CHECK_EQUAL(packet->GetRelayTag(), 1234567890);
  BOOST_CHECK_EQUAL(packet->GetSignedOnTime(), 1466500266);
  BOOST_CHECK_EQUAL(*packet->GetSignature(), 0x00);
  BOOST_CHECK_EQUAL(packet->GetSize(), sizeof(session_created));
}

BOOST_AUTO_TEST_CASE(RelayRequestPlain) {
  i2p::transport::SSUPacketParser parser(relay_request, sizeof(relay_request));
  std::unique_ptr<i2p::transport::SSURelayRequestPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseRelayRequest());
  BOOST_CHECK_EQUAL(packet->GetRelayTag(), 0x01020304);
  const std::uint8_t expected_address[4] = {0x0A, 0x0B, 0x0C, 0x0D};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->GetIPAddress(),
      packet->GetIPAddress() + sizeof(expected_address),
      expected_address,
      expected_address + sizeof(expected_address));
  BOOST_CHECK_EQUAL(packet->GetPort(), 9000);
  BOOST_CHECK_EQUAL(*packet->GetChallenge(), 0);
  BOOST_CHECK_EQUAL(*packet->GetIntroKey(), 0);
  BOOST_CHECK_EQUAL(packet->GetNonce(), 0x01010101);
  BOOST_CHECK_EQUAL(packet->GetSize(), sizeof(relay_request));
}

BOOST_AUTO_TEST_CASE(RelayResponsePlain) {
  i2p::transport::SSUPacketParser parser(relay_response, sizeof(relay_response));
  std::unique_ptr<i2p::transport::SSURelayResponsePacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseRelayResponse());
  const std::uint8_t expected_address[4] = {0x0A, 0x0B, 0x0C, 0x0D};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->GetIPAddressCharlie(),
      packet->GetIPAddressCharlie() + sizeof(expected_address),
      expected_address,
      expected_address + sizeof(expected_address));
  BOOST_CHECK_EQUAL(packet->GetPortCharlie(), 9000);
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->GetIPAddressAlice(),
      packet->GetIPAddressAlice() + sizeof(expected_address),
      expected_address,
      expected_address + sizeof(expected_address));
  BOOST_CHECK_EQUAL(packet->GetPortAlice(), 9000);
  BOOST_CHECK_EQUAL(packet->GetNonce(), 0x01010101);
  BOOST_CHECK_EQUAL(packet->GetSize(), sizeof(relay_response));
}

BOOST_AUTO_TEST_CASE(RelayIntroPlain) {
  i2p::transport::SSUPacketParser parser(relay_intro, sizeof(relay_intro));
  std::unique_ptr<i2p::transport::SSURelayIntroPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseRelayIntro());
  const std::uint8_t expected_address[4] = {0x0A, 0x0B, 0x0C, 0x0D};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->GetIPAddress(),
      packet->GetIPAddress() + sizeof(expected_address),
      expected_address,
      expected_address + sizeof(expected_address));
  BOOST_CHECK_EQUAL(packet->GetPort(), 9000);
  BOOST_CHECK_EQUAL(*packet->GetChallenge(), 0);
  BOOST_CHECK_EQUAL(packet->GetSize(), sizeof(relay_intro));
}

BOOST_AUTO_TEST_CASE(DataOneFragmentPlain) {
  i2p::transport::SSUPacketParser parser(data_single_fragment, sizeof(data_single_fragment));
  std::unique_ptr<i2p::transport::SSUDataPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseData());
  BOOST_CHECK_EQUAL(packet->GetSize(), sizeof(data_single_fragment));
}

BOOST_AUTO_TEST_CASE(DataMultFragmentsPlain) {
  i2p::transport::SSUPacketParser parser(data_multi_fragment, sizeof(data_multi_fragment));
  std::unique_ptr<i2p::transport::SSUDataPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseData());
  BOOST_CHECK_EQUAL(packet->GetSize(), sizeof(data_multi_fragment));
}

BOOST_AUTO_TEST_SUITE_END()

/**
 *
 * Packet building tests
 *
 */

BOOST_FIXTURE_TEST_SUITE(SSUPacketBuilderTests, SSUTestVectorsFixture)

using namespace i2p::transport::SSUPacketBuilder;

BOOST_AUTO_TEST_CASE(SSUHeaderPlain) {
  i2p::transport::SSUHeader header(
      i2p::transport::SSUHeader::PayloadType::SessionRequest,
      &header_plain[0],
      &header_plain[16],
      2864434397);
  std::unique_ptr<std::uint8_t> buffer(new std::uint8_t[header.GetSize()]);
  std::uint8_t* buffer_ptr = buffer.get();
  WriteHeader(buffer_ptr, &header);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + header.GetSize(),
    header_plain,
    header_plain + sizeof(header_plain));
}

BOOST_AUTO_TEST_CASE(SSUHeaderExtendedOptions) {
  i2p::transport::SSUHeader header(
      i2p::transport::SSUHeader::PayloadType::SessionRequest,
      &header_extended_options[0],
      &header_extended_options[16],
      2864434397);
  std::uint8_t extended_data[3] = {0x11, 0x12, 0x13};
  header.SetExtendedOptionsData(extended_data, sizeof(extended_data));
  header.SetExtendedOptions(true);
  std::unique_ptr<std::uint8_t> buffer(new std::uint8_t[header.GetSize()]);
  std::uint8_t* buffer_ptr = buffer.get();
  WriteHeader(buffer_ptr, &header);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + header.GetSize(),
    header_extended_options,
    header_extended_options + sizeof(header_extended_options));
}

BOOST_AUTO_TEST_CASE(SessionRequestPlain) {
  i2p::transport::SSUSessionRequestPacket packet;
  packet.SetDhX(&session_request[0]);
  packet.SetIPAddress(&session_request[257], 4);
  std::unique_ptr<std::uint8_t> buffer(new std::uint8_t[packet.GetSize()]);
  std::uint8_t* buffer_ptr = buffer.get();
  WriteSessionRequest(buffer_ptr, &packet);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + packet.GetSize(),
    session_request,
    session_request + sizeof(session_request));
}

BOOST_AUTO_TEST_CASE(SessionCreatedPlain) {
  i2p::transport::SSUSessionCreatedPacket packet;
  packet.SetDhY(&session_created[0]);
  packet.SetIPAddress(&session_created[257], 3);
  packet.SetPort(9000);
  packet.SetRelayTag(1234567890);
  packet.SetSignedOnTime(1466500266);
  packet.SetSignature(&session_created[270], 40);
  std::unique_ptr<std::uint8_t> buffer(new std::uint8_t[packet.GetSize()]);
  std::uint8_t* buffer_ptr = buffer.get();
  WriteSessionCreated(buffer_ptr, &packet);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + packet.GetSize(),
    session_created,
    session_created + sizeof(session_created));
}
BOOST_AUTO_TEST_SUITE_END()
