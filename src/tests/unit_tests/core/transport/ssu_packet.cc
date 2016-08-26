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

#include <array>
#include <memory>

#include "transport/ssu_packet.h"

/**
 *
 * Global fixtures
 *
 */

struct SSUTestVectorsFixture {

  std::array<std::uint8_t, 37> header_plain {{
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
  }};

  std::array<std::uint8_t, 41> header_extended_options {{
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
  }};

  std::array<std::uint8_t, 261> session_request {{
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
  }};

  std::array<std::uint8_t, 310> session_created {{
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
  }};

  std::array<std::uint8_t, 64> session_confirmed {{
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
  }};

  std::array<std::uint8_t, 52> relay_request {{
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
  }};

  std::array<std::uint8_t, 18> relay_response {{
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
  }};

  std::array<std::uint8_t, 12> relay_intro {{
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
  }};

  std::array<std::uint8_t, 61> data_single_fragment {{
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
  }};

  std::array<std::uint8_t, 80> data_multi_fragment {{
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
  }};
};

/**
 *
 * Header tests
 *
 */

BOOST_AUTO_TEST_SUITE(SSUHeaderTests)

BOOST_AUTO_TEST_CASE(GetPayloadType) {
  using namespace i2p::transport;
  SSUHeader header;
  header.SetPayloadType(0);
  BOOST_CHECK(header.GetPayloadType() == SSUPayloadType::SessionRequest);
  header.SetPayloadType(1);
  BOOST_CHECK(header.GetPayloadType() == SSUPayloadType::SessionCreated);
  header.SetPayloadType(2);
  BOOST_CHECK(header.GetPayloadType() == SSUPayloadType::SessionConfirmed);
  header.SetPayloadType(3);
  BOOST_CHECK(header.GetPayloadType() == SSUPayloadType::RelayRequest);
  header.SetPayloadType(4);
  BOOST_CHECK(header.GetPayloadType() == SSUPayloadType::RelayResponse);
  header.SetPayloadType(5);
  BOOST_CHECK(header.GetPayloadType() == SSUPayloadType::RelayIntro);
  header.SetPayloadType(6);
  BOOST_CHECK(header.GetPayloadType() == SSUPayloadType::Data);
  header.SetPayloadType(7);
  BOOST_CHECK(header.GetPayloadType() == SSUPayloadType::PeerTest);
  header.SetPayloadType(8);
  BOOST_CHECK(header.GetPayloadType() == SSUPayloadType::SessionDestroyed);
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
  using namespace i2p::transport;
  SSUPacketParser parser(header_plain.data(), header_plain.size());
  std::unique_ptr<SSUHeader> header;
  BOOST_CHECK_NO_THROW(header = parser.ParseHeader());
  BOOST_CHECK(!header->HasRekey());
  BOOST_CHECK(!header->HasExtendedOptions());
  BOOST_CHECK_EQUAL(header->GetTime(), 0xAABBCCDD);
  BOOST_CHECK(header->GetPayloadType()== SSUPayloadType::SessionRequest);
  BOOST_CHECK_EQUAL(header->GetSize(), header_plain.size());
}

BOOST_AUTO_TEST_CASE(SSUHeaderExtendedOptions) {
  using namespace i2p::transport;
  SSUPacketParser parser(header_extended_options.data(), header_extended_options.size());
  std::unique_ptr<SSUHeader> header;
  BOOST_CHECK_NO_THROW(header = parser.ParseHeader());
  BOOST_CHECK(!header->HasRekey());
  BOOST_CHECK(header->HasExtendedOptions());
  BOOST_CHECK_EQUAL(header->GetTime(), 0xAABBCCDD);
  BOOST_CHECK(header->GetPayloadType() == SSUPayloadType::SessionRequest);
  BOOST_CHECK_EQUAL(header->GetSize(), header_extended_options.size());
}

BOOST_AUTO_TEST_CASE(SessionRequestPlain) {
  using namespace i2p::transport;
  SSUPacketParser parser(session_request.data(), session_request.size());
  std::unique_ptr<SSUSessionRequestPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseSessionRequest());
  BOOST_CHECK_EQUAL(packet->GetSize(), session_request.size());
}

BOOST_AUTO_TEST_CASE(SessionCreatedPlain) {
  using namespace i2p::transport;
  SSUPacketParser parser(session_created.data(), session_created.size());
  std::unique_ptr<SSUSessionCreatedPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseSessionCreated());
  BOOST_CHECK_EQUAL(packet->GetIPAddressSize(), 3);
  BOOST_CHECK_EQUAL(*packet->GetIPAddress(), 0x0A);
  BOOST_CHECK_EQUAL(packet->GetPort(), 9000);
  BOOST_CHECK_EQUAL(packet->GetRelayTag(), 1234567890);
  BOOST_CHECK_EQUAL(packet->GetSignedOnTime(), 1466500266);
  BOOST_CHECK_EQUAL(*packet->GetSignature(), 0x00);
  BOOST_CHECK_EQUAL(packet->GetSize(), session_created.size());
}

BOOST_AUTO_TEST_CASE(RelayRequestPlain) {
  using namespace i2p::transport;
  SSUPacketParser parser(relay_request.data(), relay_request.size());
  std::unique_ptr<SSURelayRequestPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseRelayRequest());
  BOOST_CHECK_EQUAL(packet->GetRelayTag(), 0x01020304);
  const std::array<std::uint8_t, 4> expected_address {{ 0x0A, 0x0B, 0x0C, 0x0D }};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->GetIPAddress(),
      packet->GetIPAddress() + expected_address.size(),
      expected_address.data(),
      expected_address.data() + expected_address.size());
  BOOST_CHECK_EQUAL(packet->GetPort(), 9000);
  BOOST_CHECK_EQUAL(*packet->GetChallenge(), 0);
  BOOST_CHECK_EQUAL(*packet->GetIntroKey(), 0);
  BOOST_CHECK_EQUAL(packet->GetNonce(), 0x01010101);
  BOOST_CHECK_EQUAL(packet->GetSize(), relay_request.size());
}

BOOST_AUTO_TEST_CASE(RelayResponsePlain) {
  using namespace i2p::transport;
  SSUPacketParser parser(relay_response.data(), relay_response.size());
  std::unique_ptr<SSURelayResponsePacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseRelayResponse());
  const std::array<std::uint8_t, 4> expected_address {{ 0x0A, 0x0B, 0x0C, 0x0D }};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->GetIPAddressCharlie(),
      packet->GetIPAddressCharlie() + expected_address.size(),
      expected_address.data(),
      expected_address.data() + expected_address.size());
  BOOST_CHECK_EQUAL(packet->GetPortCharlie(), 9000);
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->GetIPAddressAlice(),
      packet->GetIPAddressAlice() + expected_address.size(),
      expected_address.data(),
      expected_address.data() + expected_address.size());
  BOOST_CHECK_EQUAL(packet->GetPortAlice(), 9000);
  BOOST_CHECK_EQUAL(packet->GetNonce(), 0x01010101);
  BOOST_CHECK_EQUAL(packet->GetSize(), relay_response.size());
}

BOOST_AUTO_TEST_CASE(RelayIntroPlain) {
  using namespace i2p::transport;
  SSUPacketParser parser(relay_intro.data(), relay_intro.size());
  std::unique_ptr<SSURelayIntroPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseRelayIntro());
  const std::array<std::uint8_t, 4> expected_address {{ 0x0A, 0x0B, 0x0C, 0x0D }};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->GetIPAddress(),
      packet->GetIPAddress() + expected_address.size(),
      expected_address.data(),
      expected_address.data() + expected_address.size());
  BOOST_CHECK_EQUAL(packet->GetPort(), 9000);
  BOOST_CHECK_EQUAL(*packet->GetChallenge(), 0);
  BOOST_CHECK_EQUAL(packet->GetSize(), relay_intro.size());
}

BOOST_AUTO_TEST_CASE(DataOneFragmentPlain) {
  using namespace i2p::transport;
  SSUPacketParser parser(data_single_fragment.data(), data_single_fragment.size());
  std::unique_ptr<SSUDataPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseData());
  BOOST_CHECK_EQUAL(packet->GetSize(), data_single_fragment.size());
}

BOOST_AUTO_TEST_CASE(DataMultFragmentsPlain) {
  using namespace i2p::transport;
  SSUPacketParser parser(data_multi_fragment.data(), data_multi_fragment.size());
  std::unique_ptr<SSUDataPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseData());
  BOOST_CHECK_EQUAL(packet->GetSize(), data_multi_fragment.size());
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
      i2p::transport::SSUPayloadType::SessionRequest,
      &header_plain.at(0),
      &header_plain.at(16),
      2864434397);
  auto buffer = std::make_unique<std::uint8_t[]>(header.GetSize());
  std::uint8_t* buffer_ptr = buffer.get();
  WriteHeader(buffer_ptr, &header);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + header.GetSize(),
    header_plain.data(),
    header_plain.data() + header_plain.size());

}

BOOST_AUTO_TEST_CASE(SSUHeaderExtendedOptions) {
  i2p::transport::SSUHeader header(
      i2p::transport::SSUPayloadType::SessionRequest,
      &header_extended_options.at(0),
      &header_extended_options.at(16),
      2864434397);
  std::array<std::uint8_t, 3> extended_data {{ 0x11, 0x12, 0x13 }};
  header.SetExtendedOptionsData(extended_data.data(), extended_data.size());
  header.SetExtendedOptions(true);
  auto buffer = std::make_unique<std::uint8_t[]>(header.GetSize());
  std::uint8_t* buffer_ptr = buffer.get();
  WriteHeader(buffer_ptr, &header);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + header.GetSize(),
    header_extended_options.data(),
    header_extended_options.data() + header_extended_options.size());
}

BOOST_AUTO_TEST_CASE(SessionRequestPlain) {
  i2p::transport::SSUSessionRequestPacket packet;
  packet.SetDhX(&session_request.at(0));
  packet.SetIPAddress(&session_request.at(257), 4);
  auto buffer = std::make_unique<std::uint8_t[]>(packet.GetSize());
  std::uint8_t* buffer_ptr = buffer.get();
  WriteSessionRequest(buffer_ptr, &packet);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + packet.GetSize(),
    session_request.data(),
    session_request.data() + session_request.size());
}

BOOST_AUTO_TEST_CASE(SessionCreatedPlain) {
  i2p::transport::SSUSessionCreatedPacket packet;
  packet.SetDhY(&session_created.at(0));
  packet.SetIPAddress(&session_created.at(257), 3);
  packet.SetPort(9000);
  packet.SetRelayTag(1234567890);
  packet.SetSignedOnTime(1466500266);
  packet.SetSignature(&session_created.at(270), 40);
  auto buffer = std::make_unique<std::uint8_t[]>(packet.GetSize());
  std::uint8_t* buffer_ptr = buffer.get();
  WriteSessionCreated(buffer_ptr, &packet);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + packet.GetSize(),
    session_created.data(),
    session_created.data() + session_created.size());
}

BOOST_AUTO_TEST_SUITE_END()
