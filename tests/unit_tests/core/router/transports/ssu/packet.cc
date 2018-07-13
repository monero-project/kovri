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

#include "tests/unit_tests/main.h"

#include <array>
#include <memory>

#include "core/router/transports/ssu/packet.h"
#include "tests/unit_tests/core/router/identity.h"

/**
 *
 * Global fixtures
 *
 */

struct SSUTestVectorsFixture : public IdentityExFixture
{
  SSUTestVectorsFixture()
  {
    // Build session_confirmed : starts with header
    std::memcpy(
        session_confirmed.data(), header_plain.data(), header_plain.size());
    // Set header flag to payload SessionConfirmed
    session_confirmed[32] = std::uint8_t(
        core::SSUPayloadType::SessionConfirmed << 4);
    core::OutputByteStream output(
        session_confirmed.data() + header_plain.size(),
        session_confirmed.size() - header_plain.size());
    // 1 byte info
    output.Write<std::uint8_t>(0x01);
    // 2 byte identity size (0x01, 0x87)
    output.Write<std::uint16_t>(raw_ident.size());
    // Append identity
    output.WriteData(raw_ident.data(), raw_ident.size());
    // Signed on time (0x57, 0x69, 0x04, 0xAA)
    output.Write<std::uint32_t>(m_SignedOnTime);
    // Padding to reach multiple of 16 bytes
    // 13 = 16 - (37(header_plain) + 1 + 2 + (387+4) + 4(time) + 64(sig len)) % 16)
    output.SkipBytes(13);
    // Signature (non-realistic example)
    // 64 bytes (EDDSA_SHA512_ED25519)
    for(std::uint8_t i(0); i< 64; i++)
      output.Write<std::uint8_t>(i);
  }

  // Signed on time (0x57, 0x69, 0x04, 0xAA)
  const std::uint32_t m_SignedOnTime = 1466500266;

  std::array<std::uint8_t, 37> header_plain {{
    // 16 byte MAC (not an actual one)
    0x0a, 0xb0, 0x00, 0x00, 0x00, 0x00, 0xd0, 0xe0,
    0x0a, 0xb0, 0x00, 0x00, 0x00, 0x00, 0xd0, 0xe0,
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
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    0xa0, 0x0b, 0xc0, 0x0d, 0xe0, 0x0f, 0xaa, 0xbb,
    // 1 byte IP address size
    0x04,
    // 4 bytes IP address
    0x0A, 0x0B, 0x0C, 0x0D
  }};

  std::array<std::uint8_t, 311> session_created {{
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
    0x04,
    // 4 bytes IP address
    0x0A, 0x0B, 0x0C, 0x0D,
    // Port (9000)
    0x23, 0x28,
    // Relay tag (1234567890) 
    0x49, 0x96, 0x02, 0xD2,
    // m_SignedOnTime (1466500266)
    0x57, 0x69, 0x04, 0xAA,
    // Signature (non-realistic example)
    // 40 bytes (DSA)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  }};

  // Initialized in constructor
  // 512 = 37(header) + 1(info) + 2(size) + (387 + 4)(identity) + 4(time)
  //     + 13(padding) + 64(sig len)
  std::array<std::uint8_t, 512> session_confirmed;

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

  std::array<std::uint8_t, 43> peer_test_v4 {{
    // 4 byte nonce
    0x01, 0x01, 0x01, 0x01,
    // 1 byte address size (4)
    0x04,
    // 4 byte address
    0x0A, 0x0B, 0x0C, 0x0D,
    // 2 byte port (9000)
    0x23, 0x28,
    // 32 bytes introduction key
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  }};

  std::array<std::uint8_t, 55> peer_test_v6 {{
    // 4 byte nonce
    0x01, 0x01, 0x01, 0x01,
    // 1 byte address size (6)
    0x10,
    // 16 byte address
    0x0A, 0x0B, 0x0C, 0x0D, 0x1A, 0x1B, 0x1C, 0x1D,
    0x2A, 0x2B, 0x2C, 0x2D, 0x3A, 0x3B, 0x3C, 0x3D,
    // 2 byte port (9000)
    0x23, 0x28,
    // 32 bytes introduction key
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  }};

  std::array<std::uint8_t, 39> peer_test_alice {{
    // 4 byte nonce
    0x01, 0x01, 0x01, 0x01,
    // 1 byte address size (empty)
    0x00,
    // 2 byte port (0)
    0x00, 0x00,
    // 32 bytes introduction key
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

BOOST_AUTO_TEST_CASE(PayloadType) {
  using namespace kovri::core;
  SSUHeader header;
  header.set_payload_type(0);
  BOOST_CHECK(header.get_payload_type() == SSUPayloadType::SessionRequest);
  header.set_payload_type(1);
  BOOST_CHECK(header.get_payload_type() == SSUPayloadType::SessionCreated);
  header.set_payload_type(2);
  BOOST_CHECK(header.get_payload_type() == SSUPayloadType::SessionConfirmed);
  header.set_payload_type(3);
  BOOST_CHECK(header.get_payload_type() == SSUPayloadType::RelayRequest);
  header.set_payload_type(4);
  BOOST_CHECK(header.get_payload_type() == SSUPayloadType::RelayResponse);
  header.set_payload_type(5);
  BOOST_CHECK(header.get_payload_type() == SSUPayloadType::RelayIntro);
  header.set_payload_type(6);
  BOOST_CHECK(header.get_payload_type() == SSUPayloadType::Data);
  header.set_payload_type(7);
  BOOST_CHECK(header.get_payload_type() == SSUPayloadType::PeerTest);
  header.set_payload_type(8);
  BOOST_CHECK(header.get_payload_type() == SSUPayloadType::SessionDestroyed);
}

BOOST_AUTO_TEST_CASE(InvalidPayloadType) {
  kovri::core::SSUHeader header;
  BOOST_CHECK_THROW(header.set_payload_type(9);, std::invalid_argument);
  BOOST_CHECK_THROW(header.set_payload_type(-1);, std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()

/**
 *
 * Packet parsing tests
 *
 */

BOOST_FIXTURE_TEST_SUITE(SSUPacketParserTests, SSUTestVectorsFixture)

BOOST_AUTO_TEST_CASE(SSUHeaderPlain) {
  using namespace kovri::core;
  SSUPacketParser parser(header_plain.data(), header_plain.size());
  std::unique_ptr<SSUHeader> header;
  BOOST_CHECK_NO_THROW(header = parser.ParseHeader());
  BOOST_CHECK(!header->has_rekey());
  BOOST_CHECK(!header->has_ext_opts());
  BOOST_CHECK_EQUAL(header->get_time(), 0xAABBCCDD);
  BOOST_CHECK(header->get_payload_type()== SSUPayloadType::SessionRequest);
  BOOST_CHECK_EQUAL(header->get_size(), header_plain.size());
}

BOOST_AUTO_TEST_CASE(SSUHeaderExtendedOptions) {
  using namespace kovri::core;
  SSUPacketParser parser(header_extended_options.data(), header_extended_options.size());
  std::unique_ptr<SSUHeader> header;
  BOOST_CHECK_NO_THROW(header = parser.ParseHeader());
  BOOST_CHECK(!header->has_rekey());
  BOOST_CHECK(header->has_ext_opts());
  BOOST_CHECK_EQUAL(header->get_time(), 0xAABBCCDD);
  BOOST_CHECK(header->get_payload_type() == SSUPayloadType::SessionRequest);
  BOOST_CHECK_EQUAL(header->get_size(), header_extended_options.size());
}

BOOST_AUTO_TEST_CASE(SessionRequestPlain) {
  using namespace kovri::core;
  SSUPacketParser parser(session_request.data(), session_request.size());
  std::unique_ptr<SSUSessionRequestPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseSessionRequest());
  BOOST_CHECK_EQUAL(packet->get_size(), session_request.size());
}

BOOST_AUTO_TEST_CASE(SessionCreatedPlain) {
  using namespace kovri::core;
  SSUPacketParser parser(session_created.data(), session_created.size());
  std::unique_ptr<SSUSessionCreatedPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseSessionCreated());
  BOOST_CHECK_EQUAL(packet->get_ip_size(), 4);
  BOOST_CHECK_EQUAL(*packet->get_ip(), 0x0A);
  BOOST_CHECK_EQUAL(packet->get_port(), 9000);
  BOOST_CHECK_EQUAL(packet->get_relay_tag(), 1234567890);
  BOOST_CHECK_EQUAL(packet->get_time(), m_SignedOnTime);
  BOOST_CHECK_EQUAL(*packet->get_sig(), 0x00);
  BOOST_CHECK_EQUAL(packet->get_size(), session_created.size());
}

BOOST_AUTO_TEST_CASE(SessionConfirmedPlain)
{
  // Construct IdentityEx
  core::IdentityEx identity;
  BOOST_CHECK(
      identity.FromBuffer(raw_ident.data(), raw_ident.size()));
  std::unique_ptr<core::SSUSessionConfirmedPacket> packet;
  // Parse
  core::SSUPacketParser parser(session_confirmed.data(), session_confirmed.size());
  BOOST_CHECK_NO_THROW(
      packet.reset(
          static_cast<core::SSUSessionConfirmedPacket*>(
              parser.ParsePacket().release())));
  // Check size
  BOOST_CHECK_EQUAL(
      packet->get_size(), session_confirmed.size());
  // Check SignedOnTime
  BOOST_CHECK_EQUAL(packet->get_time(), m_SignedOnTime);
  // Check identity
  BOOST_CHECK_EQUAL(
      packet->get_remote_ident().GetStandardIdentity().Hash(),
      identity.GetStandardIdentity().Hash());
  // Check Signature
  const auto sig_len = identity.GetSignatureLen();
  const std::size_t sig_position(session_confirmed.size() - sig_len);
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->get_sig(),
      packet->get_sig() + sig_len,
      &session_confirmed.at(sig_position),
      &session_confirmed.at(sig_position) + sig_len);
}

BOOST_AUTO_TEST_CASE(RelayRequestPlain) {
  using namespace kovri::core;
  SSUPacketParser parser(relay_request.data(), relay_request.size());
  std::unique_ptr<SSURelayRequestPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseRelayRequest());
  BOOST_CHECK_EQUAL(packet->get_relay_tag(), 0x01020304);
  const std::array<std::uint8_t, 4> expected_address {{ 0x0A, 0x0B, 0x0C, 0x0D }};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->get_ip(),
      packet->get_ip() + expected_address.size(),
      expected_address.data(),
      expected_address.data() + expected_address.size());
  BOOST_CHECK_EQUAL(packet->get_port(), 9000);
  BOOST_CHECK_EQUAL(*packet->get_challenge(), 0);
  BOOST_CHECK_EQUAL(*packet->get_intro_key(), 0);
  BOOST_CHECK_EQUAL(packet->get_nonce(), 0x01010101);
  BOOST_CHECK_EQUAL(packet->get_size(), relay_request.size());
}

BOOST_AUTO_TEST_CASE(RelayResponsePlain) {
  using namespace kovri::core;
  SSUPacketParser parser(relay_response.data(), relay_response.size());
  std::unique_ptr<SSURelayResponsePacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseRelayResponse());
  const std::array<std::uint8_t, 4> expected_address {{ 0x0A, 0x0B, 0x0C, 0x0D }};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->get_charlie_ip(),
      packet->get_charlie_ip() + expected_address.size(),
      expected_address.data(),
      expected_address.data() + expected_address.size());
  BOOST_CHECK_EQUAL(packet->get_charlie_port(), 9000);
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->get_alice_ip(),
      packet->get_alice_ip() + expected_address.size(),
      expected_address.data(),
      expected_address.data() + expected_address.size());
  BOOST_CHECK_EQUAL(packet->get_alice_port(), 9000);
  BOOST_CHECK_EQUAL(packet->get_nonce(), 0x01010101);
  BOOST_CHECK_EQUAL(packet->get_size(), relay_response.size());
}

BOOST_AUTO_TEST_CASE(RelayIntroPlain) {
  using namespace kovri::core;
  SSUPacketParser parser(relay_intro.data(), relay_intro.size());
  std::unique_ptr<SSURelayIntroPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseRelayIntro());
  const std::array<std::uint8_t, 4> expected_address {{ 0x0A, 0x0B, 0x0C, 0x0D }};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      packet->get_ip(),
      packet->get_ip() + expected_address.size(),
      expected_address.data(),
      expected_address.data() + expected_address.size());
  BOOST_CHECK_EQUAL(packet->get_port(), 9000);
  BOOST_CHECK_EQUAL(*packet->get_challenge(), 0);
  BOOST_CHECK_EQUAL(packet->get_size(), relay_intro.size());
}

BOOST_AUTO_TEST_CASE(DataOneFragmentPlain) {
  using namespace kovri::core;
  SSUPacketParser parser(data_single_fragment.data(), data_single_fragment.size());
  std::unique_ptr<SSUDataPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseData());
  BOOST_CHECK_EQUAL(packet->get_size(), data_single_fragment.size());
}

BOOST_AUTO_TEST_CASE(DataMultFragmentsPlain) {
  using namespace kovri::core;
  SSUPacketParser parser(data_multi_fragment.data(), data_multi_fragment.size());
  std::unique_ptr<SSUDataPacket> packet;
  BOOST_CHECK_NO_THROW(packet = parser.ParseData());
  BOOST_CHECK_EQUAL(packet->get_size(), data_multi_fragment.size());
}

BOOST_AUTO_TEST_CASE(PeerTestV4) {
  using namespace kovri::core;
  // Check IPv4 (non-Alice)
  std::unique_ptr<SSUPeerTestPacket> packet;
  SSUPacketParser parser(peer_test_v4.data(), peer_test_v4.size());
  BOOST_CHECK_NO_THROW(packet = parser.ParsePeerTest());
  BOOST_CHECK_EQUAL(packet->get_size(), peer_test_v4.size());
}

BOOST_AUTO_TEST_CASE(PeerTestV6) {
  using namespace kovri::core;
  // Check IPv6 (non-Alice)
  std::unique_ptr<SSUPeerTestPacket> packet;
  SSUPacketParser parser(peer_test_v6.data(), peer_test_v6.size());
  BOOST_CHECK_NO_THROW(packet = parser.ParsePeerTest());
  BOOST_CHECK_EQUAL(packet->get_size(), peer_test_v6.size());
}

BOOST_AUTO_TEST_CASE(PeerTestAlice) {
  using namespace kovri::core;
  // Check Alice (empty address)
  std::unique_ptr<SSUPeerTestPacket> packet;
  SSUPacketParser parser(peer_test_alice.data(), peer_test_alice.size());
  BOOST_CHECK_NO_THROW(packet = parser.ParsePeerTest());
  BOOST_CHECK_EQUAL(packet->get_size(), peer_test_alice.size());
}

BOOST_AUTO_TEST_SUITE_END()

/**
 *
 * Packet building tests
 *
 */

BOOST_FIXTURE_TEST_SUITE(SSUPacketBuilderTests, SSUTestVectorsFixture)

BOOST_AUTO_TEST_CASE(SSUHeaderPlain) {
  using namespace kovri::core;

  SSUHeader header(
      SSUPayloadType::SessionRequest,
      &header_plain.at(0),
      &header_plain.at(16),
      2864434397);
  auto buffer = std::make_unique<std::uint8_t[]>(header.get_size());
  SSUPacketBuilder builder(buffer.get(), header.get_size());
  builder.WriteHeader(&header);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + header.get_size(),
    header_plain.data(),
    header_plain.data() + header_plain.size());

}

BOOST_AUTO_TEST_CASE(SSUHeaderExtendedOptions) {
  using namespace kovri::core;

  SSUHeader header(
      SSUPayloadType::SessionRequest,
      &header_extended_options.at(0),
      &header_extended_options.at(16),
      2864434397);
  std::array<std::uint8_t, 3> extended_data {{ 0x11, 0x12, 0x13 }};
  header.set_ext_opts_data(extended_data.data(), extended_data.size());
  header.set_ext_opts(true);
  auto buffer = std::make_unique<std::uint8_t[]>(header.get_size());
  SSUPacketBuilder builder(buffer.get(), header.get_size());
  builder.WriteHeader(&header);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + header.get_size(),
    header_extended_options.data(),
    header_extended_options.data() + header_extended_options.size());
}

BOOST_AUTO_TEST_CASE(SessionRequestPlain) {
  using namespace kovri::core;

  SSUSessionRequestPacket packet;
  packet.set_dh_x(&session_request.at(0));
  packet.set_ip(&session_request.at(257), 4);
  auto buffer = std::make_unique<std::uint8_t[]>(packet.get_size());
  SSUPacketBuilder builder(buffer.get(), packet.get_size());
  builder.WriteSessionRequest(&packet);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + packet.get_size(),
    session_request.data(),
    session_request.data() + session_request.size());
}

BOOST_AUTO_TEST_CASE(SessionCreatedPacket) {
  using namespace kovri::core;

  SSUSessionCreatedPacket packet;
  packet.set_dh_y(&session_created.at(0));
  packet.set_ip(&session_created.at(257), 4);
  packet.set_port(9000);
  packet.set_relay_tag(1234567890);
  packet.set_time(m_SignedOnTime);
  packet.set_sig(&session_created.at(271), 40);
  auto buffer = std::make_unique<std::uint8_t[]>(packet.get_size());
  SSUPacketBuilder builder(buffer.get(), packet.get_size());
  builder.WriteSessionCreated(&packet);
  BOOST_CHECK_EQUAL_COLLECTIONS(
    buffer.get(),
    buffer.get() + packet.get_size(),
    session_created.data(),
    session_created.data() + session_created.size());
}

BOOST_AUTO_TEST_CASE(SessionConfirmedPlain)
{
  // Construct IdentityEx
  core::IdentityEx identity;
  BOOST_CHECK(
      identity.FromBuffer(raw_ident.data(), raw_ident.size()));
  // Build initial packet : need header
  core::SSUPacketParser parser(header_plain.data(), header_plain.size());
  std::unique_ptr<core::SSUHeader> header;
  BOOST_CHECK_NO_THROW(header = parser.ParseHeader());
  header->set_payload_type(core::SSUPayloadType::SessionConfirmed);
  // Packet + attributes
  core::SSUSessionConfirmedPacket packet;
  packet.set_header(std::move(header));
  packet.set_remote_ident(identity);
  packet.set_time(m_SignedOnTime);
  const std::size_t sig_position =
      session_confirmed.size() - identity.GetSignatureLen();
  packet.set_sig(&session_confirmed.at(sig_position));
  // Output to buffer
  auto buffer = std::make_unique<std::uint8_t[]>(packet.get_size());
  core::SSUPacketBuilder builder(buffer.get(), packet.get_size());
  builder.WriteHeader(packet.get_header());
  builder.WritePacket(&packet);
  // Padding is randomized, so check everything before and after
  const std::size_t padding_position = header_plain.size() + 1  // Info
                                       + 2  // Identity size
                                       + raw_ident.size()  // Identity
                                       + 4;  // SignedOnTime size
  BOOST_CHECK_EQUAL_COLLECTIONS(
      buffer.get(),
      buffer.get() + padding_position,
      session_confirmed.data(),
      session_confirmed.data() + padding_position);
  BOOST_CHECK_EQUAL_COLLECTIONS(
      buffer.get() + sig_position,
      buffer.get() + packet.get_size(),
      session_confirmed.data() + sig_position,
      session_confirmed.data() + session_confirmed.size());
}

BOOST_AUTO_TEST_SUITE_END()
