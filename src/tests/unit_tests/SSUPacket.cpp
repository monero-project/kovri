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


BOOST_AUTO_TEST_SUITE_END()

struct SSUTestVectorsFixture {

  uint8_t sessionRequest[297] = {
    // Header
    // 16 byte MAC (not an actual one)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 16 byte IV
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    // 1 byte flag
    0x00,
    // 4 bytes time
    0xAA, 0xBB, 0xCC, 0xDD,
    // Data
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
    // 1 byte IP address size
    0x03,
    // 3 bytes IP address
    0x0A, 0x0B, 0x0C
  };

  uint8_t sessionRequestExtendedOptions[42] = {
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
    // TODO(EinMByte): add data
  };

  uint8_t sessionCreated[297] = {
    // Header
    // 16 byte MAC (not an actual one)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // 16 byte IV
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    // 1 byte flag
    0x10,
    // 4 bytes time
    0xAA, 0xBB, 0xCC, 0xDD,
    // Data
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
    // 1 byte IP address size
    0x03,
    // 3 bytes IP address
    0x0A, 0x0B, 0x0C,
    // Signature (0x00 as a non-realistic example)
    0x00
  };

};

BOOST_FIXTURE_TEST_SUITE(SSUPacketParserTests, SSUTestVectorsFixture)

BOOST_AUTO_TEST_CASE(SSUHeaderPlain) {
  i2p::transport::SSUPacketParser parser(
    sessionRequest, sizeof(sessionRequest)
  );
  std::unique_ptr<i2p::transport::SSUHeader> header;
  BOOST_CHECK_NO_THROW(
     header = parser.ParseHeader();
  );
  BOOST_CHECK(!header->HasRekey());
  BOOST_CHECK(!header->HasExtendedOptions());
  BOOST_CHECK_EQUAL(header->GetTime(), 0xAABBCCDD);
  BOOST_CHECK(
    header->GetPayloadType() ==
      i2p::transport::SSUHeader::PayloadType::SessionRequest
  );
}

BOOST_AUTO_TEST_CASE(SSUHeaderExtendedOptions) {
  i2p::transport::SSUPacketParser parser(
    sessionRequestExtendedOptions, sizeof(sessionRequestExtendedOptions)
  );
  std::unique_ptr<i2p::transport::SSUHeader> header;
  BOOST_CHECK_NO_THROW(
     header = parser.ParseHeader();
  );
  BOOST_CHECK(!header->HasRekey());
  BOOST_CHECK(header->HasExtendedOptions());
  BOOST_CHECK_EQUAL(header->GetTime(), 0xAABBCCDD);
  BOOST_CHECK(
    header->GetPayloadType() ==
      i2p::transport::SSUHeader::PayloadType::SessionRequest
  );
}

BOOST_AUTO_TEST_CASE(SessionRequestPlain) {
  i2p::transport::SSUPacketParser parser(
    sessionRequest, sizeof(sessionRequest)
  );
  std::unique_ptr<i2p::transport::SSUSessionRequestPacket> packet;
  BOOST_CHECK_NO_THROW(
    packet = parser.ParseSessionRequest();
  );
}

BOOST_AUTO_TEST_CASE(SessionCreatedPlain) {
  i2p::transport::SSUPacketParser parser(
    sessionCreated, sizeof(sessionCreated)
  );
  std::unique_ptr<i2p::transport::SSUSessionCreatedPacket> packet;
  BOOST_CHECK_NO_THROW(
    packet = parser.ParseSessionCreated();
  );
}

BOOST_AUTO_TEST_SUITE_END()
