/**                                                                                           //
 * Copyright (c) 2015-2018, The Kovri I2P Router Project                                      //
 *                                                                                            //
 * All rights reserved.                                                                       //
 *                                                                                            //
 * Redistribution and use in source and binary forms, with or without modification, are       //
 * permitted provided that the following conditions are met:                                  //
 *                                                                                            //
 * 1. Redistributions of source code must retain the above copyright notice, this list of     //
 *    conditions and the following disclaimer.                                                //
 *                                                                                            //
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list     //
 *    of conditions and the following disclaimer in the documentation and/or other            //
 *    materials provided with the distribution.                                               //
 *                                                                                            //
 * 3. Neither the name of the copyright holder nor the names of its contributors may be       //
 *    used to endorse or promote products derived from this software without specific         //
 *    prior written permission.                                                               //
 *                                                                                            //
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY        //
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF    //
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL     //
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,       //
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,               //
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    //
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,          //
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF    //
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.               //
 */

#include <boost/test/unit_test.hpp>

#include "client/util/parse.h"

#include <set>

#include "core/crypto/rand.h"
#include "core/router/identity.h"
#include "core/util/log.h"

namespace core = kovri::core;
namespace client = kovri::client;

struct ParseACLFixture
{
  ParseACLFixture()
  {
    // Create hash set
    for (std::uint8_t i(0); i < 3; i++)
      {
        core::IdentHash hash;
        // Note: not a "real" (key-generated) ident hash
        core::RandBytes(hash(), sizeof(hash));
        idents.insert(hash);
      }
  }

  ~ParseACLFixture()
  {
    BOOST_TEST_MESSAGE(acl);
    BOOST_REQUIRE_NO_THROW(client::ParseACL(acl));
    BOOST_CHECK(client::ParseACL(acl) == idents);
  }

  std::set<core::IdentHash> idents;
  std::string acl;
};

BOOST_FIXTURE_TEST_SUITE(ParseACL, ParseACLFixture)

BOOST_AUTO_TEST_CASE(Base32)
{
  for (const auto& ident : idents)
    acl += ident.ToBase32() + ",";
}

BOOST_AUTO_TEST_CASE(Base32Domain)
{
  for (const auto& ident : idents)
    acl += ident.ToBase32() + ".b32.i2p,";
}

BOOST_AUTO_TEST_CASE(Base64)
{
  for (const auto& ident : idents)
    acl += ident.ToBase64() + ",";
}

BOOST_AUTO_TEST_CASE(MixedRadix)
{
  std::size_t count(0);

  for (const auto& ident : idents)
    {
      if (!count)
        acl += ident.ToBase32() + ",";
      acl += ident.ToBase64() + ",";
      count++;
    }
}

BOOST_AUTO_TEST_CASE(InvalidList)
{
  std::uint8_t count(0);

  // Construct malformed ACL
  // TODO(unassigned): extend test for malformed ACLs?
  for (const auto& ident : idents)
    {
      acl += ident.ToBase32();
      if (count != (idents.size() - 1))
        acl += ",,,,";
      count++;
    }
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(ClientParsing)

struct TunnelFixture {
  kovri::client::TunnelAttributes tunnel{};
};

// Test for correct delimiter parsing against plain configuration
BOOST_AUTO_TEST_CASE(ParseClientDestination) {
  // Create plain destination
  auto plain = std::make_unique<TunnelFixture>();

  plain->tunnel.dest = "anonimal.i2p";
  plain->tunnel.dest_port = 80;

  kovri::client::ParseClientDestination(&plain->tunnel);

  // Create delimited destination
  auto delimited = std::make_unique<TunnelFixture>();

  delimited->tunnel.dest = "anonimal.i2p:80";
  delimited->tunnel.dest_port = 12345;

  kovri::client::ParseClientDestination(&delimited->tunnel);

  // Both destinations should be equal after being parsed
  BOOST_CHECK_EQUAL(delimited->tunnel.dest, plain->tunnel.dest);
  BOOST_CHECK_EQUAL(delimited->tunnel.dest_port, plain->tunnel.dest_port);
}

// Test for bad port length
BOOST_AUTO_TEST_CASE(CatchBadClientDestination) {
  // Create bad destination
  auto bad = std::make_unique<TunnelFixture>();

  bad->tunnel.dest = "anonimal.i2p:111111111";
  bad->tunnel.dest_port = 80;

  BOOST_REQUIRE_THROW(
      kovri::client::ParseClientDestination(&bad->tunnel),
      std::exception);

  // TODO(unassigned): expand test-case (see TODO in function definition)
}

BOOST_AUTO_TEST_SUITE_END()
