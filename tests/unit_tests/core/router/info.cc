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

#include "core/router/identity.h"
#include "core/router/info.h"

struct RouterInfoFixture : public core::RouterInfoTraits
{
  core::PrivateKeys keys = core::PrivateKeys::CreateRandomKeys(
      core::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
};

BOOST_FIXTURE_TEST_SUITE(RouterInfoTests, RouterInfoFixture)

BOOST_AUTO_TEST_CASE(ValidSignature)
{
  BOOST_CHECK_NO_THROW(core::RouterInfo r(keys, {{"127.0.0.1", 10701}}, {}));
}

BOOST_AUTO_TEST_CASE(InvalidSignature)
{
  // If RI is not built completely, insufficient data will throw
  core::RouterInfo router;
  BOOST_CHECK_THROW(router.Verify(), std::exception);
  BOOST_CHECK_THROW(router.CreateBuffer(keys), std::exception);
}

BOOST_AUTO_TEST_CASE(IPv4)
{
  core::RouterInfo ri(keys, {{"127.0.0.1", 12345}}, {true, true});

  // Yes ipv4
  BOOST_CHECK_EQUAL(ri.HasNTCP(), true);
  BOOST_CHECK_EQUAL(ri.HasSSU(), true);

  // No ipv6
  // TODO(unassigned): logic would dictate that we only allow true for ipv6 capable
  //   but our current implementation doesn't allow this (these should return false)
  BOOST_CHECK_EQUAL(ri.HasNTCP(true), true);
  BOOST_CHECK_EQUAL(ri.HasSSU(true), true);
  //
  BOOST_CHECK_EQUAL(ri.HasV6(), false);
}

BOOST_AUTO_TEST_CASE(IPv6)
{
  core::RouterInfo ri(keys, {{"::1", 12345}}, {true, true});

  // No ipv4
  BOOST_CHECK_EQUAL(ri.HasNTCP(), false);
  BOOST_CHECK_EQUAL(ri.HasSSU(), false);

  // Yes ipv6
  BOOST_CHECK_EQUAL(ri.HasNTCP(true), true);
  BOOST_CHECK_EQUAL(ri.HasSSU(true), true);
  BOOST_CHECK_EQUAL(ri.HasV6(), true);
}

BOOST_AUTO_TEST_CASE(GetAddress)
{
  core::RouterInfo ri(
      keys, {{"127.0.0.1", 54321}, {"::1", 12345}}, {true, true});

  // Yes ipv4
  BOOST_CHECK(ri.GetV4Address(Transport::NTCP) != nullptr);
  BOOST_CHECK(ri.GetV4Address(Transport::SSU) != nullptr);

  // Yes ipv6
  BOOST_CHECK(ri.GetV6Address(Transport::NTCP) != nullptr);
  BOOST_CHECK(ri.GetV6Address(Transport::SSU) != nullptr);
}

BOOST_AUTO_TEST_CASE(GetAddressIPv4only)
{
  core::RouterInfo ri(keys, {{"127.0.0.1", 54321}}, {true, true});

  // Yes ipv4
  BOOST_CHECK(ri.GetV4Address(Transport::NTCP) != nullptr);
  BOOST_CHECK(ri.GetV4Address(Transport::SSU) != nullptr);

  BOOST_CHECK(ri.GetAddress(false, Transport::NTCP) != nullptr);
  BOOST_CHECK(ri.GetAddress(false, Transport::SSU) != nullptr);

  BOOST_CHECK(ri.GetAnyAddress(false, Transport::NTCP) != nullptr);
  BOOST_CHECK(ri.GetAnyAddress(false, Transport::SSU) != nullptr);

  // No ipv6
  BOOST_CHECK(ri.GetV6Address(Transport::NTCP) == nullptr);
  BOOST_CHECK(ri.GetV6Address(Transport::SSU) == nullptr);

  BOOST_CHECK(ri.GetAddress(true, Transport::NTCP) == nullptr);
  BOOST_CHECK(ri.GetAddress(true, Transport::SSU) == nullptr);

  BOOST_CHECK(ri.GetAnyAddress(true, Transport::NTCP) != nullptr);
  BOOST_CHECK(ri.GetAnyAddress(true, Transport::SSU) != nullptr);

  BOOST_CHECK_EQUAL(ri.GetAnyAddress(true, Transport::NTCP)->host.is_v6(), false);
  BOOST_CHECK_EQUAL(ri.GetAnyAddress(true, Transport::SSU)->host.is_v6(), false);
}

BOOST_AUTO_TEST_CASE(GetAddressIPv6only)
{
  core::RouterInfo ri(keys, {{"::1", 54321}}, {true, true});

  // No ipv4
  BOOST_CHECK(ri.GetV4Address(Transport::NTCP) == nullptr);
  BOOST_CHECK(ri.GetV4Address(Transport::SSU) == nullptr);

  BOOST_CHECK(ri.GetAddress(false, Transport::NTCP) == nullptr);
  BOOST_CHECK(ri.GetAddress(false, Transport::SSU) == nullptr);

  BOOST_CHECK(ri.GetAnyAddress(false, Transport::NTCP) == nullptr);
  BOOST_CHECK(ri.GetAnyAddress(false, Transport::SSU) == nullptr);

  // Yes ipv6
  BOOST_CHECK(ri.GetV6Address(Transport::NTCP) != nullptr);
  BOOST_CHECK(ri.GetV6Address(Transport::SSU) != nullptr);

  BOOST_CHECK(ri.GetAddress(true, Transport::NTCP) != nullptr);
  BOOST_CHECK(ri.GetAddress(true, Transport::SSU) != nullptr);

  BOOST_CHECK(ri.GetAnyAddress(true, Transport::NTCP) != nullptr);
  BOOST_CHECK(ri.GetAnyAddress(true, Transport::SSU) != nullptr);

  BOOST_CHECK_EQUAL(ri.GetAnyAddress(true, Transport::NTCP)->host.is_v6(), true);
  BOOST_CHECK_EQUAL(ri.GetAnyAddress(true, Transport::SSU)->host.is_v6(), true);
}

// TODO(unassigned): expand test cases

BOOST_AUTO_TEST_SUITE_END()
