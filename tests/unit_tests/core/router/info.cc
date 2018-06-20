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

#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include "core/router/identity.h"

namespace core = kovri::core;

struct RouterInfoFixture
{
  core::PrivateKeys keys = core::PrivateKeys::CreateRandomKeys(
      core::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
};

BOOST_FIXTURE_TEST_SUITE(RouterInfoTests, RouterInfoFixture)

BOOST_AUTO_TEST_CASE(CreateValidRouters)
{
  // Ensure EdDSA router w/ IPv4 transport is created
  //   Other signing types not tested, see #498
  BOOST_CHECK_NO_THROW(
      core::RouterInfo router(keys, {{"127.0.0.1", 10701}}, {true, true}));

  // Ensure EdDSA router w/ IPv6 transport is created
  BOOST_CHECK_NO_THROW(
      core::RouterInfo router(keys, {{"::1", 10702}}, {true, true}));

  // Ensure NTCP-only router is created
  BOOST_CHECK_NO_THROW(
      core::RouterInfo router(keys, {{"127.0.0.1", 10701}}, {true, false}));

  // Ensure SSU-only router is created
  BOOST_CHECK_NO_THROW(
      core::RouterInfo router(keys, {{"127.0.0.1", 10701}}, {false, true}));
}

BOOST_AUTO_TEST_CASE(CreateInvalidRouters)
{
  // Ensure router with no transports throws
  BOOST_CHECK_THROW(
      core::RouterInfo router(keys, {}, {}), std::invalid_argument);

  // Ensure router with NTCP & SSU disabled throws
  BOOST_CHECK_THROW(
      core::RouterInfo router(keys, {{"127.0.0.1", 10701}}, {false, false}),
      std::invalid_argument);

  // Ensure invalid IPv4 throws
  BOOST_CHECK_THROW(
      core::RouterInfo router(keys, {{"9127.0.0.1", 10801}}, {}),
      std::invalid_argument);

  // Ensure invalid IPv6 throws
  BOOST_CHECK_THROW(
      core::RouterInfo router(keys, {{"/:::0", 10801}}, {}),
      std::invalid_argument);

  // Ensure invalid port throws
  BOOST_CHECK_THROW(
      core::RouterInfo router(keys, {{"127.0.0.1", 42}}, {}),
      std::invalid_argument);

  // Create RSA signing keys
  keys = core::PrivateKeys::CreateRandomKeys(
      core::SIGNING_KEY_TYPE_RSA_SHA512_4096);

  // Ensure RSA_SHA512_4096 signing key throws
  //   Other signing types not tested, see #498
  BOOST_CHECK_THROW(
      core::RouterInfo router_rsa(keys, {{"127.0.0.1", 10801}}, {}),
      std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()
