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

BOOST_AUTO_TEST_CASE(ValidSignature)
{
  // Ensure EdDSA router is created & signature verification succeeds
  BOOST_CHECK_NO_THROW(core::RouterInfo r(keys, {{"127.0.0.1", 10701}}, {}));
}

BOOST_AUTO_TEST_CASE(InvalidSignature)
{
  core::RouterInfo router;

  // Ensure default constructed router fails verification
  BOOST_CHECK_THROW(router.Verify(), std::exception);

  // Create router buffer without setting default options
  BOOST_CHECK_THROW(router.CreateBuffer(keys), std::exception);
}

BOOST_AUTO_TEST_SUITE_END()
