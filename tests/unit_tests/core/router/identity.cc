/**
 * Copyright (c) 2015-2017, The Kovri I2P Router Project
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

#include "core/crypto/signature.h"
#include "core/router/identity.h"
#include "core/util/log.h"
#include "tests/unit_tests/core/router/identity.h"

namespace core = kovri::core;

BOOST_FIXTURE_TEST_SUITE(IdentityExTests, IdentityExFixture)

BOOST_AUTO_TEST_CASE(ParseIdentity)
{
  // Parse
  core::IdentityEx identity;
  BOOST_CHECK(
      identity.FromBuffer(m_AliceIdentity.data(), m_AliceIdentity.size()));
  // Check that FromBuffer + ToBuffer == original buffer
  // TODO(anonimal): review the following arbitrary size (must be >= 387)
  std::array<std::uint8_t, 1024> output{{}};
  auto len = identity.ToBuffer(output.data(), output.size());
  BOOST_CHECK_EQUAL_COLLECTIONS(
      output.data(),
      output.data() + len,
      m_AliceIdentity.data(),
      m_AliceIdentity.data() + m_AliceIdentity.size());
  // Check key types
  BOOST_CHECK_EQUAL(
      identity.GetSigningKeyType(),
      core::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);
  BOOST_CHECK_EQUAL(identity.GetCryptoKeyType(), core::CRYPTO_KEY_TYPE_ELGAMAL);
  // Check sig lengths
  BOOST_CHECK_EQUAL(
      identity.GetSigningPublicKeyLen(), core::EDDSA25519_PUBLIC_KEY_LENGTH);
  BOOST_CHECK_EQUAL(
      identity.GetSigningPrivateKeyLen(), core::EDDSA25519_PRIVATE_KEY_LENGTH);
  BOOST_CHECK_EQUAL(
      identity.GetSignatureLen(), core::EDDSA25519_SIGNATURE_LENGTH);
}

BOOST_AUTO_TEST_CASE(ParseIdentityFailure)
{
  // Change for invalid length
  core::IdentityEx identity;
  for (std::size_t i(1);
       i <= m_AliceIdentity.size() - core::DEFAULT_IDENTITY_SIZE;
       i++)
    BOOST_CHECK_EQUAL(
        identity.FromBuffer(m_AliceIdentity.data(), m_AliceIdentity.size() - i),
        0);
}

BOOST_AUTO_TEST_SUITE_END()
