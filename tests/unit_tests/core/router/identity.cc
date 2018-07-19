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

#include <boost/date_time/gregorian/gregorian_types.hpp>

#include <array>
#include <memory>
#include <regex>

#include "core/crypto/signature.h"
#include "core/router/identity.h"
#include "core/util/log.h"
#include "tests/unit_tests/core/router/identity.h"

BOOST_FIXTURE_TEST_SUITE(IdentityExTests, IdentityExFixture)

BOOST_AUTO_TEST_CASE(ParseIdentity)
{
  // Verify integrity of buffer conversion
  std::array<std::uint8_t, core::DEFAULT_IDENTITY_SIZE + 4> output{{}};
  auto const len = ident.ToBuffer(output.data(), output.size());
  BOOST_CHECK_EQUAL_COLLECTIONS(
      output.data(),
      output.data() + len,
      raw_ident.data(),
      raw_ident.data() + raw_ident.size());

  // Check key types
  BOOST_CHECK_EQUAL(
      ident.GetSigningKeyType(),
      core::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);

  BOOST_CHECK_EQUAL(ident.GetCryptoKeyType(), core::CRYPTO_KEY_TYPE_ELGAMAL);

  // Check lengths
  BOOST_CHECK_EQUAL(ident.GetSigningPublicKeyLen(), crypto::PkLen::Ed25519);

  BOOST_CHECK_EQUAL(
      ident.GetSigningPrivateKeyLen(),
      crypto::SkLen::Ed25519 - 32 /* An I2P'ism */);

  BOOST_CHECK_EQUAL(ident.GetSignatureLen(), crypto::SigLen::Ed25519);
}

BOOST_AUTO_TEST_CASE(ParseIdentityFailure)
{
  // Change for invalid length
  core::IdentityEx identity;
  for (std::size_t i(1);
       i <= raw_ident.size() - core::DEFAULT_IDENTITY_SIZE;
       i++)
    BOOST_CHECK_EQUAL(
        identity.FromBuffer(raw_ident.data(), raw_ident.size() - i),
        0);
}

BOOST_AUTO_TEST_CASE(ValidRoutingKey)
{
  BOOST_CHECK_NO_THROW(core::CreateRoutingKey(ident.GetIdentHash()));
}

BOOST_AUTO_TEST_CASE(InvalidRoutingKey)
{
  kovri::core::IdentHash hash;
  BOOST_CHECK_THROW(core::CreateRoutingKey(hash), std::invalid_argument);
  BOOST_CHECK_THROW(core::CreateRoutingKey(nullptr), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(ValidDateFormat)
{
  std::regex regex("(20\\d{2})(\\d{2})(\\d{2})");  // Valid for only this century
  BOOST_CHECK(std::regex_search(core::GetFormattedDate(), regex));
}

BOOST_AUTO_TEST_CASE(Base32Conversion)
{
  BOOST_CHECK_NO_THROW(ident.FromBase32(ident.ToBase32()));
}

BOOST_AUTO_TEST_CASE(Base64Conversion)
{
  BOOST_CHECK_NO_THROW(ident.FromBase64(ident.ToBase64()));
}

BOOST_AUTO_TEST_SUITE_END()
