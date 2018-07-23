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

#include "tests/unit_tests/main.h"

#include "core/crypto/signature.h"

BOOST_AUTO_TEST_SUITE(Ed25519Tests)

struct Ed25519Fixture
{
  Ed25519Fixture() : verifier(pk.data()), signer(sk.data()) {}

  /// @brief Public key from keypair
  static constexpr std::array<std::uint8_t, crypto::PkLen::Ed25519> pk{
      {0x0f, 0x90, 0x8b, 0xaf, 0xef, 0x40, 0x79, 0xb5, 0x94, 0xb5, 0x13,
       0xf9, 0xf6, 0x02, 0x65, 0xef, 0x4d, 0x95, 0xa4, 0x84, 0x2d, 0xc7,
       0x23, 0x1b, 0x93, 0xe4, 0x2e, 0x9d, 0x45, 0x52, 0xed, 0x62}};

  /// @brief Private key from keypair
  static constexpr std::array<std::uint8_t, crypto::SkLen::Ed25519> sk{
      {0xe1, 0xec, 0xff, 0xa6, 0xcd, 0x4e, 0xc7, 0x09, 0x2f, 0x87, 0x44,
       0xaf, 0x48, 0xb3, 0x7f, 0x63, 0x71, 0x63, 0x1e, 0x01, 0xf7, 0x20,
       0xe9, 0x0a, 0xfa, 0x3c, 0x90, 0xec, 0x97, 0x4c, 0x16, 0x27, 0x0f,
       0x90, 0x8b, 0xaf, 0xef, 0x40, 0x79, 0xb5, 0x94, 0xb5, 0x13, 0xf9,
       0xf6, 0x02, 0x65, 0xef, 0x4d, 0x95, 0xa4, 0x84, 0x2d, 0xc7, 0x23,
       0x1b, 0x93, 0xe4, 0x2e, 0x9d, 0x45, 0x52, 0xed, 0x62}};

  /// @brief Signature
  static constexpr std::array<std::uint8_t, crypto::SigLen::Ed25519> sig{
      {0x1f, 0x58, 0x29, 0xef, 0xf4, 0x1e, 0x05, 0xb5, 0x36, 0x6b, 0x01,
       0xc3, 0xdb, 0x55, 0xfe, 0x77, 0x80, 0xf5, 0x1d, 0xee, 0xb6, 0x78,
       0xa6, 0x2e, 0xb7, 0xc4, 0xc4, 0x2c, 0xb9, 0x9b, 0x60, 0x2d, 0x68,
       0xfd, 0xf6, 0x08, 0xf6, 0xd4, 0x64, 0x3d, 0x70, 0xef, 0x3e, 0xd9,
       0x11, 0x68, 0xcb, 0x0c, 0x5c, 0xa9, 0xff, 0x45, 0x7d, 0x43, 0x5e,
       0xf5, 0xc7, 0x5d, 0xfa, 0x5d, 0xd0, 0x12, 0xac, 0x0c}};

  /// @brief Message
  /// @details "From anonimal, with love <3"
  static constexpr std::array<std::uint8_t, 27> m{
      {0x46, 0x72, 0x6f, 0x6d, 0x20, 0x61, 0x6e, 0x6f, 0x6e,
       0x69, 0x6d, 0x61, 0x6c, 0x2c, 0x20, 0x77, 0x69, 0x74,
       0x68, 0x20, 0x6c, 0x6f, 0x76, 0x65, 0x20, 0x3c, 0x33}};

  core::Ed25519Verifier verifier;
  core::Ed25519Signer signer;
};

constexpr std::array<std::uint8_t, crypto::PkLen::Ed25519> Ed25519Fixture::pk;
constexpr std::array<std::uint8_t, crypto::SkLen::Ed25519> Ed25519Fixture::sk;
constexpr std::array<std::uint8_t, crypto::SigLen::Ed25519> Ed25519Fixture::sig;
constexpr std::array<std::uint8_t, 27> Ed25519Fixture::m;

BOOST_FIXTURE_TEST_CASE(ValidLen, Ed25519Fixture)
{
  BOOST_CHECK_EQUAL(verifier.GetPublicKeyLen(), crypto::PkLen::Ed25519);
  BOOST_CHECK_EQUAL(verifier.GetPrivateKeyLen(), crypto::SkLen::Ed25519 - 32 /* An I2P'ism */);
  BOOST_CHECK_EQUAL(verifier.GetSignatureLen(), crypto::SigLen::Ed25519);
}

BOOST_FIXTURE_TEST_CASE(Sign, Ed25519Fixture)
{
  std::array<std::uint8_t, sig.size()> out{{}};
  BOOST_CHECK_NO_THROW(signer.Sign(m.data(), m.size(), out.data()));
  BOOST_CHECK_EQUAL_COLLECTIONS(out.begin(), out.end(), sig.begin(), sig.end());
}

BOOST_FIXTURE_TEST_CASE(Verify, Ed25519Fixture)
{
  BOOST_CHECK_NO_THROW(verifier.Verify(m.data(), m.size(), sig.data()));
  BOOST_CHECK(verifier.Verify(m.data(), m.size(), sig.data()));
}

BOOST_FIXTURE_TEST_CASE(NullMsg, Ed25519Fixture)
{
  constexpr std::array<std::uint8_t, m.size()> null{{}};
  BOOST_CHECK_THROW(
      verifier.Verify(null.data(), null.size(), sig.data()), std::exception);
}

BOOST_FIXTURE_TEST_CASE(NullSig, Ed25519Fixture)
{
  constexpr std::array<std::uint8_t, crypto::SigLen::Ed25519> null{{}};
  BOOST_CHECK_THROW(
      verifier.Verify(m.data(), m.size(), null.data()), std::exception);
}

BOOST_AUTO_TEST_SUITE_END()
