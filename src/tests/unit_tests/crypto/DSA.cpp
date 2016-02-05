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
#include "crypto/Signature.h"
#include "crypto/Rand.h"

using namespace i2p::crypto;

BOOST_AUTO_TEST_SUITE(DSASHA1ests)

struct DSAFixture {
  DSAFixture() {
    // TODO(psi): generate static test keys
    CreateDSARandomKeys(privateKey, publicKey);

    verifier = new DSAVerifier(publicKey);
    signer = new DSASigner(privateKey);
  }

  ~DSAFixture() {
    delete verifier;
    delete signer;
  }

  uint8_t privateKey[20];
  uint8_t publicKey[128];
  DSAVerifier* verifier;
  DSASigner* signer;
  static constexpr size_t kMessageLen = 1024;
};

BOOST_FIXTURE_TEST_CASE(DSASHA1KeyLength, DSAFixture) {
  BOOST_CHECK_EQUAL(verifier->GetPublicKeyLen(), DSA_PUBLIC_KEY_LENGTH);
}


BOOST_FIXTURE_TEST_CASE(DSASHA1SignatureLength, DSAFixture) {
  BOOST_CHECK_EQUAL(verifier->GetSignatureLen(), DSA_SIGNATURE_LENGTH);
}

BOOST_FIXTURE_TEST_CASE(DSASHA1SignVerifyValid, DSAFixture) {
  uint8_t signature[40];
  uint8_t message[kMessageLen];
  RandBytes(message, kMessageLen);
  signer->Sign(message, kMessageLen, signature);
  // check that the signature is valid
  BOOST_CHECK_EQUAL(verifier->Verify(message, kMessageLen, signature), true);
}

BOOST_FIXTURE_TEST_CASE(DSASHA1SignVerifyBadSignature, DSAFixture) {
  uint8_t signature[40];
  uint8_t message[kMessageLen];
  RandBytes(message, kMessageLen);
  signer->Sign(message, kMessageLen, signature);

  // introduce an error in the signature
  signature[5] ^= RandInRange<uint8_t>(1, 128);
  // it should fail verification
  BOOST_CHECK_EQUAL(verifier->Verify(message, kMessageLen, signature), false);
}

BOOST_FIXTURE_TEST_CASE(DSASHA1SignVerifyBadMessage, DSAFixture) {
  uint8_t signature[40];
  uint8_t message[kMessageLen];
  RandBytes(message, kMessageLen);
  signer->Sign(message, kMessageLen, signature);
  // introduce an error in the message
  message[5] ^= RandInRange<uint8_t>(1, 128);
  // this should also fail verification
  BOOST_CHECK_EQUAL(verifier->Verify(message, kMessageLen, signature), false);
}

BOOST_FIXTURE_TEST_CASE(DSASHA1SignVerifyBadSignatureAndMessage, DSAFixture) {
  uint8_t signature[40];
  uint8_t message[kMessageLen];
  RandBytes(message, kMessageLen);

  signer->Sign(message, kMessageLen, signature);

  // introduce errors in both the message and signature
  message[6] ^= RandInRange<uint8_t>(1, 128);
  signature[2] ^= RandInRange<uint8_t>(1, 128);
  // this should fail verification as well
  BOOST_CHECK_EQUAL(verifier->Verify(message, kMessageLen, signature), false);
}

BOOST_AUTO_TEST_SUITE_END()
