/**                                                                                           //
 * Copyright (c) 2015-2016, The Kovri I2P Router Project                                      //
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

#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include <memory>

#include "crypto/rand.h"
#include "crypto/signature.h"

BOOST_AUTO_TEST_SUITE(DSASHA1ests)

struct DSAFixture {
  DSAFixture() {
    // TODO(unassigned): generate static test keys
    i2p::crypto::CreateDSARandomKeys(private_key, public_key);
    verifier = std::make_unique<i2p::crypto::DSAVerifier>(public_key);
    signer = std::make_unique<i2p::crypto::DSASigner>(private_key);
  }
  uint8_t private_key[20], public_key[128];
  std::unique_ptr<i2p::crypto::DSAVerifier> verifier;
  std::unique_ptr<i2p::crypto::DSASigner> signer;
  static constexpr size_t key_message_len = 1024;
};

BOOST_FIXTURE_TEST_CASE(DSASHA1KeyLength, DSAFixture) {
  BOOST_CHECK_EQUAL(
      verifier->GetPublicKeyLen(),
      i2p::crypto::DSA_PUBLIC_KEY_LENGTH);
}

BOOST_FIXTURE_TEST_CASE(DSASHA1SignatureLength, DSAFixture) {
  BOOST_CHECK_EQUAL(
      verifier->GetSignatureLen(),
      i2p::crypto::DSA_SIGNATURE_LENGTH);
}

BOOST_FIXTURE_TEST_CASE(DSASHA1SignVerifyValid, DSAFixture) {
  uint8_t signature[40], message[key_message_len];
  i2p::crypto::RandBytes(message, key_message_len);
  signer->Sign(message, key_message_len, signature);
  // check that the signature is valid
  BOOST_CHECK_EQUAL(verifier->Verify(message, key_message_len, signature), true);
}

BOOST_FIXTURE_TEST_CASE(DSASHA1SignVerifyBadSignature, DSAFixture) {
  uint8_t signature[40], message[key_message_len];
  i2p::crypto::RandBytes(message, key_message_len);
  signer->Sign(message, key_message_len, signature);
  // introduce an error in the signature
  signature[5] ^= i2p::crypto::RandInRange<uint8_t>(1, 128);
  // it should fail verification
  BOOST_CHECK_EQUAL(verifier->Verify(message, key_message_len, signature), false);
}

BOOST_FIXTURE_TEST_CASE(DSASHA1SignVerifyBadMessage, DSAFixture) {
  uint8_t signature[40], message[key_message_len];
  i2p::crypto::RandBytes(message, key_message_len);
  signer->Sign(message, key_message_len, signature);
  // introduce an error in the message
  message[5] ^= i2p::crypto::RandInRange<uint8_t>(1, 128);
  // this should also fail verification
  BOOST_CHECK_EQUAL(verifier->Verify(message, key_message_len, signature), false);
}

BOOST_FIXTURE_TEST_CASE(DSASHA1SignVerifyBadSignatureAndMessage, DSAFixture) {
  uint8_t signature[40], message[key_message_len];
  i2p::crypto::RandBytes(message, key_message_len);
  signer->Sign(message, key_message_len, signature);
  // introduce errors in both the message and signature
  message[6] ^= i2p::crypto::RandInRange<uint8_t>(1, 128);
  signature[2] ^= i2p::crypto::RandInRange<uint8_t>(1, 128);
  // this should fail verification as well
  BOOST_CHECK_EQUAL(verifier->Verify(message, key_message_len, signature), false);
}

BOOST_AUTO_TEST_SUITE_END()
