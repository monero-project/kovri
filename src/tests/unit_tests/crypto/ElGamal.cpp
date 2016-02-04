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
#include "crypto/ElGamal.h"
#include "crypto/Rand.h"

using namespace i2p::crypto;

BOOST_AUTO_TEST_SUITE(ElgamalTests)

struct ElgamalFixture {

  uint8_t privateKey[256];
  uint8_t publicKey[256];
  ElGamalEncryption* enc;
  static constexpr size_t messageLen = 222;
  static constexpr size_t cipherTextLen = 512;
  static constexpr size_t zpCipherTextLen = cipherTextLen + 2;
  ElgamalFixture() {
    // TODO(psi): use static keys
    GenerateElGamalKeyPair(privateKey, publicKey);
    enc = new ElGamalEncryption(publicKey);
  }

  ~ElgamalFixture() {
    delete enc;
  }
  

};


BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptSuccess, ElgamalFixture) {
  uint8_t plaintext[messageLen];
  uint8_t ciphertext[cipherTextLen];
  uint8_t result[messageLen];
  RandBytes(plaintext, messageLen);
  enc->Encrypt(plaintext, messageLen, ciphertext, false);
  BOOST_CHECK(ElGamalDecrypt(privateKey, ciphertext, result, false));
  
  BOOST_CHECK_EQUAL_COLLECTIONS(
    plaintext, plaintext + messageLen,
    result, result + messageLen);
}

BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptFail, ElgamalFixture) {
  uint8_t plaintext[messageLen];
  uint8_t ciphertext[cipherTextLen];
  uint8_t result[messageLen];
  RandBytes(plaintext, messageLen);
  enc->Encrypt(plaintext, messageLen, ciphertext, false);
  // Introduce an error in the ciphertext
  ciphertext[4] ^= RandInRange<uint8_t>(1, 128);

  BOOST_CHECK(!ElGamalDecrypt(privateKey, ciphertext, result, false));
}

BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptZeroPaddBadPad, ElgamalFixture) {
  uint8_t plaintext[messageLen];
  uint8_t ciphertext[zpCipherTextLen];
  uint8_t result[messageLen];
  RandBytes(plaintext, messageLen);
  enc->Encrypt(plaintext, messageLen, ciphertext, true);
  // Introduce an error in the ciphertext zeropadding
  ciphertext[0] = RandInRange<uint8_t>(1, 128);
  BOOST_CHECK(!ElGamalDecrypt(privateKey, ciphertext, result, true));
}


BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptZeroPadSuccess, ElgamalFixture) {
  uint8_t plaintext[messageLen];
  uint8_t ciphertext[zpCipherTextLen];
  uint8_t result[messageLen];
  RandBytes(plaintext, messageLen);
  enc->Encrypt(plaintext, messageLen, ciphertext, true);
  
  bool res = ElGamalDecrypt(privateKey, ciphertext, result, true);

  BOOST_CHECK(res);
  if (res) {
    BOOST_CHECK_EQUAL_COLLECTIONS(
      plaintext, plaintext + messageLen,
      result, result + messageLen);
  }
}

BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptZeroPadSmallMessageSuccess,
                        ElgamalFixture) {
  size_t smaller = 50;
  uint8_t plaintext[messageLen-smaller];
  uint8_t ciphertext[zpCipherTextLen];
  uint8_t result[messageLen];
  RandBytes(plaintext, messageLen-smaller);
  enc->Encrypt(plaintext, messageLen, ciphertext, true);
  
  BOOST_CHECK(ElGamalDecrypt(privateKey, ciphertext, result, true));
  
  BOOST_CHECK_EQUAL_COLLECTIONS(
    plaintext, plaintext + messageLen - smaller,
    result, result + messageLen - smaller);
  
}

BOOST_AUTO_TEST_SUITE_END()
