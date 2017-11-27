/**                                                                                           //
 * Copyright (c) 2015-2017, The Kovri I2P Router Project                                      //
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

#include "core/crypto/elgamal.h"
#include "core/crypto/rand.h"

void InitKeyInfo(uint8_t* priv, uint8_t* pub, uint8_t* seed) {
  for (size_t i = 0; i < 256; i++) {
    seed[i] = 0x01;
    priv[i] = 0x09;
    pub[i]  = 0x0a;
  }
}

BOOST_AUTO_TEST_SUITE(ElgamalTests)


struct ElgamalFixture {
  ElgamalFixture() {
    // Initialize elements needed for deterministic keys
    uint8_t seed[256];
    InitKeyInfo(private_key, public_key, seed);
    // Derive private and public keys from seed
    kovri::core::GenerateDeterministicElGamalKeyPair(private_key, public_key, seed);
    enc = std::make_unique<kovri::core::ElGamalEncryption>(public_key);
  }
  uint8_t private_key[256], public_key[256];
  std::unique_ptr<kovri::core::ElGamalEncryption> enc;
  static constexpr size_t key_message_len = 222;
  static constexpr size_t key_ciphertext_len = 512;
  static constexpr size_t key_zero_padding_ciphertext_len = key_ciphertext_len + 2;
};

BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptSuccess, ElgamalFixture) {
  uint8_t plaintext[key_message_len];
  uint8_t ciphertext[key_ciphertext_len];
  uint8_t result[key_message_len];
  kovri::core::RandBytes(plaintext, key_message_len);
  enc->Encrypt(plaintext, key_message_len, ciphertext, false);
  BOOST_CHECK(kovri::core::ElGamalDecrypt(private_key, ciphertext, result, false));
  BOOST_CHECK_EQUAL_COLLECTIONS(
    plaintext, plaintext + key_message_len,
    result, result + key_message_len);
}

BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptFail, ElgamalFixture) {
  uint8_t plaintext[key_message_len];
  uint8_t ciphertext[key_ciphertext_len];
  uint8_t result[key_message_len];
  kovri::core::RandBytes(plaintext, key_message_len);
  enc->Encrypt(plaintext, key_message_len, ciphertext, false);
  // Introduce an error in the ciphertext
  ciphertext[4] ^= kovri::core::RandInRange32(1, 128);
  BOOST_CHECK(!kovri::core::ElGamalDecrypt(private_key, ciphertext, result, false));
}

BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptZeroPadBadPad, ElgamalFixture) {
  uint8_t plaintext[key_message_len];
  uint8_t ciphertext[key_zero_padding_ciphertext_len];
  uint8_t result[key_message_len];
  kovri::core::RandBytes(plaintext, key_message_len);
  enc->Encrypt(plaintext, key_message_len, ciphertext, true);
  // Introduce an error in the ciphertext zeropadding
  ciphertext[0] = kovri::core::RandInRange32(1, 128);
  BOOST_CHECK(!kovri::core::ElGamalDecrypt(private_key, ciphertext, result, true));
}

BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptZeroPadSuccess, ElgamalFixture) {
  uint8_t plaintext[key_message_len];
  uint8_t ciphertext[key_zero_padding_ciphertext_len];
  uint8_t result[key_message_len];
  kovri::core::RandBytes(plaintext, key_message_len);
  enc->Encrypt(plaintext, key_message_len, ciphertext, true);
  bool res = kovri::core::ElGamalDecrypt(private_key, ciphertext, result, true);
  BOOST_CHECK(res);
  if (res) {
    BOOST_CHECK_EQUAL_COLLECTIONS(
      plaintext, plaintext + key_message_len,
      result, result + key_message_len);
  }
}

BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptZeroPadSmallMessageSuccess, ElgamalFixture) {
  constexpr size_t key_smaller = 50;
  uint8_t plaintext[key_message_len - key_smaller];
  uint8_t ciphertext[key_zero_padding_ciphertext_len];
  uint8_t result[key_message_len];
  kovri::core::RandBytes(plaintext, key_message_len - key_smaller);
  enc->Encrypt(plaintext, key_message_len, ciphertext, true);
  BOOST_CHECK(kovri::core::ElGamalDecrypt(private_key, ciphertext, result, true));
  BOOST_CHECK_EQUAL_COLLECTIONS(
    plaintext, plaintext + key_message_len - key_smaller,
    result, result + key_message_len - key_smaller);
}

BOOST_FIXTURE_TEST_CASE(ElgamalDeterministicKeyGenerationUniqueKeysBySeed, ElgamalFixture) {
  uint8_t tstseed[256],
          tstpriv[256],
          tstpub[256];

  InitKeyInfo(tstpriv, tstpub, tstseed); 
  kovri::core::GenerateDeterministicElGamalKeyPair(tstpriv, tstpub, tstseed);

  BOOST_TEST_MESSAGE("Test private key: " << tstpriv << "\n" 
                     << "Private key: " << private_key << "\n\n"
                     << "Test public key: " << tstpub << "\n"
                     << "Public key: " << public_key << "\n");

  for (size_t i = 0; i < 256; i++) {
    BOOST_CHECK_EQUAL(tstpriv[i], private_key[i]);
    BOOST_CHECK_EQUAL(tstpub[i], public_key[i]);
  }
}

BOOST_AUTO_TEST_SUITE_END()
