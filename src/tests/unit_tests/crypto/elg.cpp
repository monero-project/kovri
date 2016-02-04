
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
  uint8_t ciphertext[512];
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
  uint8_t ciphertext[512];
  uint8_t result[messageLen];
  RandBytes(plaintext, messageLen);
  enc->Encrypt(plaintext, messageLen, ciphertext, false);
  // fug up the ciphertext
  ciphertext[4] ^= RandInRange<uint8_t>(1, 128);

  BOOST_CHECK(!ElGamalDecrypt(privateKey, ciphertext, result, false));
}

BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptZeroPaddBadPad, ElgamalFixture) {
  uint8_t plaintext[messageLen];
  uint8_t ciphertext[514];
  uint8_t result[messageLen];
  RandBytes(plaintext, messageLen);
  enc->Encrypt(plaintext, messageLen, ciphertext, true);
  // fug up the ciphertext zeropadding
  ciphertext[0] = RandInRange<uint8_t>(1, 128);
  BOOST_CHECK(!ElGamalDecrypt(privateKey, ciphertext, result, true));
}


BOOST_FIXTURE_TEST_CASE(ElgamalEncryptDecryptZeroPadSuccess, ElgamalFixture) {
  uint8_t plaintext[messageLen];
  uint8_t ciphertext[514];
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

BOOST_AUTO_TEST_SUITE_END()
