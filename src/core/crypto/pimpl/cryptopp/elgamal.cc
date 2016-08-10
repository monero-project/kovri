/**                                                                                           //
 * Copyright (c) 2013-2016, The Kovri I2P Router Project                                      //
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
 *                                                                                            //
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#include "crypto/elgamal.h"

#include <cryptopp/integer.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

#include <array>

#include "crypto_const.h"
#include "crypto/diffie_hellman.h"
#include "crypto/rand.h"
#include "util/log.h"

namespace i2p {
namespace crypto {

/// @class ElGamalEncryptionImpl
/// @brief ElGamal encryption
class ElGamalEncryption::ElGamalEncryptionImpl {
 public:
  ElGamalEncryptionImpl(
      const std::uint8_t* key) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::Integer
      y(key, 256),
      k(prng, CryptoPP::Integer::One(), elgp - 1);
    a = a_exp_b_mod_c(elgg, k, elgp);
    b1 = a_exp_b_mod_c(y, k, elgp);
  }

  void Encrypt(
      const std::uint8_t* data,
      std::size_t len,
      std::uint8_t* encrypted,
      bool zeroPadding) const {
    try {
      if (len > 222) {
        // Bad size, will overflow
        throw std::logic_error(
            "ElGamalEncryptionImpl: bad size for encryption: " +
            std::to_string(len));
      }
      std::array<std::uint8_t, 255> memory;
      // Don't pad with uninitialized memory
      RandBytes(memory.data(), 255);
      memory.at(0) = 0xFF;
      memcpy(memory.data() + 33, data, len);
      CryptoPP::SHA256().CalculateDigest(
          memory.data() + 1,
          memory.data() + 33,
          222);
      CryptoPP::Integer b(
          a_times_b_mod_c(
              b1,
              CryptoPP::Integer(memory.data(), 255),
              elgp));
      // Copy a and b
      if (zeroPadding) {
        encrypted[0] = 0;
        a.Encode(encrypted + 1, 256);
        encrypted[257] = 0;
        b.Encode(encrypted + 258, 256);
      } else {
        a.Encode(encrypted, 256);
        b.Encode(encrypted + 256, 256);
      }
    } catch (CryptoPP::Exception e) {
      LogPrint(eLogError,
          "ElGamalEncryptionImpl: Encrypt() caught exception '", e.what(), "'");
    }
  }

 private:
  CryptoPP::Integer a, b1;
};

ElGamalEncryption::ElGamalEncryption(
    const std::uint8_t* key)
    : m_ElGamalEncryptionPimpl(
          std::make_unique<ElGamalEncryptionImpl>(key)) {}

ElGamalEncryption::~ElGamalEncryption() {}

void ElGamalEncryption::Encrypt(
    const std::uint8_t* data,
    std::size_t len,
    std::uint8_t* encrypted,
    bool zeroPadding) const {
  m_ElGamalEncryptionPimpl->Encrypt(data, len, encrypted, zeroPadding);
}

// ElGamal decryption
bool ElGamalDecrypt(
    const std::uint8_t* key,
    const std::uint8_t* encrypted,
    std::uint8_t* data,
    bool zeroPadding) {
  if (zeroPadding && (encrypted[0] || encrypted[257]))
    return false;  // Bad padding
  CryptoPP::Integer
    x(key, 256),
    a(zeroPadding ? encrypted + 1 : encrypted, 256),
    b(zeroPadding ? encrypted + 258 : encrypted + 256, 256);
  std::array<std::uint8_t, 255> memory;
  a_times_b_mod_c(
      b,
      a_exp_b_mod_c(
          a,
          elgp - x - 1,
          elgp),
      elgp).Encode(memory.data(), 255);
  if (!CryptoPP::SHA256().VerifyDigest(
        memory.data() + 1,
        memory.data() + 33,
        222)) {
    return false;
  }
  memcpy(data, memory.data() + 33, 222);
  return true;
}

// Create keypair
void GenerateElGamalKeyPair(
    std::uint8_t* priv,
    std::uint8_t* pub) {
  try {
#if defined(__x86_64__) || defined(__i386__) || defined(_MSC_VER)
  RandBytes(priv, 256);
  a_exp_b_mod_c(
      elgg,
      CryptoPP::Integer(priv, 256),
      elgp).Encode(pub, 256);
#else
    DiffieHellman().GenerateKeyPair(priv, pub);
#endif
  } catch (CryptoPP::Exception e) {
    LogPrint(eLogError,
        "GenerateElGamalKeyPair(): caught exception '", e.what(), "'");
  }
}

}  //  namespace crypto
}  //  namespace i2p
