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

#ifndef SRC_CORE_CRYPTO_EDDSA25519_H_
#define SRC_CORE_CRYPTO_EDDSA25519_H_

#include "SignatureBase.h"

namespace i2p {
namespace crypto {

// EdDSA
const size_t EDDSA25519_PUBLIC_KEY_LENGTH = 32;
const size_t EDDSA25519_SIGNATURE_LENGTH = 64;
const size_t EDDSA25519_PRIVATE_KEY_LENGTH = 32;

class EDDSA25519Verifier : public Verifier {
 public:
  EDDSA25519Verifier(
      const uint8_t* signingKey);

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

  size_t GetPublicKeyLen() const { return EDDSA25519_PUBLIC_KEY_LENGTH; }
  size_t GetSignatureLen() const { return EDDSA25519_SIGNATURE_LENGTH; }
  size_t GetPrivateKeyLen() const { return EDDSA25519_PRIVATE_KEY_LENGTH; }
 private:
  uint8_t m_PublicKey[EDDSA25519_PUBLIC_KEY_LENGTH];
};

class EDDSA25519Signer : public Signer {
 public:
  // Construct from a key pair.
  EDDSA25519Signer(
      const uint8_t* signingPrivateKey,
      const uint8_t* signingPublicKey);

  // Construct from a private key.
  // The corresponding public key will be computed from it.
  EDDSA25519Signer(
      const uint8_t* signingPrivateKey);

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const;

  uint8_t m_PrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH];
  uint8_t m_PublicKey[EDDSA25519_PUBLIC_KEY_LENGTH];
};

void CreateEDDSARandomKeys(
    uint8_t* privateKey,
    uint8_t* publicKey);

}  // namespace crypto
}  // namespace i2p

#endif  // SRC_CORE_CRYPTO_EDDSA25519_H_
