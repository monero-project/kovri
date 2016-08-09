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

#include "crypto/signature.h"

#include <cstring>
#include <cstdint>

#include "ed25519/ed25519_ref10.h"
#include "crypto/rand.h"

namespace i2p {
namespace crypto {

/**
 *
 * Ed25519
 *
 */

/// @class EDDSA25519VerifierImpl
class EDDSA25519Verifier::EDDSA25519VerifierImpl {
 public:
  EDDSA25519VerifierImpl(
      const std::uint8_t* signingKey) {
    std::memcpy(
        m_PublicKey,
        signingKey,
        EDDSA25519_PUBLIC_KEY_LENGTH);
  }

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const {
    return ed25519_ref10_open(
        signature,
        buf,
        len,
        m_PublicKey) >= 0;
  }

 private:
  std::uint8_t m_PublicKey[EDDSA25519_PUBLIC_KEY_LENGTH];
};

EDDSA25519Verifier::EDDSA25519Verifier(
    const std::uint8_t* signing_key)
    : m_EDDSA25519VerifierPimpl(
          std::make_unique<EDDSA25519VerifierImpl>(signing_key)) {}

EDDSA25519Verifier::~EDDSA25519Verifier() {}

bool EDDSA25519Verifier::Verify(
    const std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* signature) const {
  return m_EDDSA25519VerifierPimpl->Verify(buf, len, signature);
}

/// @class EDDSA25519SignerImpl
class EDDSA25519Signer::EDDSA25519SignerImpl {
 public:
  EDDSA25519SignerImpl(
      const std::uint8_t* private_signing_key,
      const std::uint8_t* public_signing_key) {
    std::memcpy(
        m_PrivateKey,
        private_signing_key,
        EDDSA25519_PRIVATE_KEY_LENGTH);
    std::memcpy(
        m_PublicKey,
        public_signing_key,
        EDDSA25519_PUBLIC_KEY_LENGTH);
  }

  EDDSA25519SignerImpl(
      const std::uint8_t* private_signing_key) {
    std::memcpy(
        m_PrivateKey,
        private_signing_key,
        EDDSA25519_PRIVATE_KEY_LENGTH);
    ed25519_ref10_pubkey(m_PublicKey, m_PrivateKey);
  }

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const {
    ed25519_ref10_sign(
        signature,
        buf,
        len,
        m_PrivateKey,
        m_PublicKey);
  }

 private:
  std::uint8_t m_PrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH];
  std::uint8_t m_PublicKey[EDDSA25519_PUBLIC_KEY_LENGTH];
};

EDDSA25519Signer::EDDSA25519Signer(
    const std::uint8_t* private_signing_key)
    : m_EDDSA25519SignerPimpl(
          std::make_unique<EDDSA25519SignerImpl>(
              private_signing_key)) {}

EDDSA25519Signer::EDDSA25519Signer(
    const std::uint8_t* private_signing_key,
    const std::uint8_t* public_signing_key)
    : m_EDDSA25519SignerPimpl(
          std::make_unique<EDDSA25519SignerImpl>(
              private_signing_key,
              public_signing_key)) {}

EDDSA25519Signer::~EDDSA25519Signer() {}

void EDDSA25519Signer::Sign(
    const std::uint8_t* buf,
    std::size_t len,
    std::uint8_t* signature) const {
  m_EDDSA25519SignerPimpl->Sign(buf, len, signature);
}

// Create keys
void CreateEDDSARandomKeys(
    std::uint8_t* privateKey,
    std::uint8_t* publicKey) {
  i2p::crypto::RandBytes(
      privateKey,
      EDDSA25519_PRIVATE_KEY_LENGTH);
  ed25519_ref10_pubkey(
      publicKey,
      privateKey);
}

}  // namespace crypto
}  // namespace i2p
