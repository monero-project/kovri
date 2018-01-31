/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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

#ifndef SRC_CORE_CRYPTO_SIGNATURE_H_
#define SRC_CORE_CRYPTO_SIGNATURE_H_

#include <cstdint>
#include <memory>

#include "core/crypto/signature_base.h"

namespace kovri {
namespace core {

const std::size_t RSASHA5124096_KEY_LENGTH = 512;

/**
 *
 * RSASHA5124096Raw
 *
 */

/// @class RSASHA5124096RawVerifier
class RSASHA5124096RawVerifier : public RawVerifier {
 public:
  explicit RSASHA5124096RawVerifier(
      const std::uint8_t* signing_key);
  ~RSASHA5124096RawVerifier();

  bool Verify(
      const std::uint8_t* signature);

  void Update(
      const std::uint8_t* signature,
      std::size_t len);

 private:
  class RSASHA5124096RawVerifierImpl;
  std::unique_ptr<RSASHA5124096RawVerifierImpl> m_RSASHA5124096RawVerifierPimpl;
};

/**
 *
 * Ed25519
 *
 */

const std::size_t EDDSA25519_PUBLIC_KEY_LENGTH = 32;
const std::size_t EDDSA25519_SIGNATURE_LENGTH = 64;
const std::size_t EDDSA25519_PRIVATE_KEY_LENGTH = 32;

/// @class EDDSA25519Verifier
class EDDSA25519Verifier : public Verifier {
 public:
  EDDSA25519Verifier(
      const std::uint8_t* signing_key);
  ~EDDSA25519Verifier();

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const;

  std::size_t GetPublicKeyLen() const {
    return EDDSA25519_PUBLIC_KEY_LENGTH;
  }

  std::size_t GetSignatureLen() const {
    return EDDSA25519_SIGNATURE_LENGTH;
  }

  std::size_t GetPrivateKeyLen() const {
    return EDDSA25519_PRIVATE_KEY_LENGTH;
  }

 private:
  class EDDSA25519VerifierImpl;
  std::unique_ptr<EDDSA25519VerifierImpl> m_EDDSA25519VerifierPimpl;
};

/// @class EDDSA25519Signer
class EDDSA25519Signer : public Signer {
 public:
  /// @brief Construct from a key pair.
  EDDSA25519Signer(
      const std::uint8_t* signing_private_key,
      const std::uint8_t* signing_public_key);

  // @brief Construct from a private key.
  // @details The corresponding public key will be computed from it.
  EDDSA25519Signer(
      const std::uint8_t* signing_private_key);
  ~EDDSA25519Signer();

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const;

 private:
  class EDDSA25519SignerImpl;
  std::unique_ptr<EDDSA25519SignerImpl> m_EDDSA25519SignerPimpl;
};

// Create keys
void CreateEDDSARandomKeys(
    std::uint8_t* private_key,
    std::uint8_t* public_key);


}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_CRYPTO_SIGNATURE_H_
