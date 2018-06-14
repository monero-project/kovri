/**                                                                                           //
 * Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
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

#include <cryptopp/naclite.h>

#include "core/crypto/signature_base.h"

namespace kovri {
namespace core {

/**
 *
 * DSA
 *
 */

const std::size_t DSA_PUBLIC_KEY_LENGTH = 128;
const std::size_t DSA_SIGNATURE_LENGTH = 40;
const std::size_t DSA_PRIVATE_KEY_LENGTH = DSA_SIGNATURE_LENGTH / 2;

/// @class DSAVerifier
class DSAVerifier : public Verifier {
 public:
  DSAVerifier(
      const std::uint8_t* signing_key);
  ~DSAVerifier();

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const;

  std::size_t GetPublicKeyLen() const {
    return DSA_PUBLIC_KEY_LENGTH;
  }

  std::size_t GetSignatureLen() const {
    return DSA_SIGNATURE_LENGTH;
  }

  std::size_t GetPrivateKeyLen() const {
    return DSA_PRIVATE_KEY_LENGTH;
  }

 private:
  class DSAVerifierImpl;
  std::unique_ptr<DSAVerifierImpl> m_DSAVerifierPimpl;
};

/// @class DSASigner
class DSASigner : public Signer {
 public:
  explicit DSASigner(
      const std::uint8_t* private_signing_key);
  ~DSASigner();

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const;

 private:
  class DSASignerImpl;
  std::unique_ptr<DSASignerImpl> m_DSASignerPimpl;
};

void CreateDSARandomKeys(
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key);

/**
 *
 * ECDSAP256
 *
 */

const std::size_t ECDSAP256_KEY_LENGTH = 64;

/// @class ECDSAP256Verifier
class ECDSAP256Verifier : public Verifier {
 public:
  ECDSAP256Verifier(
      const std::uint8_t* signing_key);
  ~ECDSAP256Verifier();

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const;

  std::size_t GetPublicKeyLen() const {
    return ECDSAP256_KEY_LENGTH;
  }

  std::size_t GetSignatureLen() const {
    return ECDSAP256_KEY_LENGTH;
  }

  std::size_t GetPrivateKeyLen() const {
    return ECDSAP256_KEY_LENGTH / 2;
  }

 private:
  class ECDSAP256VerifierImpl;
  std::unique_ptr<ECDSAP256VerifierImpl> m_ECDSAP256VerifierPimpl;
};

/// @class ECDSAP256Signer
class ECDSAP256Signer : public Signer {
 public:
  explicit ECDSAP256Signer(
      const std::uint8_t* private_signing_key);
  ~ECDSAP256Signer();

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const;

 private:
  class ECDSAP256SignerImpl;
  std::unique_ptr<ECDSAP256SignerImpl> m_ECDSAP256SignerPimpl;
};

void CreateECDSAP256RandomKeys(
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key);

/**
 *
 * ECDSAP384
 *
 */

const std::size_t ECDSAP384_KEY_LENGTH = 96;

/// @class ECDSAP384Verifier
class ECDSAP384Verifier : public Verifier {
 public:
  ECDSAP384Verifier(
      const std::uint8_t* signing_key);
  ~ECDSAP384Verifier();

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const;

  std::size_t GetPublicKeyLen() const {
    return ECDSAP384_KEY_LENGTH;
  }

  std::size_t GetSignatureLen() const {
    return ECDSAP384_KEY_LENGTH;
  }

  std::size_t GetPrivateKeyLen() const {
    return ECDSAP384_KEY_LENGTH / 2;
  }

 private:
  class ECDSAP384VerifierImpl;
  std::unique_ptr<ECDSAP384VerifierImpl> m_ECDSAP384VerifierPimpl;
};

/// @class ECDSAP384Signer
class ECDSAP384Signer : public Signer {
 public:
  explicit ECDSAP384Signer(
      const uint8_t* private_signing_key);
  ~ECDSAP384Signer();

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const;

 private:
  class ECDSAP384SignerImpl;
  std::unique_ptr<ECDSAP384SignerImpl> m_ECDSAP384SignerPimpl;
};

void CreateECDSAP384RandomKeys(
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key);

/**
 *
 * ECDSAP521
 *
 */

const std::size_t ECDSAP521_KEY_LENGTH = 132;

/// @class ECDSAP521Verifier
class ECDSAP521Verifier : public Verifier {
 public:
  ECDSAP521Verifier(
      const std::uint8_t* signing_key);
  ~ECDSAP521Verifier();

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const;

  std::size_t GetPublicKeyLen() const {
    return ECDSAP521_KEY_LENGTH;
  }

  std::size_t GetSignatureLen() const {
    return ECDSAP521_KEY_LENGTH;
  }

  std::size_t GetPrivateKeyLen() const {
    return ECDSAP521_KEY_LENGTH / 2;
  }

 private:
  class ECDSAP521VerifierImpl;
  std::unique_ptr<ECDSAP521VerifierImpl> m_ECDSAP521VerifierPimpl;
};

/// @class ECDSAP521Signer
class ECDSAP521Signer : public Signer {
 public:
  explicit ECDSAP521Signer(
      const uint8_t* private_signing_key);
  ~ECDSAP521Signer();

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const;

 private:
  class ECDSAP521SignerImpl;
  std::unique_ptr<ECDSAP521SignerImpl> m_ECDSAP521SignerPimpl;
};

void CreateECDSAP521RandomKeys(
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key);

/**
 *
 * RSASHA2562048
 *
 */

const std::size_t RSASHA2562048_KEY_LENGTH = 256;

/// @class RSASHA2562048Verifier
class RSASHA2562048Verifier : public Verifier {
 public:
    explicit RSASHA2562048Verifier(
        const std::uint8_t* signing_key);
  ~RSASHA2562048Verifier();

  std::size_t GetPublicKeyLen() const {
    return RSASHA2562048_KEY_LENGTH;
  }

  std::size_t GetSignatureLen() const {
    return RSASHA2562048_KEY_LENGTH;
  }

  std::size_t GetPrivateKeyLen() const {
    return RSASHA2562048_KEY_LENGTH * 2;
  }

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const;

 private:
  class RSASHA2562048VerifierImpl;
  std::unique_ptr<RSASHA2562048VerifierImpl> m_RSASHA2562048VerifierPimpl;
};

/// @class RSASHA2562048Signer
class RSASHA2562048Signer : public Signer {
 public:
  explicit RSASHA2562048Signer(
      const std::uint8_t* private_signing_key);
  ~RSASHA2562048Signer();

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const;

 private:
  class RSASHA2562048SignerImpl;
  std::unique_ptr<RSASHA2562048SignerImpl> m_RSASHA2562048SignerPimpl;
};

/**
 *
 * RSASHA3843072
 *
 */

const std::size_t RSASHA3843072_KEY_LENGTH = 384;

/// @class RSASHA3843072Verifier
class RSASHA3843072Verifier : public Verifier {
 public:
  explicit RSASHA3843072Verifier(
      const std::uint8_t* signing_key);
  ~RSASHA3843072Verifier();

  std::size_t GetPublicKeyLen() const {
    return RSASHA3843072_KEY_LENGTH;
  }

  std::size_t GetSignatureLen() const {
    return RSASHA3843072_KEY_LENGTH;
  }

  std::size_t GetPrivateKeyLen() const {
    return RSASHA3843072_KEY_LENGTH * 2;
  }

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const;

 private:
  class RSASHA3843072VerifierImpl;
  std::unique_ptr<RSASHA3843072VerifierImpl> m_RSASHA3843072VerifierPimpl;
};

/// @class RSASHA3843072Signer
class RSASHA3843072Signer : public Signer {
 public:
  explicit RSASHA3843072Signer(
      const std::uint8_t* private_signing_key);
  ~RSASHA3843072Signer();

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const;

 private:
  class RSASHA3843072SignerImpl;
  std::unique_ptr<RSASHA3843072SignerImpl> m_RSASHA3843072SignerPimpl;
};

/**
 *
 * RSASHA5124096
 *
 */

const std::size_t RSASHA5124096_KEY_LENGTH = 512;

/// @class RSASHA5124096Verifier
class RSASHA5124096Verifier : public Verifier {
 public:
  explicit RSASHA5124096Verifier(
      const std::uint8_t* signing_key);
  ~RSASHA5124096Verifier();

  std::size_t GetPublicKeyLen() const {
    return RSASHA5124096_KEY_LENGTH;
  }

  std::size_t GetSignatureLen() const {
    return RSASHA5124096_KEY_LENGTH;
  }

  std::size_t GetPrivateKeyLen() const {
    return RSASHA5124096_KEY_LENGTH * 2;
  }

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const;

 private:
  class RSASHA5124096VerifierImpl;
  std::unique_ptr<RSASHA5124096VerifierImpl> m_RSASHA5124096VerifierPimpl;
};

/// @class RSASHA5124096Signer
class RSASHA5124096Signer : public Signer {
 public:
  explicit RSASHA5124096Signer(
      const std::uint8_t* private_signing_key);
  ~RSASHA5124096Signer();

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const;

 private:
  class RSASHA5124096SignerImpl;
  std::unique_ptr<RSASHA5124096SignerImpl> m_RSASHA5124096SignerPimpl;
};

void CreateRSARandomKeys(
    std::size_t public_key_length,
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key);

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

// TODO(anonimal): continue with remaining crypto
namespace crypto
{
namespace PkLen
{
enum
{
  Ed25519 = CryptoPP::NaCl::crypto_sign_PUBLICKEYBYTES,
};
}  // namespace PkLen

namespace SkLen
{
enum
{
  Ed25519 = CryptoPP::NaCl::crypto_sign_SECRETKEYBYTES,
};
}  // namespace SkLen

namespace SigLen
{
enum
{
  Ed25519 = CryptoPP::NaCl::crypto_sign_BYTES,
};
}  // namespace SigLen
}  // namespace crypto

/// @class Ed25519Verifier
/// @brief Interface class for the EdDSA Ed25519 verifier
class Ed25519Verifier : public Verifier
{
 public:
  explicit Ed25519Verifier(const std::uint8_t* pk);

  ~Ed25519Verifier();

  /// @brief Verify signed message with given signature
  /// @param m Message (without signature)
  /// @param mlen Message length (without signature)
  /// @param sig Signature
  bool Verify(
      const std::uint8_t* m,
      const std::size_t mlen,
      const std::uint8_t* sig) const;

  std::size_t GetPublicKeyLen() const
  {
    return crypto::PkLen::Ed25519;
  }

  std::size_t GetPrivateKeyLen() const
  {
    return crypto::SkLen::Ed25519 - 32;  // An I2P'ism
  }

  std::size_t GetSignatureLen() const
  {
    return crypto::SigLen::Ed25519;
  }

 private:
  class Ed25519VerifierImpl;
  std::unique_ptr<Ed25519VerifierImpl> m_Ed25519VerifierPimpl;
};

/// @class Ed25519Signer
/// @brief Interface class for the EdDSA Ed25519 signer
class Ed25519Signer : public Signer
{
 public:
  /// @brief Create signer from a private key
  /// @param sk Private key
  /// @details The corresponding public key will be computed internally
  explicit Ed25519Signer(const std::uint8_t* sk);

  /// @brief Create signer from a keypair
  /// @param sk Private key
  /// @param pk Public key
  Ed25519Signer(const std::uint8_t* sk, const std::uint8_t* pk);

  ~Ed25519Signer();

  /// @brief Ed25519 sign a message
  /// @param m Message
  /// @param mlen Message size
  /// @param sig Output the signature (only) of the signed message
  void Sign(const std::uint8_t* m, const std::size_t mlen, std::uint8_t* sig)
      const;

 private:
  class Ed25519SignerImpl;
  std::unique_ptr<Ed25519SignerImpl> m_Ed25519SignerPimpl;
};

/// @brief Generate ed25519 keypair
void CreateEd25519KeyPair(std::uint8_t* sk, std::uint8_t* pk);

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_CRYPTO_SIGNATURE_H_
