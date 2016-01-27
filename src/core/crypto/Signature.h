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

#ifndef SRC_CORE_CRYPTO_SIGNATURE_H_
#define SRC_CORE_CRYPTO_SIGNATURE_H_

#include <inttypes.h>

#include "EdDSA25519.h"
#include "SignatureBase.h"

namespace i2p {
namespace crypto {

const size_t DSA_PUBLIC_KEY_LENGTH = 128;
const size_t DSA_SIGNATURE_LENGTH = 40;
const size_t DSA_PRIVATE_KEY_LENGTH = DSA_SIGNATURE_LENGTH/2;

// DSAVerifier
class DSAVerifier_Pimpl;
class DSAVerifier : public Verifier {
 public:
  DSAVerifier(
    const uint8_t* signingKey);

  ~DSAVerifier();
  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

  size_t GetPublicKeyLen() const {
    return DSA_PUBLIC_KEY_LENGTH;
  }

  size_t GetSignatureLen() const {
    return DSA_SIGNATURE_LENGTH;
  }

  size_t GetPrivateKeyLen() const {
    return DSA_PRIVATE_KEY_LENGTH;
  }

 private:
  DSAVerifier_Pimpl* m_Impl;
};

// DSASigner
class DSASigner_Pimpl;
class DSASigner : public Signer {
 public:
  explicit DSASigner(
      const uint8_t* signingPrivateKey);
  ~DSASigner();

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const;

 private:
  DSASigner_Pimpl* m_Impl;
};

void CreateDSARandomKeys(
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey);

// ECDSA_SHA256_P256
const size_t ECDSAP256_KEY_LENGTH = 64;
// ECDSAP256Verifier
class ECDSAP256Verifier_Pimpl;
class ECDSAP256Verifier : public Verifier {
 public:
  ECDSAP256Verifier(
      const uint8_t * signingKey);
  ~ECDSAP256Verifier();

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

  size_t GetPublicKeyLen() const {
    return ECDSAP256_KEY_LENGTH;
  }

  size_t GetSignatureLen() const {
    return ECDSAP256_KEY_LENGTH;
  }

  size_t GetPrivateKeyLen() const {
    return ECDSAP256_KEY_LENGTH / 2;
  }

 private:
  ECDSAP256Verifier_Pimpl* m_Impl;
};

// ECDSAP256Signer
class ECDSAP256Signer_Pimpl;
struct ECDSAP256Signer : public Signer {
  explicit ECDSAP256Signer(
      const uint8_t* signingPrivateKey);
  ~ECDSAP256Signer();

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const;

 private:
  ECDSAP256Signer_Pimpl* m_Impl;
};

void CreateECDSAP256RandomKeys(
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey);

// ECDSA_SHA384_P384
const size_t ECDSAP384_KEY_LENGTH = 96;
// ECDSAP384Verifier
class ECDSAP384Verifier_Pimpl;
class ECDSAP384Verifier : public Verifier {
 public:
  ECDSAP384Verifier(
      const uint8_t * signingKey);
  ~ECDSAP384Verifier();

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

  size_t GetPublicKeyLen() const {
    return ECDSAP384_KEY_LENGTH;
  }

  size_t GetSignatureLen() const {
    return ECDSAP384_KEY_LENGTH;
  }

  size_t GetPrivateKeyLen() const {
    return ECDSAP384_KEY_LENGTH / 2;
  }

 private:
  ECDSAP384Verifier_Pimpl* m_Impl;
};

// ECDSAP384Signer
class ECDSAP384Signer_Pimpl;
struct ECDSAP384Signer : public Signer {
  explicit ECDSAP384Signer(
      const uint8_t* signingPrivateKey);
  ~ECDSAP384Signer();

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const;

 private:
  ECDSAP384Signer_Pimpl* m_Impl;
};

void CreateECDSAP384RandomKeys(
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey);

// ECDSA_SHA512_P521
const size_t ECDSAP521_KEY_LENGTH = 132;
// ECDSAP521Verifier
class ECDSAP521Verifier_Pimpl;
class ECDSAP521Verifier : public Verifier {
 public:
  ECDSAP521Verifier(
      const uint8_t* signingKey);
  ~ECDSAP521Verifier();

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

  size_t GetPublicKeyLen() const {
    return ECDSAP521_KEY_LENGTH;
  }

  size_t GetSignatureLen() const {
    return ECDSAP521_KEY_LENGTH;
  }

  size_t GetPrivateKeyLen() const {
    return ECDSAP521_KEY_LENGTH / 2;
  }

 private:
  ECDSAP521Verifier_Pimpl* m_Impl;
};

// ECDSAP521Signer
class ECDSAP521Signer_Pimpl;
struct ECDSAP521Signer : public Signer {
  explicit ECDSAP521Signer(
      const uint8_t* signingPrivateKey);
  ~ECDSAP521Signer();

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const;

 private:
  ECDSAP521Signer_Pimpl* m_Impl;
};

void CreateECDSAP521RandomKeys(
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey);

// RSA_SHA256_2048
const size_t RSASHA2562048_KEY_LENGTH = 256;
// RSASHA2562048Verifier
class RSASHA2562048Verifier_Pimpl;
class RSASHA2562048Verifier : public Verifier {
 public:
    explicit RSASHA2562048Verifier(
        const uint8_t* signingKey);
  ~RSASHA2562048Verifier();

  size_t GetPublicKeyLen() const {
    return RSASHA2562048_KEY_LENGTH;
  }

  size_t GetSignatureLen() const {
    return RSASHA2562048_KEY_LENGTH;
  }

  size_t GetPrivateKeyLen() const {
    return RSASHA2562048_KEY_LENGTH * 2;
  }

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

 private:
  RSASHA2562048Verifier_Pimpl* m_Impl;
};

// RSASHA2562048Signer
class RSASHA2562048Signer_Pimpl;
class RSASHA2562048Signer : public Signer {
 public:
  explicit RSASHA2562048Signer(
      const uint8_t* signingPrivateKey);
  ~RSASHA2562048Signer();

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const;

 private:
  RSASHA2562048Signer_Pimpl* m_Impl;
};

// RSA_SHA384_3072
const size_t RSASHA3843072_KEY_LENGTH = 384;
// RSASHA3843072Verifier
class RSASHA3843072Verifier_Pimpl;
class RSASHA3843072Verifier : public Verifier {
 public:
  explicit RSASHA3843072Verifier(
      const uint8_t* signingKey);
  ~RSASHA3843072Verifier();

  size_t GetPublicKeyLen() const {
    return RSASHA3843072_KEY_LENGTH;
  }

  size_t GetSignatureLen() const {
    return RSASHA3843072_KEY_LENGTH;
  }

  size_t GetPrivateKeyLen() const {
    return RSASHA3843072_KEY_LENGTH * 2;
  }

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

 private:
  RSASHA3843072Verifier_Pimpl* m_Impl;
};

// RSASHA3843072Signer
class RSASHA3843072Signer_Pimpl;
class RSASHA3843072Signer : public Signer {
 public:
  explicit RSASHA3843072Signer(
      const uint8_t* signingPrivateKey);
  ~RSASHA3843072Signer();

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const;

 private:
  RSASHA3843072Signer_Pimpl* m_Impl;
};

// RSA_SHA512_4096
const size_t RSASHA5124096_KEY_LENGTH = 512;
// RSASHA5124096Verifier
class RSASHA5124096Verifier_Pimpl;
class RSASHA5124096Verifier : public Verifier {
 public:
  explicit RSASHA5124096Verifier(
      const uint8_t* signingKey);
  ~RSASHA5124096Verifier();

  size_t GetPublicKeyLen() const {
    return RSASHA5124096_KEY_LENGTH;
  }

  size_t GetSignatureLen() const {
    return RSASHA5124096_KEY_LENGTH;
  }

  size_t GetPrivateKeyLen() const {
    return RSASHA5124096_KEY_LENGTH * 2;
  }

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

 private:
  RSASHA5124096Verifier_Pimpl* m_Impl;
};

// RSASHA5124096Signer
class RSASHA5124096Signer_Pimpl;
class RSASHA5124096Signer : public Signer {
 public:
  explicit RSASHA5124096Signer(
      const uint8_t* signingPrivateKey);
  ~RSASHA5124096Signer();

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t * signature) const;

 private:
  RSASHA5124096Signer_Pimpl* m_Impl;
};

void CreateRSARandomKeys(
    size_t publicKeyLen,
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey);

// TODO(unassigned): ???
/*
// Raw verifiers
class RawVerifier {
 public:
  virtual ~RawVerifier() {}

  virtual void Update(
      const uint8_t* buf,
      size_t len) = 0;

  virtual bool Verify(
      const uint8_t* signature) = 0;
};

template<typename Hash, size_t keyLen>
class RSARawVerifier
    : public RawVerifier {
 public:
  RSARawVerifier(
      const uint8_t* signingKey)
      : n(signingKey, keyLen) {}

  void Update(
      const uint8_t* buf,
      size_t len) {
    m_Hash.Update(buf, len);
  }

  bool Verify(
      const uint8_t* signature) {
    // RSA encryption first
    CryptoPP::Integer enSig(
        a_exp_b_mod_c(
          CryptoPP::Integer(
            signature,
            keyLen),
          CryptoPP::Integer(
            i2p::crypto::rsae),
          n));  // s^e mod n
    uint8_t EnSigBuf[keyLen];
    enSig.Encode(EnSigBuf, keyLen);
    uint8_t digest[Hash::DIGESTSIZE];
    m_Hash.Final(digest);
    if (static_cast<int>(keyLen) < Hash::DIGESTSIZE)
      return false;  // can't verify digest longer than key
    // we assume digest is right aligned, at least for PKCS#1 v1.5 padding
    return !memcmp(
        EnSigBuf + (keyLen - Hash::DIGESTSIZE),
        digest,
        Hash::DIGESTSIZE);
  }

 private:
  CryptoPP::Integer n;  // RSA modulus
  Hash m_Hash;
};
*/

// RSASHA5124096RawVerifier
class RSASHA5124096RawVerifier_Pimpl;
class RSASHA5124096RawVerifier : public RawVerifier {
// public RSARawVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH> {
 public:
  explicit RSASHA5124096RawVerifier(
      const uint8_t* signingKey);
  ~RSASHA5124096RawVerifier();

  bool Verify(
      const uint8_t* signature);

  void Update(
      const uint8_t* signature,
      size_t len);

 private:
  RSASHA5124096RawVerifier_Pimpl* m_Impl;
};

}  // namespace crypto
}  // namespace i2p

#endif  // SRC_CORE_CRYPTO_SIGNATURE_H_
