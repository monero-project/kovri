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

#ifndef SRC_CORE_CRYPTO_CRYPTOPP_IMPL_H_
#define SRC_CORE_CRYPTO_CRYPTOPP_IMPL_H_

// CryptoPP Pimpl definitions

#include <cryptopp/asn.h>
#include <cryptopp/dsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/integer.h>
#include <cryptopp/oids.h>
#include <cryptopp/rsa.h>

#include "CryptoPP_Rand.h"
#include "Signature.h"

namespace i2p {
namespace crypto {

class DSAVerifier_Pimpl {
 public:
  DSAVerifier_Pimpl(
      const uint8_t* signingKey);

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

 private:
  CryptoPP::DSA::PublicKey m_PublicKey;
};

class DSASigner_Pimpl {
 public:
  DSASigner_Pimpl(
      const uint8_t* signingPrivateKey);

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const;

 private:
  CryptoPP::DSA::PrivateKey m_PrivateKey;
};

template<typename Hash, size_t keyLen>
class ECDSAVerifier {
 public:
  template<typename Curve>
  ECDSAVerifier(
      Curve curve,
      const uint8_t* signingKey) {
    m_PublicKey.Initialize(
        curve,
        CryptoPP::ECP::Point(
            CryptoPP::Integer(
                signingKey,
                keyLen / 2),
            CryptoPP::Integer(
              signingKey + keyLen / 2,
              keyLen / 2)));
  }

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t * signature) const {
    typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::Verifier
      verifier(m_PublicKey);
    return verifier.VerifyMessage(
        buf, len, signature, keyLen);  // signature length
  }

 private:
  typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PublicKey m_PublicKey;
};


template<typename Hash>
class ECDSASigner : public Signer {
 public:
  template<typename Curve>
  ECDSASigner(
      Curve curve,
      const uint8_t* signingPrivateKey,
      size_t keyLen) {
    m_PrivateKey.Initialize(
        curve,
        CryptoPP::Integer(
          signingPrivateKey,
          keyLen / 2));  // private key length
  }

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const {
    typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::Signer
      signer(m_PrivateKey);
    PRNG rnd;
    signer.SignMessage(rnd, buf, len, signature);
  }

 private:
  typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PrivateKey
    m_PrivateKey;
};

template<typename Hash, typename Curve>
inline void CreateECDSARandomKeys(
    Curve curve,
    size_t keyLen,
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey) {
  typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PrivateKey
    privateKey;
  typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PublicKey
    publicKey;
  PRNG rnd;
  privateKey.Initialize(rnd, curve);
  privateKey.MakePublicKey(publicKey);
  privateKey.GetPrivateExponent().Encode(signingPrivateKey, keyLen / 2);
  auto q = publicKey.GetPublicElement();
  q.x.Encode(signingPublicKey, keyLen / 2);
  q.y.Encode(signingPublicKey + keyLen / 2, keyLen / 2);
}

class ECDSAP256Verifier_Pimpl
    : public ECDSAVerifier<CryptoPP::SHA256, ECDSAP256_KEY_LENGTH> {
 public:
  ECDSAP256Verifier_Pimpl(
      const uint8_t* signingKey)
      : ECDSAVerifier(
          CryptoPP::ASN1::secp256r1(),
          signingKey) {}
};

class ECDSAP256Signer_Pimpl
    : public ECDSASigner<CryptoPP::SHA256> {
 public:
  ECDSAP256Signer_Pimpl(
      const uint8_t* signingPrivateKey)
      : ECDSASigner(
          CryptoPP::ASN1::secp256r1(),
          signingPrivateKey,
          ECDSAP256_KEY_LENGTH) {}
};

class ECDSAP384Verifier_Pimpl
    : public ECDSAVerifier<CryptoPP::SHA384, ECDSAP384_KEY_LENGTH> {
 public:
  ECDSAP384Verifier_Pimpl(
      const uint8_t* signingKey)
      : ECDSAVerifier(
          CryptoPP::ASN1::secp384r1(),
          signingKey) {}
};

class ECDSAP384Signer_Pimpl
    : public ECDSASigner<CryptoPP::SHA384> {
 public:
  ECDSAP384Signer_Pimpl(
      const uint8_t* signingPrivateKey)
      : ECDSASigner(
          CryptoPP::ASN1::secp384r1(),
          signingPrivateKey,
          ECDSAP384_KEY_LENGTH) {}
};

class ECDSAP521Verifier_Pimpl
    : public ECDSAVerifier<CryptoPP::SHA512, ECDSAP521_KEY_LENGTH> {
 public:
  ECDSAP521Verifier_Pimpl(
      const uint8_t* signingKey)
      : ECDSAVerifier(
          CryptoPP::ASN1::secp521r1(),
          signingKey) {}
};

class ECDSAP521Signer_Pimpl
    : public ECDSASigner<CryptoPP::SHA512> {
 public:
  ECDSAP521Signer_Pimpl(
      const uint8_t* signingPrivateKey)
      : ECDSASigner(
          CryptoPP::ASN1::secp521r1(),
          signingPrivateKey,
          ECDSAP521_KEY_LENGTH) {}
};

template<typename Hash, size_t keyLen>
class RSAVerifier {
 public:
  explicit RSAVerifier(
  const uint8_t* signingKey) {
    m_PublicKey.Initialize(
        CryptoPP::Integer(
            signingKey,
            keyLen),
        CryptoPP::Integer(
          rsae));
  }
  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const {
    typename CryptoPP::RSASS<CryptoPP::PKCS1v15, Hash>::Verifier
      verifier(m_PublicKey);
    // signature length
    return verifier.VerifyMessage(buf, len, signature, keyLen);
  }

 private:
  CryptoPP::RSA::PublicKey m_PublicKey;
};


template<typename Hash>
class RSASigner {
 public:
  RSASigner(
      const uint8_t* signingPrivateKey,
      size_t keyLen) {
    m_PrivateKey.Initialize(
        CryptoPP::Integer(
            signingPrivateKey,
            keyLen / 2),
            rsae,
            CryptoPP::Integer(
                signingPrivateKey + keyLen / 2,
                keyLen / 2));
  }

  void Sign(
      const uint8_t* buf,
      size_t len,
      uint8_t* signature) const {
    PRNG rnd;
    typename CryptoPP::RSASS<CryptoPP::PKCS1v15, Hash>::Signer
      signer(m_PrivateKey);
    signer.SignMessage(rnd, buf, len, signature);
  }

 private:
  CryptoPP::RSA::PrivateKey m_PrivateKey;
};


class RSASHA2562048Verifier_Pimpl
    : public RSAVerifier<CryptoPP::SHA256, RSASHA2562048_KEY_LENGTH> {
 public:
  explicit RSASHA2562048Verifier_Pimpl(
      const uint8_t* pubkey)
      : RSAVerifier<CryptoPP::SHA256, RSASHA2562048_KEY_LENGTH>(pubkey) {}
};

class RSASHA3843072Verifier_Pimpl
    : public RSAVerifier<CryptoPP::SHA384, RSASHA3843072_KEY_LENGTH> {
 public:
  explicit RSASHA3843072Verifier_Pimpl(
      const uint8_t* pubkey)
      : RSAVerifier<CryptoPP::SHA384, RSASHA3843072_KEY_LENGTH>(pubkey) {}
};

class RSASHA5124096Verifier_Pimpl
    : public RSAVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH> {
 public:
  RSASHA5124096Verifier_Pimpl(
      const uint8_t* pubkey)
      : RSAVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH>(pubkey) {}
};

class RSASHA2562048Signer_Pimpl
    : public RSASigner<CryptoPP::SHA256> {
 public:
  RSASHA2562048Signer_Pimpl(
      const uint8_t* privkey)
      : RSASigner<CryptoPP::SHA256>(privkey, RSASHA2562048_KEY_LENGTH * 2) {}
};

class RSASHA3843072Signer_Pimpl
    : public RSASigner<CryptoPP::SHA384> {
 public:
  RSASHA3843072Signer_Pimpl(
      const uint8_t* privkey)
      : RSASigner<CryptoPP::SHA384>(privkey, RSASHA3843072_KEY_LENGTH * 2) {}
};

class RSASHA5124096Signer_Pimpl
    : public RSASigner<CryptoPP::SHA512> {
 public:
  RSASHA5124096Signer_Pimpl(
      const uint8_t* privkey)
      : RSASigner<CryptoPP::SHA512>(privkey, RSASHA5124096_KEY_LENGTH * 2) {}
};

template<typename Hash, size_t keyLen>
class RSARawVerifier {
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


class RSASHA5124096RawVerifier_Pimpl
    : public RSARawVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH> {
 public:
  RSASHA5124096RawVerifier_Pimpl(
      const uint8_t* signingKey)
      : RSARawVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH>(signingKey) {}
};

}  // namespace crypto
}  // namespace i2p

#endif  // SRC_CORE_CRYPTO_CRYPTOPP_IMPL_H_
