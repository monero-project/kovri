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

#include <cryptopp/asn.h>
#include <cryptopp/dsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/integer.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <array>
#include <cstdint>
#include <memory>

#include "crypto_const.h"
#include "crypto/rand.h"
#include "util/log.h"

namespace i2p {
namespace crypto {

/**
 *
 * DSA
 *
 */

/// @class DSAVerifierImpl
/// @brief DSA verifier implementation
class DSAVerifier::DSAVerifierImpl {
 public:
  DSAVerifierImpl(
      const std::uint8_t* signing_key) {
    m_PublicKey.Initialize(
        dsap,
        dsaq,
        dsag,
        CryptoPP::Integer(
            signing_key,
            DSA_PUBLIC_KEY_LENGTH));
  }

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const {
    CryptoPP::DSA::Verifier verifier(m_PublicKey);
    return verifier.VerifyMessage(buf, len, signature, DSA_SIGNATURE_LENGTH);
  }

 private:
  CryptoPP::DSA::PublicKey m_PublicKey;
};

DSAVerifier::DSAVerifier(
    const std::uint8_t* signing_key)
    : m_DSAVerifierPimpl(
          std::make_unique<DSAVerifierImpl>(signing_key)) {}

DSAVerifier::~DSAVerifier() {}

bool DSAVerifier::Verify(
    const std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* signature) const {
  return m_DSAVerifierPimpl->Verify(buf, len, signature);
}

/// @class DSASignerImpl
/// @brief DSA signing implementation
class DSASigner::DSASignerImpl {
 public:
  DSASignerImpl(
      const std::uint8_t* private_signing_key) {
    m_PrivateKey.Initialize(
        dsap,
        dsaq,
        dsag,
        CryptoPP::Integer(
            private_signing_key,
            DSA_PRIVATE_KEY_LENGTH));
  }

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const {
    CryptoPP::DSA::Signer signer(m_PrivateKey);
    CryptoPP::AutoSeededRandomPool prng;
    try {
      signer.SignMessage(prng, buf, len, signature);
    } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError, "DSASignerImpl: Sign() caught exception '", e.what(), "'");
    }
  }

 private:
  CryptoPP::DSA::PrivateKey m_PrivateKey;
};

DSASigner::DSASigner(
    const std::uint8_t* private_signing_key)
    : m_DSASignerPimpl(
          std::make_unique<DSASignerImpl>(private_signing_key)) {}

DSASigner::~DSASigner() {}

void DSASigner::Sign(
    const std::uint8_t* buf,
    std::size_t len,
    std::uint8_t* signature) const {
  m_DSASignerPimpl->Sign(buf, len, signature);
}

// Create keys
void CreateDSARandomKeys(
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key) {
  std::array<std::uint8_t, DSA_PRIVATE_KEY_LENGTH> key_buf;
  CryptoPP::Integer dsax;
  try {
    do {
      i2p::crypto::RandBytes(key_buf.data(), DSA_PRIVATE_KEY_LENGTH);
      dsax = CryptoPP::Integer(key_buf.data(), DSA_PRIVATE_KEY_LENGTH);
    } while (dsax.IsZero() || dsax >= dsaq);
    CryptoPP::DSA::PrivateKey private_key;
    CryptoPP::DSA::PublicKey public_key;
    private_key.Initialize(dsap, dsaq, dsag, dsax);
    private_key.MakePublicKey(public_key);
    private_key.GetPrivateExponent().Encode(
        private_signing_key,
        DSA_PRIVATE_KEY_LENGTH);
    public_key.GetPublicElement().Encode(
        public_signing_key,
        DSA_PUBLIC_KEY_LENGTH);
  } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError, "CreateDSARandomKeys(): caught exception '", e.what(), "'");
  }
}

/**
 *
 * ECDSA
 *
 */


/// @class ECDSAVerifier
/// @brief ECDSA verifier base class
template<typename Hash, std::size_t KeyLen>
class ECDSAVerifier {
 public:
  template<typename Curve>
  ECDSAVerifier(
      Curve curve,
      const std::uint8_t* signing_key) {
    m_PublicKey.Initialize(
        curve,
        CryptoPP::ECP::Point(
            CryptoPP::Integer(
                signing_key,
                KeyLen / 2),
            CryptoPP::Integer(
                signing_key + KeyLen / 2,
                KeyLen / 2)));
  }

  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const {
    typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::Verifier
      verifier(m_PublicKey);
    return verifier.VerifyMessage(
        buf,
        len,
        signature,
        KeyLen);  // Signature length
  }

 private:
  typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PublicKey m_PublicKey;
};

/// @class ECDSASigner
/// @brief ECDSA signer base class
template<typename Hash>
class ECDSASigner : public Signer {
 public:
  template<typename Curve>
  ECDSASigner(
      Curve curve,
      const std::uint8_t* private_signing_key,
      std::size_t key_length) {
    m_PrivateKey.Initialize(
        curve,
        CryptoPP::Integer(
            private_signing_key,
            key_length / 2));  // Private key length
  }

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const {
    typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::Signer
      signer(m_PrivateKey);
    CryptoPP::AutoSeededRandomPool prng;
    try {
      signer.SignMessage(prng, buf, len, signature);
    } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError, "ECDSASigner: Sign() caught exception '", e.what(), "'");
    }
  }

 private:
  typedef typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PrivateKey
    SignKey;
  SignKey m_PrivateKey;
};

// Create keys
template<typename Hash, typename Curve>
inline void CreateECDSARandomKeys(
    Curve curve,
    std::size_t key_length,
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key) {
  typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PrivateKey
    private_key;
  typename CryptoPP::ECDSA<CryptoPP::ECP, Hash>::PublicKey
    public_key;
  CryptoPP::AutoSeededRandomPool prng;
  try {
    private_key.Initialize(prng, curve);
    private_key.MakePublicKey(public_key);
    private_key.GetPrivateExponent().Encode(private_signing_key, key_length / 2);
    auto q = public_key.GetPublicElement();
    q.x.Encode(public_signing_key, key_length / 2);
    q.y.Encode(public_signing_key + key_length / 2, key_length / 2);
  } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError, "CreateECDSARandomKeys(): caught exception '", e.what(), "'");
  }
}

/**
 *
 * ECDSAP256
 *
 */

/// @class ECDSAP256VerifierImpl
/// @brief ECDSAP256 verifier implementation
class ECDSAP256Verifier::ECDSAP256VerifierImpl
    : public ECDSAVerifier<CryptoPP::SHA256, ECDSAP256_KEY_LENGTH> {
 public:
  ECDSAP256VerifierImpl(
      const std::uint8_t* signing_key)
      : ECDSAVerifier(
            CryptoPP::ASN1::secp256r1(),
            signing_key) {}
};

ECDSAP256Verifier::ECDSAP256Verifier(
    const std::uint8_t* signing_key)
    : m_ECDSAP256VerifierPimpl(
          std::make_unique<ECDSAP256VerifierImpl>(signing_key)) {}

ECDSAP256Verifier::~ECDSAP256Verifier() {}

bool ECDSAP256Verifier::Verify(
    const std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* signature) const {
  return m_ECDSAP256VerifierPimpl->Verify(buf, len, signature);
}

/// @class ECDSAP256SignerImpl
/// @brief ECDSAP256 signing implementation
class ECDSAP256Signer::ECDSAP256SignerImpl
    : public ECDSASigner<CryptoPP::SHA256> {
 public:
  ECDSAP256SignerImpl(
      const std::uint8_t* private_signing_key)
      : ECDSASigner(
            CryptoPP::ASN1::secp256r1(),
            private_signing_key,
            ECDSAP256_KEY_LENGTH) {}
};

ECDSAP256Signer::ECDSAP256Signer(
    const std::uint8_t* private_signing_key)
    : m_ECDSAP256SignerPimpl(
          std::make_unique<ECDSAP256SignerImpl>(private_signing_key)) {}

ECDSAP256Signer::~ECDSAP256Signer() {}

void ECDSAP256Signer::Sign(
    const std::uint8_t* buf,
    std::size_t len,
    std::uint8_t* signature) const {
  m_ECDSAP256SignerPimpl->Sign(buf, len, signature);
}

// Create keys
void CreateECDSAP256RandomKeys(
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key) {
  CreateECDSARandomKeys<CryptoPP::SHA256>(
      CryptoPP::ASN1::secp256r1(),
      ECDSAP256_KEY_LENGTH,
      private_signing_key,
      public_signing_key);
}

/**
 *
 * ECDSAP384
 *
 */

/// @class ECDSAP384VerifierImpl
/// @brief ECDSAP384 verifier implementation
class ECDSAP384Verifier::ECDSAP384VerifierImpl
    : public ECDSAVerifier<CryptoPP::SHA384, ECDSAP384_KEY_LENGTH> {
 public:
  ECDSAP384VerifierImpl(
      const std::uint8_t* signing_key)
      : ECDSAVerifier(
            CryptoPP::ASN1::secp384r1(),
            signing_key) {}
};

ECDSAP384Verifier::ECDSAP384Verifier(
    const std::uint8_t* signing_key)
    : m_ECDSAP384VerifierPimpl(
          std::make_unique<ECDSAP384VerifierImpl>(signing_key)) {}

ECDSAP384Verifier::~ECDSAP384Verifier() {}

bool ECDSAP384Verifier::Verify(
    const std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* signature) const {
  return m_ECDSAP384VerifierPimpl->Verify(buf, len, signature);
}

/// @class ECDSAP384SignerImpl
/// @brief ECDSAP384 signing implementation
class ECDSAP384Signer::ECDSAP384SignerImpl
    : public ECDSASigner<CryptoPP::SHA384> {
 public:
  ECDSAP384SignerImpl(
      const std::uint8_t* private_signing_key)
      : ECDSASigner(
            CryptoPP::ASN1::secp384r1(),
            private_signing_key,
            ECDSAP384_KEY_LENGTH) {}
};

ECDSAP384Signer::ECDSAP384Signer(
    const std::uint8_t* private_signing_key)
    : m_ECDSAP384SignerPimpl(
          std::make_unique<ECDSAP384SignerImpl>(private_signing_key)) {}

ECDSAP384Signer::~ECDSAP384Signer() {}

void ECDSAP384Signer::Sign(
    const std::uint8_t* buf,
    std::size_t len,
    std::uint8_t * signature) const {
  m_ECDSAP384SignerPimpl->Sign(buf, len, signature);
}

// Create keys
void CreateECDSAP384RandomKeys(
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key) {
  CreateECDSARandomKeys<CryptoPP::SHA384>(
      CryptoPP::ASN1::secp384r1(),
      ECDSAP384_KEY_LENGTH,
      private_signing_key,
      public_signing_key);
}

/**
 *
 * ECDSAP521
 *
 */
/// @class ECDSAP521VerifierImpl
/// @brief ECDSAP521 verifier implementation
class ECDSAP521Verifier::ECDSAP521VerifierImpl
    : public ECDSAVerifier<CryptoPP::SHA512, ECDSAP521_KEY_LENGTH> {
 public:
  ECDSAP521VerifierImpl(
      const std::uint8_t* signing_key)
      : ECDSAVerifier(
            CryptoPP::ASN1::secp521r1(),
            signing_key) {}
};

ECDSAP521Verifier::ECDSAP521Verifier(
    const std::uint8_t* signing_key)
    : m_ECDSAP521VerifierPimpl(
          std::make_unique<ECDSAP521VerifierImpl>(signing_key)) {}

ECDSAP521Verifier::~ECDSAP521Verifier() {}

bool ECDSAP521Verifier::Verify(
    const std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* signature) const {
  return m_ECDSAP521VerifierPimpl->Verify(buf, len, signature);
}

/// @class ECDSAP521SignerImpl
/// @brief ECDSAP521 signing implementation
class ECDSAP521Signer::ECDSAP521SignerImpl
    : public ECDSASigner<CryptoPP::SHA512> {
 public:
  ECDSAP521SignerImpl(
      const std::uint8_t* private_signing_key)
      : ECDSASigner(
            CryptoPP::ASN1::secp521r1(),
            private_signing_key,
            ECDSAP521_KEY_LENGTH) {}
};

ECDSAP521Signer::ECDSAP521Signer(
    const std::uint8_t* private_signing_key)
    : m_ECDSAP521SignerPimpl(
          std::make_unique<ECDSAP521SignerImpl>(private_signing_key)) {}

ECDSAP521Signer::~ECDSAP521Signer() {}

void ECDSAP521Signer::Sign(
    const std::uint8_t* buf,
    std::size_t len,
    std::uint8_t* signature) const {
  m_ECDSAP521SignerPimpl->Sign(buf, len, signature);
}

// Create keys
void CreateECDSAP521RandomKeys(
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key) {
  CreateECDSARandomKeys<CryptoPP::SHA512>(
      CryptoPP::ASN1::secp521r1(),
      ECDSAP521_KEY_LENGTH,
      private_signing_key,
      public_signing_key);
}

/**
 *
 * RSA
 *
 */

/// @class RSAVerifier
/// @brief RSA verifier base class
template<typename Hash, std::size_t KeyLen>
class RSAVerifier {
 public:
  explicit RSAVerifier(
  const std::uint8_t* signing_key) {
    m_PublicKey.Initialize(
        CryptoPP::Integer(
            signing_key,
            KeyLen),
        CryptoPP::Integer(
            rsae));
  }
  bool Verify(
      const std::uint8_t* buf,
      std::size_t len,
      const std::uint8_t* signature) const {
    typename CryptoPP::RSASS<CryptoPP::PKCS1v15, Hash>::Verifier
      verifier(m_PublicKey);
    return verifier.VerifyMessage(
        buf,
        len,
        signature,
        KeyLen);  // Signature length
  }

 private:
  CryptoPP::RSA::PublicKey m_PublicKey;
};

/// @class RSASigner
/// @brief RSA signing base class
template<typename Hash>
class RSASigner {
 public:
  RSASigner(
      const std::uint8_t* private_signing_key,
      std::size_t key_length) {
    m_PrivateKey.Initialize(
        CryptoPP::Integer(
            private_signing_key,
            key_length / 2),
            rsae,
            CryptoPP::Integer(
                private_signing_key + key_length / 2,
                key_length / 2));
  }

  void Sign(
      const std::uint8_t* buf,
      std::size_t len,
      std::uint8_t* signature) const {
    CryptoPP::AutoSeededRandomPool prng;
    typename CryptoPP::RSASS<CryptoPP::PKCS1v15, Hash>::Signer
      signer(m_PrivateKey);
    try {
      signer.SignMessage(prng, buf, len, signature);
    } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError, "RSASigner: Sign() caught exception '", e.what(), "'");
    }
  }

 private:
  CryptoPP::RSA::PrivateKey m_PrivateKey;
};

// Create keys
void CreateRSARandomKeys(
    std::size_t public_key_length,
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key) {
  CryptoPP::RSA::PrivateKey private_key;
  CryptoPP::AutoSeededRandomPool prng;
  try {
    private_key.Initialize(
        prng,
        public_key_length * 8,
        rsae);
    private_key.GetModulus().Encode(
        private_signing_key,
        public_key_length);
    private_key.GetPrivateExponent().Encode(
        private_signing_key + public_key_length,
        public_key_length);
    private_key.GetModulus().Encode(
        public_signing_key,
        public_key_length);
  } catch (CryptoPP::Exception& e) {
    LogPrint(eLogError, "CreateRSARandomKeys(): caught exception '", e.what(), "'");
  }
}

/**
 *
 * RSASHA2562048
 *
 */

/// @class RSASHA2562048VerifierImpl
/// @brief RSASHA2562048 verifier implementation
class RSASHA2562048Verifier::RSASHA2562048VerifierImpl
    : public RSAVerifier<CryptoPP::SHA256, RSASHA2562048_KEY_LENGTH> {
 public:
  explicit RSASHA2562048VerifierImpl(
      const std::uint8_t* public_key)
      : RSAVerifier<CryptoPP::SHA256, RSASHA2562048_KEY_LENGTH>(public_key) {}
};

RSASHA2562048Verifier::RSASHA2562048Verifier(
    const std::uint8_t* pubKey)
    : m_RSASHA2562048VerifierPimpl(
          std::make_unique<RSASHA2562048VerifierImpl>(pubKey)) {}

RSASHA2562048Verifier::~RSASHA2562048Verifier() {}

bool RSASHA2562048Verifier::Verify(
    const std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* signature) const {
  return m_RSASHA2562048VerifierPimpl->Verify(buf, len, signature);
}

/// @class RSASHA2562048SignerImpl
/// @brief RSASHA2562048 signing implementation
class RSASHA2562048Signer::RSASHA2562048SignerImpl
    : public RSASigner<CryptoPP::SHA256> {
 public:
  RSASHA2562048SignerImpl(
      const std::uint8_t* privkey)
      : RSASigner<CryptoPP::SHA256>(privkey, RSASHA2562048_KEY_LENGTH * 2) {}
};

RSASHA2562048Signer::RSASHA2562048Signer(
    const std::uint8_t* private_key)
    : m_RSASHA2562048SignerPimpl(
          std::make_unique<RSASHA2562048SignerImpl>(private_key)) {}

RSASHA2562048Signer::~RSASHA2562048Signer() {}

void RSASHA2562048Signer::Sign(
    const std::uint8_t* buf,
    std::size_t len,
    std::uint8_t* signature) const {
  m_RSASHA2562048SignerPimpl->Sign(buf, len, signature);
}

/**
 *
 * RSASHA3843072
 *
 */

/// @class RSASHA3843072VerifierImpl
/// @brief RSASHA3843072 verifier implementation
class RSASHA3843072Verifier::RSASHA3843072VerifierImpl
    : public RSAVerifier<CryptoPP::SHA384, RSASHA3843072_KEY_LENGTH> {
 public:
  explicit RSASHA3843072VerifierImpl(
      const std::uint8_t* public_key)
      : RSAVerifier<CryptoPP::SHA384, RSASHA3843072_KEY_LENGTH>(public_key) {}
};

RSASHA3843072Verifier::RSASHA3843072Verifier(
    const std::uint8_t* pubKey)
    : m_RSASHA3843072VerifierPimpl(
          std::make_unique<RSASHA3843072VerifierImpl>(pubKey)) {}

RSASHA3843072Verifier::~RSASHA3843072Verifier() {}

bool RSASHA3843072Verifier::Verify(
    const std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* signature) const {
  return m_RSASHA3843072VerifierPimpl->Verify(buf, len, signature);
}

/// @class RSASHA3843072SignerImpl
/// @brief RSASHA3843072 signing implementation
class RSASHA3843072Signer::RSASHA3843072SignerImpl
    : public RSASigner<CryptoPP::SHA384> {
 public:
  RSASHA3843072SignerImpl(
      const std::uint8_t* privkey)
      : RSASigner<CryptoPP::SHA384>(privkey, RSASHA3843072_KEY_LENGTH * 2) {}
};

RSASHA3843072Signer::RSASHA3843072Signer(
    const std::uint8_t* private_key)
    : m_RSASHA3843072SignerPimpl(
          std::make_unique<RSASHA3843072SignerImpl>(private_key)) {}

RSASHA3843072Signer::~RSASHA3843072Signer() {}

void RSASHA3843072Signer::Sign(
    const std::uint8_t* buf,
    std::size_t len,
    std::uint8_t* signature) const {
  m_RSASHA3843072SignerPimpl->Sign(buf, len, signature);
}

/**
 *
 * RSASHA5124096
 *
 */

/// @class RSASHA5124096VerifierImpl
/// @brief RSASHA5124096 verifier implementation
class RSASHA5124096Verifier::RSASHA5124096VerifierImpl
    : public RSAVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH> {
 public:
  RSASHA5124096VerifierImpl(
      const std::uint8_t* public_key)
      : RSAVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH>(public_key) {}
};

RSASHA5124096Verifier::RSASHA5124096Verifier(
    const std::uint8_t* pubKey)
    : m_RSASHA5124096VerifierPimpl(
        std::make_unique<RSASHA5124096VerifierImpl>(pubKey)) {}

RSASHA5124096Verifier::~RSASHA5124096Verifier() {}

bool RSASHA5124096Verifier::Verify(
    const std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* signature) const {
  return m_RSASHA5124096VerifierPimpl->Verify(buf, len, signature);
}

/// @class RSASHA5124096SignerImpl
/// @brief RSASHA5124096 signing implementation
class RSASHA5124096Signer::RSASHA5124096SignerImpl
    : public RSASigner<CryptoPP::SHA512> {
 public:
  RSASHA5124096SignerImpl(
      const std::uint8_t* privkey)
      : RSASigner<CryptoPP::SHA512>(privkey, RSASHA5124096_KEY_LENGTH * 2) {}
};

RSASHA5124096Signer::RSASHA5124096Signer(
    const std::uint8_t* private_key)
    : m_RSASHA5124096SignerPimpl(
          std::make_unique<RSASHA5124096SignerImpl>(private_key)) {}

RSASHA5124096Signer::~RSASHA5124096Signer() {}

void RSASHA5124096Signer::Sign(
    const std::uint8_t* buf,
    std::size_t len,
    std::uint8_t* signature) const {
  m_RSASHA5124096SignerPimpl->Sign(buf, len, signature);
}

/**
 *
 * RSARaw
 *
 */

/// @class RSARawVerifier
/// @brief RSA raw verifier base class
template<typename Hash, std::size_t key_length>
class RSARawVerifier {
 public:
  RSARawVerifier(
      const std::uint8_t* signing_key)
      : n(signing_key, key_length) {}

  void Update(
      const std::uint8_t* buf,
      std::size_t len) {
    m_Hash.Update(buf, len);
  }

  bool Verify(
      const std::uint8_t* signature) {
    // RSA encryption first
    CryptoPP::Integer enSig(
    a_exp_b_mod_c(
      CryptoPP::Integer(
          signature,
          key_length),
      CryptoPP::Integer(
          i2p::crypto::rsae),
      n));  // s^e mod n
    std::uint8_t EnSigBuf[key_length];
    enSig.Encode(EnSigBuf, key_length);
    std::uint8_t digest[Hash::DIGESTSIZE];
    m_Hash.Final(digest);
    if (static_cast<int>(key_length) < Hash::DIGESTSIZE)
      return false;  // Can't verify digest longer than key
    // We assume digest is right aligned, at least for PKCS#1 v1.5 padding
    return !memcmp(
        EnSigBuf + (key_length - Hash::DIGESTSIZE),
        digest,
        Hash::DIGESTSIZE);
}

 private:
  CryptoPP::Integer n;  // RSA modulus
  Hash m_Hash;
};

/**
 *
 * RSASHA5124096Raw
 *
 */

/// @class RSASHA5124096RawVerifierImpl
/// @brief RSASHA5124096 verifier implementation
class RSASHA5124096RawVerifier::RSASHA5124096RawVerifierImpl
    : public RSARawVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH> {
 public:
  RSASHA5124096RawVerifierImpl(
      const std::uint8_t* signing_key)
      : RSARawVerifier<CryptoPP::SHA512, RSASHA5124096_KEY_LENGTH>(signing_key) {}
};

RSASHA5124096RawVerifier::RSASHA5124096RawVerifier(
    const std::uint8_t* signing_key)
    : m_RSASHA5124096RawVerifierPimpl(
          std::make_unique<RSASHA5124096RawVerifierImpl>(signing_key)) {}

RSASHA5124096RawVerifier::~RSASHA5124096RawVerifier() {}

void RSASHA5124096RawVerifier::Update(
    const std::uint8_t* buf,
    std::size_t len) {
  m_RSASHA5124096RawVerifierPimpl->Update(buf, len);
}

bool RSASHA5124096RawVerifier::Verify(
    const std::uint8_t* signature) {
  return m_RSASHA5124096RawVerifierPimpl->Verify(signature);
}

}  // namespace crypto
}  // namespace i2p
