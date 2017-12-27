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

#include "core/crypto/signature.h"

#include <cryptopp/asn.h>
#include <cryptopp/dsa.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/integer.h>
#include <cryptopp/oids.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "crypto_const.h"

#include "core/crypto/rand.h"

#include "core/util/log.h"

namespace kovri {
namespace core {

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


// Create keys
void CreateRSARandomKeys(
    std::size_t public_key_length,
    std::uint8_t* private_signing_key,
    std::uint8_t* public_signing_key) {
  CryptoPP::RSA::PrivateKey private_key;
  CryptoPP::AutoSeededRandomPool prng;
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
      : m_Modulus(signing_key, key_length) {}

  void Update(
      const std::uint8_t* buf,
      std::size_t len) {
    m_Hash.Update(buf, len);
  }

  bool Verify(
      const std::uint8_t* signature) {
    // RSA encryption first
    CryptoPP::Integer encrypted_signature(
        a_exp_b_mod_c(
            CryptoPP::Integer(signature, key_length),
            CryptoPP::Integer(kovri::core::rsae),
            m_Modulus));  // s^e mod n
    std::vector<std::uint8_t> buf(key_length);
    encrypted_signature.Encode(buf.data(), buf.size());
    std::array<std::uint8_t, Hash::DIGESTSIZE> digest {{}};
    m_Hash.Final(digest.data());
    if (buf.size() < Hash::DIGESTSIZE)
      return false;  // Can't verify digest longer than key
    // We assume digest is right aligned, at least for PKCS#1 v1.5 padding
    return !std::memcmp(
        buf.data() + (buf.size() - Hash::DIGESTSIZE),
        digest.data(),
        Hash::DIGESTSIZE);
}

 private:
  /// @brief RSA modulus 'n'
  CryptoPP::Integer m_Modulus;
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

}  // namespace core
}  // namespace kovri
