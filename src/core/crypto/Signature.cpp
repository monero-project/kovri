/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
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
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#include "Signature.h"

#include "CryptoConst.h"
#include "CryptoPP_Impl.h"
#include "Rand.h"

#include <memory>

#include "util/Log.h"

namespace i2p {
namespace crypto {

// DSA
DSAVerifier::DSAVerifier(
    const uint8_t* signingKey)
    : m_Impl(
        new DSAVerifier_Pimpl(signingKey)) {}

DSAVerifier::~DSAVerifier() {
  delete m_Impl;
}

bool DSAVerifier::Verify(
    const uint8_t* buf,
    size_t len,
    const uint8_t* signature) const {
  return m_Impl->Verify(buf, len, signature);
}

DSASigner::DSASigner(
    const uint8_t* signingPrivateKey)
    : m_Impl(
        new DSASigner_Pimpl(signingPrivateKey)) {}

DSASigner::~DSASigner() {
  delete m_Impl;
}

void DSASigner::Sign(
    const uint8_t* buf,
    size_t len,
    uint8_t* signature) const {
  m_Impl->Sign(buf, len, signature);
}

DSASigner_Pimpl::DSASigner_Pimpl(
    const uint8_t* signingPrivateKey) {
  m_PrivateKey.Initialize(
      dsap,
      dsaq,
      dsag,
      CryptoPP::Integer(
          signingPrivateKey,
          DSA_PRIVATE_KEY_LENGTH));
}
DSASigner_Pimpl::~DSASigner_Pimpl() {}

void DSASigner_Pimpl::Sign(
    const uint8_t* buf,
    size_t len,
    uint8_t* signature) const {
  CryptoPP::DSA::Signer signer(m_PrivateKey);
  PRNG& r = prng;
  signer.SignMessage(r, buf, len, signature);
}

void CreateDSARandomKeys(
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey) {
  uint8_t keybuff[DSA_PRIVATE_KEY_LENGTH];
  CryptoPP::Integer dsax;
  do {
    i2p::crypto::RandBytes(keybuff, DSA_PRIVATE_KEY_LENGTH);
    dsax = CryptoPP::Integer(keybuff, DSA_PRIVATE_KEY_LENGTH);
  } while(dsax.IsZero() || dsax >= dsaq);
  CryptoPP::DSA::PrivateKey privateKey;
  CryptoPP::DSA::PublicKey publicKey;
  privateKey.Initialize(dsap, dsaq, dsag, dsax);
  privateKey.MakePublicKey(publicKey);
  privateKey.GetPrivateExponent().Encode(
      signingPrivateKey,
      DSA_PRIVATE_KEY_LENGTH);
  publicKey.GetPublicElement().Encode(
      signingPublicKey,
      DSA_PUBLIC_KEY_LENGTH);
}

DSAVerifier_Pimpl::DSAVerifier_Pimpl(
    const uint8_t* signingKey) {
  m_PublicKey.Initialize(
      dsap,
      dsaq,
      dsag,
      CryptoPP::Integer(
          signingKey,
          DSA_PUBLIC_KEY_LENGTH));
}

bool DSAVerifier_Pimpl::Verify(
    const uint8_t* buf,
    size_t len,
    const uint8_t* signature) const {
  CryptoPP::DSA::Verifier verifier(m_PublicKey);
  return verifier.VerifyMessage(buf, len, signature, DSA_SIGNATURE_LENGTH);
}

// ECDSAP256
ECDSAP256Verifier::ECDSAP256Verifier(
    const uint8_t* signingKey)
    : m_Impl(
        new ECDSAP256Verifier_Pimpl(signingKey)) {}

ECDSAP256Verifier::~ECDSAP256Verifier() {
  delete m_Impl;
}

bool ECDSAP256Verifier::Verify(
    const uint8_t* buf,
    size_t len,
    const uint8_t* signature) const {
  return m_Impl->Verify(buf, len, signature);
}

ECDSAP256Signer::ECDSAP256Signer(
    const uint8_t* signingPrivateKey)
    : m_Impl(
        new ECDSAP256Signer_Pimpl(signingPrivateKey)) {}

ECDSAP256Signer::~ECDSAP256Signer() {
  delete m_Impl;
}

void ECDSAP256Signer::Sign(
    const uint8_t* buf,
    size_t len,
    uint8_t* signature) const {
  m_Impl->Sign(buf, len, signature);
}

// ECDSAP384
ECDSAP384Verifier::ECDSAP384Verifier(
    const uint8_t* signingKey)
    : m_Impl(
        new ECDSAP384Verifier_Pimpl(signingKey)) {}

ECDSAP384Verifier::~ECDSAP384Verifier() {
  delete m_Impl;
}

bool ECDSAP384Verifier::Verify(
    const uint8_t* buf,
    size_t len,
    const uint8_t* signature) const {
  return m_Impl->Verify(buf, len, signature);
}

ECDSAP384Signer::ECDSAP384Signer(
    const uint8_t* signingPrivateKey)
    : m_Impl(
        new ECDSAP384Signer_Pimpl(signingPrivateKey)) {}

ECDSAP384Signer::~ECDSAP384Signer() {
  delete m_Impl;
}

void ECDSAP384Signer::Sign(
    const uint8_t* buf,
    size_t len,
    uint8_t * signature) const {
  m_Impl->Sign(buf, len, signature);
}

// ECDSAP521
ECDSAP521Verifier::ECDSAP521Verifier(
    const uint8_t* signingKey)
    : m_Impl(
        new ECDSAP521Verifier_Pimpl(signingKey)) {}

ECDSAP521Verifier::~ECDSAP521Verifier() {
  delete m_Impl;
}

bool ECDSAP521Verifier::Verify(
    const uint8_t* buf,
    size_t len,
    const uint8_t* signature) const {
  return m_Impl->Verify(buf, len, signature);
}

ECDSAP521Signer::ECDSAP521Signer(
    const uint8_t* signingPrivateKey)
    : m_Impl(
        new ECDSAP521Signer_Pimpl(signingPrivateKey)) {}

ECDSAP521Signer::~ECDSAP521Signer() {
  delete m_Impl;
}

void ECDSAP521Signer::Sign(
    const uint8_t* buf,
    size_t len,
    uint8_t* signature) const {
  m_Impl->Sign(buf, len, signature);
}

// ECDSAP256
void CreateECDSAP256RandomKeys(
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey) {
  CreateECDSARandomKeys<CryptoPP::SHA256>(
      CryptoPP::ASN1::secp256r1(),
      ECDSAP256_KEY_LENGTH,
      signingPrivateKey,
      signingPublicKey);
}

// ECDSAP384
void CreateECDSAP384RandomKeys(
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey) {
  CreateECDSARandomKeys<CryptoPP::SHA384>(
      CryptoPP::ASN1::secp384r1(),
      ECDSAP384_KEY_LENGTH,
      signingPrivateKey,
      signingPublicKey);
}

// ECDSAP521
void CreateECDSAP521RandomKeys(
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey) {
  CreateECDSARandomKeys<CryptoPP::SHA512>(
      CryptoPP::ASN1::secp521r1(),
      ECDSAP521_KEY_LENGTH,
      signingPrivateKey,
      signingPublicKey);
}

// RSA
void CreateRSARandomKeys(
    size_t publicKeyLen,
    uint8_t* signingPrivateKey,
    uint8_t* signingPublicKey) {
  CryptoPP::RSA::PrivateKey privateKey;
  privateKey.Initialize(
      prng,
      publicKeyLen * 8,
      rsae);
  privateKey.GetModulus().Encode(
      signingPrivateKey,
      publicKeyLen);
  privateKey.GetPrivateExponent().Encode(
      signingPrivateKey + publicKeyLen,
      publicKeyLen);
  privateKey.GetModulus().Encode(
      signingPublicKey,
      publicKeyLen);
  }

// RSASHA2562048
RSASHA2562048Signer::RSASHA2562048Signer(
    const uint8_t* privateKey)
    : m_Impl(
        new RSASHA2562048Signer_Pimpl(privateKey)) {}

RSASHA2562048Signer::~RSASHA2562048Signer() {
  delete m_Impl;
}

void RSASHA2562048Signer::Sign(
    const uint8_t* buf,
    size_t len,
    uint8_t* signature) const {
  m_Impl->Sign(buf, len, signature);
}

// RSASHA3843072
RSASHA3843072Signer::RSASHA3843072Signer(
    const uint8_t* privateKey)
    : m_Impl(
        new RSASHA3843072Signer_Pimpl(privateKey)) {}

RSASHA3843072Signer::~RSASHA3843072Signer() {
  delete m_Impl;
}

void RSASHA3843072Signer::Sign(
    const uint8_t* buf,
    size_t len,
    uint8_t* signature) const {
  m_Impl->Sign(buf, len, signature);
}

// RSASHA5124096
RSASHA5124096Signer::RSASHA5124096Signer(
    const uint8_t* privateKey)
    : m_Impl(
        new RSASHA5124096Signer_Pimpl(privateKey)) {}

RSASHA5124096Signer::~RSASHA5124096Signer() {
  delete m_Impl;
}

void RSASHA5124096Signer::Sign(
    const uint8_t* buf,
    size_t len,
    uint8_t* signature) const {
  m_Impl->Sign(buf, len, signature);
}

// RSASHA2562048
RSASHA2562048Verifier::RSASHA2562048Verifier(
    const uint8_t* pubKey)
    : m_Impl(
        new RSASHA2562048Verifier_Pimpl(pubKey)) {}

RSASHA2562048Verifier::~RSASHA2562048Verifier() {
  delete m_Impl;
}

bool RSASHA2562048Verifier::Verify(
    const uint8_t* buf,
    size_t len,
    const uint8_t* signature) const {
  return m_Impl->Verify(buf, len, signature);
}

// RSASHA3843072
RSASHA3843072Verifier::RSASHA3843072Verifier(
    const uint8_t* pubKey)
    : m_Impl(
        new RSASHA3843072Verifier_Pimpl(pubKey)) {}

RSASHA3843072Verifier::~RSASHA3843072Verifier() {
  delete m_Impl;
}

bool RSASHA3843072Verifier::Verify(
    const uint8_t* buf,
    size_t len,
    const uint8_t* signature) const {
  return m_Impl->Verify(buf, len, signature);
}

// RSASHA5124096
RSASHA5124096Verifier::RSASHA5124096Verifier(
    const uint8_t* pubKey)
    : m_Impl(
        new RSASHA5124096Verifier_Pimpl(pubKey)) {}

RSASHA5124096Verifier::~RSASHA5124096Verifier() {
  delete m_Impl;
}

bool RSASHA5124096Verifier::Verify(
    const uint8_t* buf,
    size_t len,
    const uint8_t* signature) const {
  return m_Impl->Verify(buf, len, signature);
}

// RSASHA5124096
RSASHA5124096RawVerifier::RSASHA5124096RawVerifier(
    const uint8_t* signingKey)
    : m_Impl(
        new RSASHA5124096RawVerifier_Pimpl(signingKey)) {}

RSASHA5124096RawVerifier::~RSASHA5124096RawVerifier() {
  delete m_Impl;
}

void RSASHA5124096RawVerifier::Update(
    const uint8_t* buf,
    size_t len) {
  m_Impl->Update(buf, len);
}

bool RSASHA5124096RawVerifier::Verify(
    const uint8_t* signature) {
  return m_Impl->Verify(signature);
}

}  // namespace crypto
}  // namespace i2p
