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

#include "identity.h"

#include <stdio.h>
#include <time.h>

#include <memory>
#include <string>

#include "router_context.h"
#include "crypto/elgamal.h"
#include "crypto/hash.h"
#include "crypto/rand.h"
#include "crypto/signature.h"
#include "util/base64.h"
#include "util/i2p_endian.h"
#include "util/log.h"

namespace i2p {
namespace data {

Identity& Identity::operator=(const Keys& keys) {
  // copy public and signing keys together
  memcpy(public_key, keys.public_key, sizeof(public_key) + sizeof(signing_key));
  memset(&certificate, 0, sizeof(certificate));
  return *this;
}

size_t Identity::FromBuffer(
    const uint8_t* buf,
    size_t) {
  memcpy(public_key, buf, DEFAULT_IDENTITY_SIZE);
  return DEFAULT_IDENTITY_SIZE;
}

IdentHash Identity::Hash() const {
  IdentHash hash;
  i2p::crypto::SHA256().CalculateDigest(
      hash,
      public_key,
      DEFAULT_IDENTITY_SIZE);
  return hash;
}

IdentityEx::IdentityEx()
    : m_Verifier(nullptr),
      m_ExtendedLen(0),
      m_ExtendedBuffer(nullptr) {}

IdentityEx::IdentityEx(
    const uint8_t* public_key,
    const uint8_t* signing_key,
    SigningKeyType type) {
  memcpy(
      m_StandardIdentity.public_key,
      public_key,
      sizeof(m_StandardIdentity.public_key));
  if (type != SIGNING_KEY_TYPE_DSA_SHA1) {
    size_t excess_len = 0;
    std::unique_ptr<std::uint8_t[]> excess_buf;
    switch (type) {
      case SIGNING_KEY_TYPE_ECDSA_SHA256_P256: {
        size_t padding =
          128 - i2p::crypto::ECDSAP256_KEY_LENGTH;  // 64 = 128 - 64
        i2p::crypto::RandBytes(
            m_StandardIdentity.signing_key,
            padding);
        memcpy(
            m_StandardIdentity.signing_key + padding,
            signing_key,
            i2p::crypto::ECDSAP256_KEY_LENGTH);
        break;
      }
      case SIGNING_KEY_TYPE_ECDSA_SHA384_P384: {
        size_t padding =
          128 - i2p::crypto::ECDSAP384_KEY_LENGTH;  // 32 = 128 - 96
        i2p::crypto::RandBytes(
            m_StandardIdentity.signing_key,
            padding);
        memcpy(
            m_StandardIdentity.signing_key + padding,
            signing_key,
            i2p::crypto::ECDSAP384_KEY_LENGTH);
        break;
      }
      case SIGNING_KEY_TYPE_ECDSA_SHA512_P521: {
        memcpy(m_StandardIdentity.signing_key, signing_key, 128);
        excess_len = i2p::crypto::ECDSAP521_KEY_LENGTH - 128;  // 4 = 132 - 128
        excess_buf = std::make_unique<std::uint8_t[]>(excess_len);
        memcpy(excess_buf.get(), signing_key + 128, excess_len);
        break;
      }
      case SIGNING_KEY_TYPE_RSA_SHA256_2048: {
        memcpy(m_StandardIdentity.signing_key, signing_key, 128);
        excess_len = i2p::crypto::RSASHA2562048_KEY_LENGTH - 128;  // 128 = 256 - 128
        excess_buf = std::make_unique<std::uint8_t[]>(excess_len);
        memcpy(excess_buf.get(), signing_key + 128, excess_len);
        break;
      }
      case SIGNING_KEY_TYPE_RSA_SHA384_3072: {
        memcpy(m_StandardIdentity.signing_key, signing_key, 128);
        excess_len = i2p::crypto::RSASHA3843072_KEY_LENGTH - 128;  // 256 = 384 - 128
        excess_buf = std::make_unique<std::uint8_t[]>(excess_len);
        memcpy(excess_buf.get(), signing_key + 128, excess_len);
        break;
      }
      case SIGNING_KEY_TYPE_RSA_SHA512_4096: {
        memcpy(m_StandardIdentity.signing_key, signing_key, 128);
        excess_len = i2p::crypto::RSASHA5124096_KEY_LENGTH - 128;  // 384 = 512 - 128
        excess_buf = std::make_unique<std::uint8_t[]>(excess_len);
        memcpy(excess_buf.get(), signing_key + 128, excess_len);
        break;
      }
      case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519: {
        size_t padding =
          128 - i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH;  // 96 = 128 - 32
        i2p::crypto::RandBytes(
            m_StandardIdentity.signing_key,
            padding);
        memcpy(
            m_StandardIdentity.signing_key + padding,
            signing_key,
            i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH);
        break;
      }
      default:
        LogPrint(eLogWarn,
            "IdentityEx: signing key type ",
            static_cast<int>(type), " is not supported");
    }
    m_ExtendedLen = 4 + excess_len;  // 4 bytes extra + excess length
    // fill certificate
    m_StandardIdentity.certificate.type = CERTIFICATE_TYPE_KEY;
    m_StandardIdentity.certificate.length = htobe16(m_ExtendedLen);
    // fill extended buffer
    m_ExtendedBuffer = std::make_unique<std::uint8_t[]>(m_ExtendedLen);
    htobe16buf(m_ExtendedBuffer.get(), type);
    htobe16buf(m_ExtendedBuffer.get() + 2, CRYPTO_KEY_TYPE_ELGAMAL);
    if (excess_len && excess_buf) {
      memcpy(m_ExtendedBuffer.get() + 4, excess_buf.get(), excess_len);
    }
    // calculate ident hash
    auto buf = std::make_unique<std::uint8_t[]>(GetFullLen());
    ToBuffer(buf.get(), GetFullLen());
    i2p::crypto::SHA256().CalculateDigest(m_IdentHash, buf.get(), GetFullLen());
  } else {  // DSA-SHA1
    memcpy(
        m_StandardIdentity.signing_key,
        signing_key,
        sizeof(m_StandardIdentity.signing_key));
    memset(
        &m_StandardIdentity.certificate,
        0,
        sizeof(m_StandardIdentity.certificate));
    m_IdentHash = m_StandardIdentity.Hash();
    m_ExtendedLen = 0;
    m_ExtendedBuffer.reset(nullptr);
  }
  CreateVerifier();
}

IdentityEx::IdentityEx(
    const uint8_t* buf,
    size_t len)
    : m_Verifier(nullptr),
      m_ExtendedLen(0),
      m_ExtendedBuffer(nullptr) {
  FromBuffer(buf, len);
}

IdentityEx::IdentityEx(
    const IdentityEx& other)
    : m_Verifier(nullptr),
      m_ExtendedBuffer(nullptr) {
  *this = other;
}

IdentityEx::~IdentityEx() {}

IdentityEx& IdentityEx::operator=(const IdentityEx& other) {
  if (&other != this) {
    memcpy(&m_StandardIdentity, &other.m_StandardIdentity, DEFAULT_IDENTITY_SIZE);
    m_IdentHash = other.m_IdentHash;
    m_ExtendedLen = other.m_ExtendedLen;
    if (m_ExtendedLen > 0) {
      m_ExtendedBuffer = std::make_unique<std::uint8_t[]>(m_ExtendedLen);
      memcpy(m_ExtendedBuffer.get(), other.m_ExtendedBuffer.get(), m_ExtendedLen);
    } else {
      m_ExtendedBuffer.reset(nullptr);
    }
    m_Verifier.reset(nullptr);
  }
  return *this;
}

IdentityEx& IdentityEx::operator=(const Identity& standard) {
  m_StandardIdentity = standard;
  m_IdentHash = m_StandardIdentity.Hash();
  m_ExtendedBuffer.reset(nullptr);
  m_ExtendedLen = 0;
  m_Verifier.reset(nullptr);
  return *this;
}

size_t IdentityEx::FromBuffer(
    const uint8_t* buf,
    size_t len) {
  if (len < DEFAULT_IDENTITY_SIZE) {
    LogPrint(eLogError, "IdentityEx: identity buffer length ", len, " is too small");
    return 0;
  }
  memcpy(&m_StandardIdentity, buf, DEFAULT_IDENTITY_SIZE);
  if (m_StandardIdentity.certificate.length) {
    m_ExtendedLen = be16toh(m_StandardIdentity.certificate.length);
    if (m_ExtendedLen + DEFAULT_IDENTITY_SIZE <= len) {
      m_ExtendedBuffer = std::make_unique<std::uint8_t[]>(m_ExtendedLen);
      memcpy(m_ExtendedBuffer.get(), buf + DEFAULT_IDENTITY_SIZE, m_ExtendedLen);
    } else {
      LogPrint(eLogError,
          "IdentityEx: certificate length ", m_ExtendedLen,
          " exceeds buffer length ", len - DEFAULT_IDENTITY_SIZE);
      return 0;
    }
  } else {
    m_ExtendedLen = 0;
    m_ExtendedBuffer.reset(nullptr);
  }
  i2p::crypto::SHA256().CalculateDigest(m_IdentHash, buf, GetFullLen());
  m_Verifier.reset(nullptr);
  return GetFullLen();
}

size_t IdentityEx::ToBuffer(
    uint8_t* buf,
    size_t) const {
  memcpy(buf, &m_StandardIdentity, DEFAULT_IDENTITY_SIZE);
  if (m_ExtendedLen > 0 && m_ExtendedBuffer)
    memcpy(buf + DEFAULT_IDENTITY_SIZE, m_ExtendedBuffer.get(), m_ExtendedLen);
  return GetFullLen();
}

size_t IdentityEx::FromBase64(
    const std::string& s) {
  uint8_t buf[1024];
  auto len = i2p::util::Base64ToByteStream(s.c_str(), s.length(), buf, 1024);
  return FromBuffer(buf, len);
}

std::string IdentityEx::ToBase64() const {
  uint8_t buf[1024];
  char str[1536];
  size_t l = ToBuffer(buf, 1024);
  size_t l1 = i2p::util::ByteStreamToBase64(buf, l, str, 1536);
  str[l1] = 0;
  return std::string(str);
}

size_t IdentityEx::GetSigningPublicKeyLen() const {
  if (!m_Verifier)
    CreateVerifier();
  if (m_Verifier)
    return m_Verifier->GetPublicKeyLen();
  return 128;
}

size_t IdentityEx::GetSigningPrivateKeyLen() const {
  if (!m_Verifier)
    CreateVerifier();
  if (m_Verifier)
    return m_Verifier->GetPrivateKeyLen();
  return GetSignatureLen() / 2;
}

size_t IdentityEx::GetSignatureLen() const {
  if (!m_Verifier)
    CreateVerifier();
  if (m_Verifier)
    return m_Verifier->GetSignatureLen();
  return i2p::crypto::DSA_SIGNATURE_LENGTH;
}
bool IdentityEx::Verify(
    const uint8_t* buf,
    size_t len,
    const uint8_t* signature) const {
  if (!m_Verifier)
    CreateVerifier();
  if (m_Verifier)
    return m_Verifier->Verify(buf, len, signature);
  return false;
}

SigningKeyType IdentityEx::GetSigningKeyType() const {
  if (m_StandardIdentity.certificate.type ==
      CERTIFICATE_TYPE_KEY && m_ExtendedBuffer)
    return bufbe16toh(m_ExtendedBuffer.get());  // signing key
  return SIGNING_KEY_TYPE_DSA_SHA1;
}

CryptoKeyType IdentityEx::GetCryptoKeyType() const {
  if (m_StandardIdentity.certificate.type ==
      CERTIFICATE_TYPE_KEY && m_ExtendedBuffer)
    return bufbe16toh(m_ExtendedBuffer.get() + 2);  // crypto key
  return CRYPTO_KEY_TYPE_ELGAMAL;
}

void IdentityEx::CreateVerifier() const  {
  auto keyType = GetSigningKeyType();
  switch (keyType) {
    case SIGNING_KEY_TYPE_DSA_SHA1:
      m_Verifier = std::make_unique<i2p::crypto::DSAVerifier>(m_StandardIdentity.signing_key);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA256_P256: {
      size_t padding = 128 - i2p::crypto::ECDSAP256_KEY_LENGTH;  // 64 = 128 - 64
      m_Verifier =
        std::make_unique<i2p::crypto::ECDSAP256Verifier>(
            m_StandardIdentity.signing_key + padding);
      break;
    }
    case SIGNING_KEY_TYPE_ECDSA_SHA384_P384: {
      size_t padding = 128 - i2p::crypto::ECDSAP384_KEY_LENGTH;  // 32 = 128 - 96
      m_Verifier =
        std::make_unique<i2p::crypto::ECDSAP384Verifier>(
            m_StandardIdentity.signing_key + padding);
      break;
    }
    case SIGNING_KEY_TYPE_ECDSA_SHA512_P521: {
      uint8_t signing_key[i2p::crypto::ECDSAP521_KEY_LENGTH];
      memcpy(signing_key, m_StandardIdentity.signing_key, 128);
      size_t excess_len = i2p::crypto::ECDSAP521_KEY_LENGTH - 128;  // 4 = 132- 128
      memcpy(signing_key + 128, m_ExtendedBuffer.get() + 4, excess_len);  // right after signing and crypto key types
      m_Verifier = std::make_unique<i2p::crypto::ECDSAP521Verifier>(signing_key);
      break;
    }
    case SIGNING_KEY_TYPE_RSA_SHA256_2048: {
      uint8_t signing_key[i2p::crypto::RSASHA2562048_KEY_LENGTH];
      memcpy(signing_key, m_StandardIdentity.signing_key, 128);
      size_t excess_len = i2p::crypto::RSASHA2562048_KEY_LENGTH - 128;  // 128 = 256- 128
      memcpy(signing_key + 128, m_ExtendedBuffer.get() + 4, excess_len);
      m_Verifier = std::make_unique<i2p::crypto::RSASHA2562048Verifier>(signing_key);
      break;
    }
    case SIGNING_KEY_TYPE_RSA_SHA384_3072: {
      uint8_t signing_key[i2p::crypto::RSASHA3843072_KEY_LENGTH];
      memcpy(signing_key, m_StandardIdentity.signing_key, 128);
      size_t excess_len = i2p::crypto::RSASHA3843072_KEY_LENGTH - 128;  // 256 = 384- 128
      memcpy(signing_key + 128, m_ExtendedBuffer.get() + 4, excess_len);
      m_Verifier = std::make_unique<i2p::crypto::RSASHA3843072Verifier>(signing_key);
      break;
    }
    case SIGNING_KEY_TYPE_RSA_SHA512_4096: {
      uint8_t signing_key[i2p::crypto::RSASHA5124096_KEY_LENGTH];
      memcpy(signing_key, m_StandardIdentity.signing_key, 128);
      size_t excess_len = i2p::crypto::RSASHA5124096_KEY_LENGTH - 128;  // 384 = 512- 128
      memcpy(signing_key + 128, m_ExtendedBuffer.get() + 4, excess_len);
      m_Verifier = std::make_unique<i2p::crypto::RSASHA5124096Verifier>(signing_key);
      break;
    }
    case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519: {
      size_t padding = 128 - i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH;  // 96 = 128 - 32
      m_Verifier =
        std::make_unique<i2p::crypto::EDDSA25519Verifier>(
            m_StandardIdentity.signing_key + padding);
      break;
    }
    default:
      LogPrint(eLogWarn,
          "IdentityEx: signing key type ",
          static_cast<int>(keyType), " is not supported");
  }
}

void IdentityEx::DropVerifier() {
  m_Verifier.reset(nullptr);
}

/**
 *
 * PrivateKeys
 *
 */

PrivateKeys::PrivateKeys() : m_Signer(nullptr) {}
PrivateKeys::~PrivateKeys() {}

PrivateKeys& PrivateKeys::operator=(const Keys& keys) {
  m_Public = Identity(keys);
  memcpy(m_PrivateKey, keys.private_key, 256);  // 256
  memcpy(
      m_SigningPrivateKey,
      keys.signing_private_key,
      m_Public.GetSigningPrivateKeyLen());
  m_Signer.reset(nullptr);
  CreateSigner();
  return *this;
}

PrivateKeys& PrivateKeys::operator=(const PrivateKeys& other) {
  m_Public = other.m_Public;
  memcpy(m_PrivateKey, other.m_PrivateKey, 256);  // 256
  memcpy(
      m_SigningPrivateKey,
      other.m_SigningPrivateKey,
      m_Public.GetSigningPrivateKeyLen());
  m_Signer.reset(nullptr);
  CreateSigner();
  return *this;
}

size_t PrivateKeys::FromBuffer(
    const uint8_t* buf,
    size_t len) {
  size_t ret = m_Public.FromBuffer(buf, len);
  memcpy(m_PrivateKey, buf + ret, 256);  // private key always 256
  ret += 256;
  size_t signingPrivateKeySize = m_Public.GetSigningPrivateKeyLen();
  memcpy(m_SigningPrivateKey, buf + ret, signingPrivateKeySize);
  ret += signingPrivateKeySize;
  m_Signer.reset(nullptr);
  CreateSigner();
  return ret;
}

size_t PrivateKeys::ToBuffer(
    uint8_t* buf,
    size_t len) const {
  size_t ret = m_Public.ToBuffer(buf, len);
  memcpy(buf + ret, m_PrivateKey, 256);  // private key always 256
  ret += 256;
  size_t signingPrivateKeySize = m_Public.GetSigningPrivateKeyLen();
  memcpy(buf + ret, m_SigningPrivateKey, signingPrivateKeySize);
  ret += signingPrivateKeySize;
  return ret;
}

size_t PrivateKeys::FromBase64(
    const std::string& s) {
  auto buf = std::make_unique<std::uint8_t[]>(s.length());
  size_t l = i2p::util::Base64ToByteStream(
      s.c_str(),
      s.length(),
      buf.get(),
      s.length());
  size_t ret = FromBuffer(buf.get(), l);
  return ret;
}

std::string PrivateKeys::ToBase64() const {
  auto buf = std::make_unique<std::uint8_t[]>(GetFullLen());
  auto str = std::make_unique<char[]>(GetFullLen() * 2);
  size_t l = ToBuffer(buf.get(), GetFullLen());
  size_t l1 = i2p::util::ByteStreamToBase64(buf.get(), l, str.get(), GetFullLen() * 2);
  str[l1] = 0;
  std::string ret(str.get());
  return ret;
}

void PrivateKeys::Sign(
    const uint8_t* buf,
    int len,
    uint8_t* signature) const {
  if (m_Signer)
    m_Signer->Sign(buf, len, signature);
}

void PrivateKeys::CreateSigner() {
  switch (m_Public.GetSigningKeyType()) {
    case SIGNING_KEY_TYPE_DSA_SHA1:
      m_Signer = std::make_unique<i2p::crypto::DSASigner>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
      m_Signer = std::make_unique<i2p::crypto::ECDSAP256Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
      m_Signer = std::make_unique<i2p::crypto::ECDSAP384Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
      m_Signer = std::make_unique<i2p::crypto::ECDSAP521Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_RSA_SHA256_2048:
      m_Signer = std::make_unique<i2p::crypto::RSASHA2562048Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_RSA_SHA384_3072:
      m_Signer = std::make_unique<i2p::crypto::RSASHA3843072Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_RSA_SHA512_4096:
      m_Signer = std::make_unique<i2p::crypto::RSASHA5124096Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
      m_Signer = std::make_unique<i2p::crypto::EDDSA25519Signer>(m_SigningPrivateKey);
    break;
    default:
      LogPrint(eLogWarn,
          "IdentityEx: Signing key type ",
          static_cast<int>(m_Public.GetSigningKeyType()), " is not supported");
  }
}

PrivateKeys PrivateKeys::CreateRandomKeys(SigningKeyType type) {
  PrivateKeys keys;
  // signature
  uint8_t signingPublicKey[512];  // signing public key is 512 bytes max
  switch (type) {
    case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
      i2p::crypto::CreateECDSAP256RandomKeys(
          keys.m_SigningPrivateKey,
          signingPublicKey);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
      i2p::crypto::CreateECDSAP384RandomKeys(
          keys.m_SigningPrivateKey,
          signingPublicKey);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
      i2p::crypto::CreateECDSAP521RandomKeys(
          keys.m_SigningPrivateKey,
          signingPublicKey);
    break;
    case SIGNING_KEY_TYPE_RSA_SHA256_2048:
      i2p::crypto::CreateRSARandomKeys(
          i2p::crypto::RSASHA2562048_KEY_LENGTH,
          keys.m_SigningPrivateKey,
          signingPublicKey);
    break;
    case SIGNING_KEY_TYPE_RSA_SHA384_3072:
      i2p::crypto::CreateRSARandomKeys(
          i2p::crypto::RSASHA3843072_KEY_LENGTH,
          keys.m_SigningPrivateKey,
          signingPublicKey);
    break;
    case SIGNING_KEY_TYPE_RSA_SHA512_4096:
      i2p::crypto::CreateRSARandomKeys(
          i2p::crypto::RSASHA5124096_KEY_LENGTH,
          keys.m_SigningPrivateKey,
          signingPublicKey);
    break;
    case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
      i2p::crypto::CreateEDDSARandomKeys(
          keys.m_SigningPrivateKey,
          signingPublicKey);
    break;
    default: // Includes 
      LogPrint(eLogWarn,
          "IdentityEx: Signing key type ",
          static_cast<int>(type), " is not supported, creating DSA-SHA1");
    case SIGNING_KEY_TYPE_DSA_SHA1:
      return PrivateKeys(i2p::data::CreateRandomKeys());  // DSA-SHA1
  }
  // encryption
  uint8_t public_key[256];
  i2p::crypto::GenerateElGamalKeyPair(keys.m_PrivateKey, public_key);
  // identity
  keys.m_Public = IdentityEx(public_key, signingPublicKey, type);
  keys.CreateSigner();
  return keys;
}

Keys CreateRandomKeys() {
  Keys keys;
  // encryption
  i2p::crypto::GenerateElGamalKeyPair(
      keys.private_key,
      keys.public_key);
  // signing
  i2p::crypto::CreateDSARandomKeys(
      keys.signing_private_key,
      keys.signing_key);
  return keys;
}

IdentHash CreateRoutingKey(
    const IdentHash& ident) {
  uint8_t buf[41];  // ident + yyyymmdd
  memcpy(buf, (const uint8_t *)ident, 32);
  time_t t = time(nullptr);
  struct tm tm;
  // TODO(unassigned): never use sprintf, use snprintf instead.
#ifdef _WIN32
  gmtime_s(&tm, &t);
  sprintf_s(
      reinterpret_cast<char *>((buf + 32)),
      9,
      "%04i%02i%02i",
      tm.tm_year + 1900,
      tm.tm_mon + 1,
      tm.tm_mday);
#else
  gmtime_r(&t, &tm);
  sprintf(
      reinterpret_cast<char *>((buf + 32)),
      "%04i%02i%02i",
      tm.tm_year + 1900,
      tm.tm_mon + 1,
      tm.tm_mday);
#endif
  IdentHash key;
  i2p::crypto::SHA256().CalculateDigest((uint8_t *)key, buf, 40);
  return key;
}

XORMetric operator^(
    const IdentHash& key1,
    const IdentHash& key2) {
  XORMetric m;
  const uint64_t* hash1 = key1.GetLL(), * hash2 = key2.GetLL();
  m.metric_ll[0] = hash1[0] ^ hash2[0];
  m.metric_ll[1] = hash1[1] ^ hash2[1];
  m.metric_ll[2] = hash1[2] ^ hash2[2];
  m.metric_ll[3] = hash1[3] ^ hash2[3];
  return m;
}

}  // namespace data
}  // namespace i2p
