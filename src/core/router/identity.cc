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

#include "core/router/identity.h"

#include <stdio.h>
#include <time.h>

#include "core/crypto/hash.h"
#include "core/crypto/rand.h"
#include "core/crypto/signature.h"

#include "core/router/context.h"

#include "core/util/i2p_endian.h"
#include "core/util/log.h"

namespace kovri {
namespace core {

// TODO(unassigned): identity implementation needs a big refactor

// TODO(unassigned): keep an eye open for alignment issues and for hacks like:
// copy public and signing keys together
//memcpy(public_key, keys.public_key, sizeof(public_key) + sizeof(signing_key));

Identity& Identity::operator=(const Keys& keys) {
  memcpy(public_key, keys.public_key, sizeof(public_key));
  memset(&certificate, 0, sizeof(certificate));
  return *this;
}

// TODO(unassigned): unused, remove after refactor
/*size_t Identity::FromBuffer(
    const uint8_t* buf,
    size_t) {
  //memcpy(public_key, buf, DEFAULT_IDENTITY_SIZE);
  memcpy(public_key, buf, sizeof(public_key));
  return DEFAULT_IDENTITY_SIZE;
}*/

IdentHash Identity::Hash() const {
  IdentHash hash;
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    kovri::core::SHA256().CalculateDigest(
        hash,
        public_key,
        DEFAULT_IDENTITY_SIZE);
  } catch (...) {
    core::Exception ex;
    ex.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  return hash;
}

IdentityEx::IdentityEx()
    : m_StandardIdentity {},
      m_IdentHash {},
      m_Verifier(nullptr),
      m_ExtendedLen(0),
      m_ExtendedBuffer(nullptr),
      m_Exception(__func__) {}

IdentityEx::IdentityEx(
    const std::uint8_t* public_key,
    const std::uint8_t* signing_key,
    SigningKeyType type) {
  try {
    memcpy(
        m_StandardIdentity.public_key,
        public_key,
        sizeof(m_StandardIdentity.public_key));
    std::size_t excess_len = 0;
    std::unique_ptr<std::uint8_t[]> excess_buf;
    switch (type) {
      case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519: {
        std::size_t padding =
          128 - kovri::core::EDDSA25519_PUBLIC_KEY_LENGTH;  // 96 = 128 - 32
        kovri::core::RandBytes(
            m_StandardIdentity.signing_key,
            padding);
        memcpy(
            m_StandardIdentity.signing_key + padding,
            signing_key,
            kovri::core::EDDSA25519_PUBLIC_KEY_LENGTH);
        break;
      }
      default:
        LOG(warning)
          << "IdentityEx: signing key type "
          << static_cast<int>(type) << " is not supported";
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
    kovri::core::SHA256().CalculateDigest(m_IdentHash, buf.get(), GetFullLen());
    CreateVerifier();
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

IdentityEx::IdentityEx(
    const std::uint8_t* buf,
    std::size_t len)
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
    m_ExtendedBuffer.reset(nullptr);
    if (m_ExtendedLen) {
      m_ExtendedBuffer = std::make_unique<std::uint8_t[]>(m_ExtendedLen);
      // Ensure that source buffer is not null before we copy (see #432)
      if (!other.m_ExtendedBuffer.get())
        throw std::runtime_error("IdentityEx: other extended buffer is null");
      memcpy(m_ExtendedBuffer.get(), other.m_ExtendedBuffer.get(), m_ExtendedLen);
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

std::size_t IdentityEx::FromBuffer(
    const std::uint8_t* buf,
    std::size_t len) {
  if (len < DEFAULT_IDENTITY_SIZE) {
    LOG(error) << "IdentityEx: identity buffer length " << len << " is too small";
    return 0;
  }
  m_ExtendedLen = 0;
  m_ExtendedBuffer.reset(nullptr);
  memcpy(&m_StandardIdentity, buf, DEFAULT_IDENTITY_SIZE);
  if (m_StandardIdentity.certificate.length) {
    m_ExtendedLen = be16toh(m_StandardIdentity.certificate.length);
    if (m_ExtendedLen + DEFAULT_IDENTITY_SIZE <= len) {
      m_ExtendedBuffer = std::make_unique<std::uint8_t[]>(m_ExtendedLen);
      memcpy(m_ExtendedBuffer.get(), buf + DEFAULT_IDENTITY_SIZE, m_ExtendedLen);
    } else {
      LOG(error)
        << "IdentityEx: certificate length " << m_ExtendedLen
        << " exceeds buffer length " << len - DEFAULT_IDENTITY_SIZE;
      return 0;
    }
  }
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    kovri::core::SHA256().CalculateDigest(m_IdentHash, buf, GetFullLen());
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  m_Verifier.reset(nullptr);
  return GetFullLen();
}

std::size_t IdentityEx::ToBuffer(
    std::uint8_t* buf,
    std::size_t) const {
  memcpy(buf, &m_StandardIdentity, DEFAULT_IDENTITY_SIZE);
  if (m_ExtendedLen > 0 && m_ExtendedBuffer)
    memcpy(buf + DEFAULT_IDENTITY_SIZE, m_ExtendedBuffer.get(), m_ExtendedLen);
  return GetFullLen();
}

std::size_t IdentityEx::FromBase64(
    const std::string& s) {
  std::uint8_t buf[1024];
  auto len = kovri::core::Base64ToByteStream(s.c_str(), s.length(), buf, 1024);
  return FromBuffer(buf, len);
}

std::string IdentityEx::ToBase64() const {
  std::uint8_t buf[1024];
  char str[1536];
  std::size_t l = ToBuffer(buf, 1024);
  std::size_t l1 = kovri::core::ByteStreamToBase64(buf, l, str, 1536);
  str[l1] = 0;
  return std::string(str);
}

std::string GetCertificateTypeName(std::uint8_t type)
{
  switch (type)
    {
      case CERTIFICATE_TYPE_NULL:
        return "Null";
      case CERTIFICATE_TYPE_HASHCASH:
        return "Hashcash";
      case CERTIFICATE_TYPE_HIDDEN:
        return "Hidden";
      case CERTIFICATE_TYPE_SIGNED:
        return "Signed";
      case CERTIFICATE_TYPE_MULTIPLE:
        return "Multiple";
      case CERTIFICATE_TYPE_KEY:
        return "Key";
      default:
        LOG(error) << "Unknown type " << type;
        return "";
    }
}

std::string IdentityEx::GetDescription(const std::string& tabs) const
{
  std::stringstream ss;
  ss << tabs << "RouterIdentity: " << std::endl
     << tabs << "\tHash: " << GetIdentHash().ToBase64() << std::endl
     << tabs << "\tCertificate:" << std::endl
     << tabs << "\t\ttype: "
     << GetCertificateTypeName(m_StandardIdentity.certificate.type)
     << " certificate " << std::endl
     << tabs << "\t\tCrypto type: " << GetCryptoKeyType() << std::endl
     << tabs << "\tPublickey: size: 256" << std::endl
     << tabs << "\tSigningPublickey: " << std::endl
     << tabs << "\t\t" << GetSigningKeyTypeName(GetSigningKeyType())
     << std::endl
     << tabs << "\t\tsize: " << GetSigningPublicKeyLen() << std::endl
     << tabs << "\t\t";
  switch (GetSigningKeyType())
    {
      case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:  // 96 = 128 - 32
        ss << "Padding: " << (128 - kovri::core::EDDSA25519_PUBLIC_KEY_LENGTH);
        break;
      default:
        LOG(warning) << "IdentityEx: signing key type "
                     << static_cast<int>(GetSigningKeyType())
                     << " is not supported";
        break;
    }
  ss << std::endl
     << tabs << "\tSignature: size: " << GetSignatureLen() << std::endl;
  return ss.str();
}

std::size_t IdentityEx::GetSigningPublicKeyLen() const {
  if (!m_Verifier)
    CreateVerifier();
  if (m_Verifier)
    return m_Verifier->GetPublicKeyLen();
  return 128;
}

std::size_t IdentityEx::GetSigningPrivateKeyLen() const {
  if (!m_Verifier)
    CreateVerifier();
  if (m_Verifier)
    return m_Verifier->GetPrivateKeyLen();
  return GetSignatureLen() / 2;
}

std::size_t IdentityEx::GetSignatureLen() const {
  if (!m_Verifier)
    CreateVerifier();
  if (m_Verifier)
    return m_Verifier->GetSignatureLen();
  return kovri::core::EDDSA25519_SIGNATURE_LENGTH;
}

bool IdentityEx::Verify(
    const std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* signature) const {
  if (!m_Verifier)
    CreateVerifier();
  if (m_Verifier) {
    // TODO(anonimal): this try block should be handled entirely by caller
    try {
      return m_Verifier->Verify(buf, len, signature);
    } catch (...) {
      core::Exception ex;
      ex.Dispatch(__func__);
      // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
      throw;
    }
  }
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
  auto key_type = GetSigningKeyType();
  switch (key_type) {
    case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519: {
      std::size_t padding = 128 - kovri::core::EDDSA25519_PUBLIC_KEY_LENGTH;  // 96 = 128 - 32
      m_Verifier =
        std::make_unique<kovri::core::EDDSA25519Verifier>(
            m_StandardIdentity.signing_key + padding);
      break;
    }
    default:
      LOG(warning)
        << "IdentityEx: signing key type "
        << static_cast<int>(key_type) << " is not supported";
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

std::size_t PrivateKeys::FromBuffer(
    const std::uint8_t* buf,
    std::size_t len) {
  std::size_t ret = m_Public.FromBuffer(buf, len);
  memcpy(m_PrivateKey, buf + ret, 256);  // private key always 256
  ret += 256;
  std::size_t signing_private_key_size = m_Public.GetSigningPrivateKeyLen();
  memcpy(m_SigningPrivateKey, buf + ret, signing_private_key_size);
  ret += signing_private_key_size;
  m_Signer.reset(nullptr);
  CreateSigner();
  return ret;
}

std::size_t PrivateKeys::ToBuffer(
    std::uint8_t* buf,
    std::size_t len) const {
  std::size_t ret = m_Public.ToBuffer(buf, len);
  memcpy(buf + ret, m_PrivateKey, 256);  // private key always 256
  ret += 256;
  std::size_t signing_private_key_size = m_Public.GetSigningPrivateKeyLen();
  memcpy(buf + ret, m_SigningPrivateKey, signing_private_key_size);
  ret += signing_private_key_size;
  return ret;
}

std::size_t PrivateKeys::FromBase64(
    const std::string& s) {
  auto buf = std::make_unique<std::uint8_t[]>(s.length());
  std::size_t l = kovri::core::Base64ToByteStream(
      s.c_str(),
      s.length(),
      buf.get(),
      s.length());
  std::size_t ret = FromBuffer(buf.get(), l);
  return ret;
}

std::string PrivateKeys::ToBase64() const {
  auto buf = std::make_unique<std::uint8_t[]>(GetFullLen());
  auto str = std::make_unique<char[]>(GetFullLen() * 2);
  std::size_t l = ToBuffer(buf.get(), GetFullLen());
  std::size_t l1 = kovri::core::ByteStreamToBase64(buf.get(), l, str.get(), GetFullLen() * 2);
  str[l1] = 0;
  std::string ret(str.get());
  return ret;
}

void PrivateKeys::Sign(
    const std::uint8_t* buf,
    int len,
    std::uint8_t* signature) const {
  if (m_Signer) {
    try {
      m_Signer->Sign(buf, len, signature);
    } catch (...) {
      core::Exception ex;
      ex.Dispatch(__func__);
      // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
      throw;
    }
  }
}

void PrivateKeys::CreateSigner() {
  switch (m_Public.GetSigningKeyType()) {
    case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
      m_Signer = std::make_unique<kovri::core::EDDSA25519Signer>(m_SigningPrivateKey);
    break;
    default:
      LOG(warning)
        << "IdentityEx: Signing key type "
        << static_cast<int>(m_Public.GetSigningKeyType())
        << " is not supported";
  }
}

PrivateKeys PrivateKeys::CreateRandomKeys(SigningKeyType type) {
  PrivateKeys keys;
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    // signature
    std::uint8_t signing_public_key[512];  // signing public key is 512 bytes max
    switch (type) {
      case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
        kovri::core::CreateEDDSARandomKeys(
            keys.m_SigningPrivateKey,
            signing_public_key);
      break;
      default:
        LOG(warning)
          << "IdentityEx: Signing key type "
          << static_cast<int>(type) << " is not supported, creating EDDSA_SHA512_ED25519";
        // fall-through
        kovri::core::CreateEDDSARandomKeys(
            keys.m_SigningPrivateKey,
            signing_public_key);
    }
    // encryption
    std::uint8_t public_key[256];
    kovri::core::GenerateElGamalKeyPair(keys.m_PrivateKey, public_key);
    // identity
    keys.m_Public = IdentityEx(public_key, signing_public_key, type);
    keys.CreateSigner();
  } catch (...) {
    core::Exception ex;
    ex.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  return keys;
}

Keys CreateRandomKeys() {
  Keys keys;
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    // encryption
    kovri::core::GenerateElGamalKeyPair(
        keys.private_key,
        keys.public_key);
    // signing
    kovri::core::CreateEDDSARandomKeys(
        keys.signing_private_key,
        keys.signing_key);
  } catch (...) {
    core::Exception ex;
    ex.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  return keys;
}

IdentHash CreateRoutingKey(
    const IdentHash& ident) {
  std::uint8_t buf[41];  // ident + yyyymmdd
  memcpy(buf, (const std::uint8_t *)ident, 32);
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
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    kovri::core::SHA256().CalculateDigest((std::uint8_t *)key, buf, 40);
  } catch (...) {
    core::Exception ex;
    ex.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  return key;
}

XORMetric operator^(
    const IdentHash& key1,
    const IdentHash& key2) {
  XORMetric m;
  const std::uint64_t* hash1 = key1.GetLL(), * hash2 = key2.GetLL();
  m.metric_ll[0] = hash1[0] ^ hash2[0];
  m.metric_ll[1] = hash1[1] ^ hash2[1];
  m.metric_ll[2] = hash1[2] ^ hash2[2];
  m.metric_ll[3] = hash1[3] ^ hash2[3];
  return m;
}

const std::string GetSigningKeyTypeName(const std::uint16_t key)
{
  switch (key)
    {
      case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
        return "EDDSA_SHA512_ED25519";
      default:
        LOG(error) << "Unknown signing key type " << key;
        return "";
    }
}

}  // namespace core
}  // namespace kovri
