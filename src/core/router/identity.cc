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

#include "core/router/identity.h"

#include <boost/endian/conversion.hpp>
#include <boost/date_time/gregorian/gregorian_types.hpp>

#include "core/crypto/hash.h"
#include "core/crypto/rand.h"
#include "core/crypto/signature.h"

#include "core/router/context.h"

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
    if (type != SIGNING_KEY_TYPE_DSA_SHA1) {
      std::size_t excess_len = 0;
      std::unique_ptr<std::uint8_t[]> excess_buf;
      switch (type) {
        case SIGNING_KEY_TYPE_ECDSA_SHA256_P256: {
          std::size_t padding =
            128 - kovri::core::ECDSAP256_KEY_LENGTH;  // 64 = 128 - 64
          kovri::core::RandBytes(
              m_StandardIdentity.signing_key,
              padding);
          memcpy(
              m_StandardIdentity.signing_key + padding,
              signing_key,
              kovri::core::ECDSAP256_KEY_LENGTH);
          break;
        }
        case SIGNING_KEY_TYPE_ECDSA_SHA384_P384: {
          std::size_t padding =
            128 - kovri::core::ECDSAP384_KEY_LENGTH;  // 32 = 128 - 96
          kovri::core::RandBytes(
              m_StandardIdentity.signing_key,
              padding);
          memcpy(
              m_StandardIdentity.signing_key + padding,
              signing_key,
              kovri::core::ECDSAP384_KEY_LENGTH);
          break;
        }
        case SIGNING_KEY_TYPE_ECDSA_SHA512_P521: {
          memcpy(m_StandardIdentity.signing_key, signing_key, 128);
          excess_len = kovri::core::ECDSAP521_KEY_LENGTH - 128;  // 4 = 132 - 128
          excess_buf = std::make_unique<std::uint8_t[]>(excess_len);
          memcpy(excess_buf.get(), signing_key + 128, excess_len);
          break;
        }
        case SIGNING_KEY_TYPE_RSA_SHA256_2048: {
          memcpy(m_StandardIdentity.signing_key, signing_key, 128);
          excess_len = kovri::core::RSASHA2562048_KEY_LENGTH - 128;  // 128 = 256 - 128
          excess_buf = std::make_unique<std::uint8_t[]>(excess_len);
          memcpy(excess_buf.get(), signing_key + 128, excess_len);
          break;
        }
        case SIGNING_KEY_TYPE_RSA_SHA384_3072: {
          memcpy(m_StandardIdentity.signing_key, signing_key, 128);
          excess_len = kovri::core::RSASHA3843072_KEY_LENGTH - 128;  // 256 = 384 - 128
          excess_buf = std::make_unique<std::uint8_t[]>(excess_len);
          memcpy(excess_buf.get(), signing_key + 128, excess_len);
          break;
        }
        case SIGNING_KEY_TYPE_RSA_SHA512_4096: {
          memcpy(m_StandardIdentity.signing_key, signing_key, 128);
          excess_len = kovri::core::RSASHA5124096_KEY_LENGTH - 128;  // 384 = 512 - 128
          excess_buf = std::make_unique<std::uint8_t[]>(excess_len);
          memcpy(excess_buf.get(), signing_key + 128, excess_len);
          break;
        }
        case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519: {
          std::size_t padding = 128 - crypto::PkLen::Ed25519;  // 96 = 128 - 32
          kovri::core::RandBytes(
              m_StandardIdentity.signing_key,
              padding);
          memcpy(
              m_StandardIdentity.signing_key + padding,
              signing_key,
              crypto::PkLen::Ed25519);
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
      m_StandardIdentity.certificate.length = boost::endian::native_to_big(m_ExtendedLen);
      // fill extended buffer
      m_ExtendedBuffer = std::make_unique<std::uint8_t[]>(m_ExtendedLen);
      core::OutputByteStream::Write<std::uint16_t>(
          m_ExtendedBuffer.get(), type);
      core::OutputByteStream::Write<std::uint16_t>(
          m_ExtendedBuffer.get() + 2, CRYPTO_KEY_TYPE_ELGAMAL);
      if (excess_len && excess_buf) {
        memcpy(m_ExtendedBuffer.get() + 4, excess_buf.get(), excess_len);
      }
      // calculate ident hash
      auto buf = std::make_unique<std::uint8_t[]>(GetFullLen());
      ToBuffer(buf.get(), GetFullLen());
      kovri::core::SHA256().CalculateDigest(m_IdentHash, buf.get(), GetFullLen());
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
    m_ExtendedLen = boost::endian::big_to_native(m_StandardIdentity.certificate.length);
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
    std::size_t buflen) const {
  if (buflen < DEFAULT_IDENTITY_SIZE)
    throw std::length_error("IdentityEx: supplied buffer is too small");

  memcpy(buf, &m_StandardIdentity, DEFAULT_IDENTITY_SIZE);
  if (m_ExtendedLen > 0 && m_ExtendedBuffer)
  {
    if (buflen < DEFAULT_IDENTITY_SIZE + m_ExtendedLen)
      throw std::length_error("IdentityEx: supplied buffer is too small"); 

    memcpy(buf + DEFAULT_IDENTITY_SIZE, m_ExtendedBuffer.get(), m_ExtendedLen);
  }
  return GetFullLen();
}

void IdentityEx::FromBase32(const std::string& encoded)
{
  auto const decoded = core::Base32::Decode(encoded.c_str(), encoded.length());
  if (!FromBuffer(decoded.data(), decoded.size()))
    throw std::runtime_error("IdentityEx: could not decode from base32");
}

void IdentityEx::FromBase64(const std::string& encoded)
{
  auto const decoded = core::Base64::Decode(encoded.c_str(), encoded.length());
  if (!FromBuffer(
          decoded.data(),
          decoded.size()))
    throw std::runtime_error("IdentityEx: could not decode from base64");
}

std::string IdentityEx::ToBase32() const
{
  // TODO(anonimal): this max size is arbitrary. Realistically,
  //   we'll only need a max with 387 + 4 for EdDSA-Ed25519 routers
  //   which is a majority of the network. Note: do not set that size
  //   until we remove implementing other signatures.
  core::Buffer<core::DEFAULT_IDENTITY_SIZE, 1024> buf;
  buf(ToBuffer(buf.data(), buf.size()));
  return core::Base32::Encode(buf.data(), buf.size());
}

std::string IdentityEx::ToBase64() const
{
  std::array<std::uint8_t, 1024> buf{{}};
  std::size_t len = ToBuffer(buf.data(), buf.size());
  std::string const encoded(core::Base64::Encode(buf.data(), len));
  return encoded;
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
      case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:  // 64 = 128 - 64
        ss << "Padding: " << (128 - kovri::core::ECDSAP256_KEY_LENGTH);
        break;
      case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:  // 32 = 128 - 96
        ss << "Padding: " << (128 - kovri::core::ECDSAP384_KEY_LENGTH);
        break;
      case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:  // 4 = 132 - 128
        ss << "Excess: " << (kovri::core::ECDSAP521_KEY_LENGTH - 128);
        break;
      case SIGNING_KEY_TYPE_RSA_SHA256_2048:  // 128 = 256 - 128
        ss << "Excess: " << (kovri::core::RSASHA2562048_KEY_LENGTH - 128);
        break;
      case SIGNING_KEY_TYPE_RSA_SHA384_3072:  // 256 = 384 - 128
        ss << "Excess: " << (kovri::core::RSASHA3843072_KEY_LENGTH - 128);
        break;
      case SIGNING_KEY_TYPE_RSA_SHA512_4096:  // 384 = 512 - 128
        ss << "Excess: " << (kovri::core::RSASHA5124096_KEY_LENGTH - 128);
        break;
      case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:  // 96 = 128 - 32
        ss << "Padding: " << (128 - crypto::PkLen::Ed25519);
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
  return kovri::core::DSA_SIGNATURE_LENGTH;
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
    return core::InputByteStream::Read<std::uint16_t>(
        m_ExtendedBuffer.get());  // signing key
  return SIGNING_KEY_TYPE_DSA_SHA1;
}

CryptoKeyType IdentityEx::GetCryptoKeyType() const {
  if (m_StandardIdentity.certificate.type ==
      CERTIFICATE_TYPE_KEY && m_ExtendedBuffer)
    return core::InputByteStream::Read<std::uint16_t>(
        m_ExtendedBuffer.get() + 2);  // crypto key
  return CRYPTO_KEY_TYPE_ELGAMAL;
}

void IdentityEx::CreateVerifier() const  {
  auto key_type = GetSigningKeyType();
  switch (key_type) {
    case SIGNING_KEY_TYPE_DSA_SHA1:
      m_Verifier = std::make_unique<kovri::core::DSAVerifier>(m_StandardIdentity.signing_key);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA256_P256: {
      std::size_t padding = 128 - kovri::core::ECDSAP256_KEY_LENGTH;  // 64 = 128 - 64
      m_Verifier =
        std::make_unique<kovri::core::ECDSAP256Verifier>(
            m_StandardIdentity.signing_key + padding);
      break;
    }
    case SIGNING_KEY_TYPE_ECDSA_SHA384_P384: {
      std::size_t padding = 128 - kovri::core::ECDSAP384_KEY_LENGTH;  // 32 = 128 - 96
      m_Verifier =
        std::make_unique<kovri::core::ECDSAP384Verifier>(
            m_StandardIdentity.signing_key + padding);
      break;
    }
    case SIGNING_KEY_TYPE_ECDSA_SHA512_P521: {
      std::uint8_t signing_key[kovri::core::ECDSAP521_KEY_LENGTH];
      memcpy(signing_key, m_StandardIdentity.signing_key, 128);
      std::size_t excess_len = kovri::core::ECDSAP521_KEY_LENGTH - 128;  // 4 = 132- 128
      memcpy(signing_key + 128, m_ExtendedBuffer.get() + 4, excess_len);  // right after signing and crypto key types
      m_Verifier = std::make_unique<kovri::core::ECDSAP521Verifier>(signing_key);
      break;
    }
    case SIGNING_KEY_TYPE_RSA_SHA256_2048: {
      std::uint8_t signing_key[kovri::core::RSASHA2562048_KEY_LENGTH];
      memcpy(signing_key, m_StandardIdentity.signing_key, 128);
      std::size_t excess_len = kovri::core::RSASHA2562048_KEY_LENGTH - 128;  // 128 = 256- 128
      memcpy(signing_key + 128, m_ExtendedBuffer.get() + 4, excess_len);
      m_Verifier = std::make_unique<kovri::core::RSASHA2562048Verifier>(signing_key);
      break;
    }
    case SIGNING_KEY_TYPE_RSA_SHA384_3072: {
      std::uint8_t signing_key[kovri::core::RSASHA3843072_KEY_LENGTH];
      memcpy(signing_key, m_StandardIdentity.signing_key, 128);
      std::size_t excess_len = kovri::core::RSASHA3843072_KEY_LENGTH - 128;  // 256 = 384- 128
      memcpy(signing_key + 128, m_ExtendedBuffer.get() + 4, excess_len);
      m_Verifier = std::make_unique<kovri::core::RSASHA3843072Verifier>(signing_key);
      break;
    }
    case SIGNING_KEY_TYPE_RSA_SHA512_4096: {
      std::uint8_t signing_key[kovri::core::RSASHA5124096_KEY_LENGTH];
      memcpy(signing_key, m_StandardIdentity.signing_key, 128);
      std::size_t excess_len = kovri::core::RSASHA5124096_KEY_LENGTH - 128;  // 384 = 512- 128
      memcpy(signing_key + 128, m_ExtendedBuffer.get() + 4, excess_len);
      m_Verifier = std::make_unique<kovri::core::RSASHA5124096Verifier>(signing_key);
      break;
    }
    case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519: {
      std::size_t padding = 128 - crypto::PkLen::Ed25519;  // 96 = 128 - 32
      m_Verifier = std::make_unique<kovri::core::Ed25519Verifier>(
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
    case SIGNING_KEY_TYPE_DSA_SHA1:
      m_Signer = std::make_unique<kovri::core::DSASigner>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
      m_Signer = std::make_unique<kovri::core::ECDSAP256Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
      m_Signer = std::make_unique<kovri::core::ECDSAP384Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
      m_Signer = std::make_unique<kovri::core::ECDSAP521Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_RSA_SHA256_2048:
      m_Signer = std::make_unique<kovri::core::RSASHA2562048Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_RSA_SHA384_3072:
      m_Signer = std::make_unique<kovri::core::RSASHA3843072Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_RSA_SHA512_4096:
      m_Signer = std::make_unique<kovri::core::RSASHA5124096Signer>(m_SigningPrivateKey);
    break;
    case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
      m_Signer = std::make_unique<kovri::core::Ed25519Signer>(m_SigningPrivateKey);
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
      case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
        kovri::core::CreateECDSAP256RandomKeys(
            keys.m_SigningPrivateKey,
            signing_public_key);
      break;
      case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
        kovri::core::CreateECDSAP384RandomKeys(
            keys.m_SigningPrivateKey,
            signing_public_key);
      break;
      case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
        kovri::core::CreateECDSAP521RandomKeys(
            keys.m_SigningPrivateKey,
            signing_public_key);
      break;
      case SIGNING_KEY_TYPE_RSA_SHA256_2048:
        kovri::core::CreateRSARandomKeys(
            kovri::core::RSASHA2562048_KEY_LENGTH,
            keys.m_SigningPrivateKey,
            signing_public_key);
      break;
      case SIGNING_KEY_TYPE_RSA_SHA384_3072:
        kovri::core::CreateRSARandomKeys(
            kovri::core::RSASHA3843072_KEY_LENGTH,
            keys.m_SigningPrivateKey,
            signing_public_key);
      break;
      case SIGNING_KEY_TYPE_RSA_SHA512_4096:
        kovri::core::CreateRSARandomKeys(
            kovri::core::RSASHA5124096_KEY_LENGTH,
            keys.m_SigningPrivateKey,
            signing_public_key);
      break;
      case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
        kovri::core::CreateEd25519KeyPair(
            keys.m_SigningPrivateKey, signing_public_key);
        break;
      default:
        LOG(warning)
          << "IdentityEx: Signing key type "
          << static_cast<int>(type) << " is not supported, creating DSA-SHA1";
        // fall-through
      case SIGNING_KEY_TYPE_DSA_SHA1:
        return PrivateKeys(kovri::core::CreateRandomKeys());  // DSA-SHA1
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
    kovri::core::CreateDSARandomKeys(
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

// TODO(unassigned): should not be a free function
IdentHash CreateRoutingKey(const IdentHash& ident)
{
  IdentHash key;
  try
    {
      if (ident.IsZero())
        throw std::invalid_argument("Identity: zero-initialized ident");

      // Get spec-defined formatted date
      std::string const date(GetFormattedDate());

      // Create buffer for key
      std::vector<std::uint8_t> buf(
          ident(), ident() + (ident.size() + date.size()));

      // Append the ISO date
      buf.insert(buf.end(), date.begin(), date.end());

      // Hash the key
      assert(key.size() <= buf.size());
      kovri::core::SHA256().CalculateDigest(key(), buf.data(), buf.size());
    }
  catch (...)
    {
      kovri::core::Exception ex(__func__);
      ex.Dispatch();
      throw;
    }
  return key;
}

// TODO(unassigned): should not be a free function
std::string GetFormattedDate()
{
  boost::gregorian::date date(boost::gregorian::day_clock::universal_day());
  return boost::gregorian::to_iso_string(date);
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
      case SIGNING_KEY_TYPE_DSA_SHA1:
        return "DSA_SHA1";
      case SIGNING_KEY_TYPE_ECDSA_SHA256_P256:
        return "ECDSA_SHA256_P256";
      case SIGNING_KEY_TYPE_ECDSA_SHA384_P384:
        return "ECDSA_SHA384_P384";
      case SIGNING_KEY_TYPE_ECDSA_SHA512_P521:
        return "ECDSA_SHA512_P521";
      case SIGNING_KEY_TYPE_RSA_SHA256_2048:
        return "RSA_SHA256_2048";
      case SIGNING_KEY_TYPE_RSA_SHA384_3072:
        return "RSA_SHA384_3072";
      case SIGNING_KEY_TYPE_RSA_SHA512_4096:
        return "RSA_SHA512_4096";
      case SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:
        return "EDDSA_SHA512_ED25519";
      default:
        LOG(error) << "Unknown signing key type " << key;
        return "";
    }
}

}  // namespace core
}  // namespace kovri
