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

#ifndef SRC_CORE_IDENTITY_H_
#define SRC_CORE_IDENTITY_H_

#include <inttypes.h>
#include <string.h>

#include <memory>
#include <string>

#include "crypto/elgamal.h"
#include "crypto/signature_base.h"
#include "util/base64.h"

namespace i2p {
namespace data {

// TODO(unassigned): review/consider moving this class into core/util
template<int Size>
class Tag {
 public:
  Tag(const uint8_t* buf) {
    memcpy(m_Buf, buf, Size);
  }
  Tag(const Tag<Size>&) = default;

#ifndef _WIN32
  Tag(Tag<Size>&&) = default;
#endif

  Tag() = default;

  Tag<Size>& operator= (const Tag<Size>&) = default;

#ifndef _WIN32
  Tag<Size>& operator= (Tag<Size>&&) = default;
#endif

  uint8_t* operator()() {
    return m_Buf;
  }

  const uint8_t* operator()() const {
    return m_Buf;
  }

  operator uint8_t* () {
    return m_Buf;
  }

  operator const uint8_t* () const {
    return m_Buf;
  }

  const uint64_t* GetLL() const {
    return ll;
  }

  bool operator==(const Tag<Size>& other) const {
    return !memcmp(m_Buf, other.m_Buf, Size);
  }

  bool operator<(const Tag<Size>& other) const {
    return memcmp(m_Buf, other.m_Buf, Size) < 0;
  }

  bool IsZero() const {
    for (int i = 0; i < Size / 8; i++)
    if (ll[i])
      return false;
    return true;
  }

  std::string ToBase64() const {
    char str[Size * 2];
    int l = i2p::util::ByteStreamToBase64(m_Buf, Size, str, Size * 2);
    str[l] = 0;
    return std::string(str);
  }

  std::string ToBase32() const {
    char str[Size * 2];
    int l = i2p::util::ByteStreamToBase32(m_Buf, Size, str, Size * 2);
    str[l] = 0;
    return std::string(str);
  }

  void FromBase32(
      const std::string& s) {
    i2p::util::Base32ToByteStream(s.c_str(), s.length(), m_Buf, Size);
  }

  void FromBase64(
      const std::string& s) {
    i2p::util::Base64ToByteStream(s.c_str(), s.length(), m_Buf, Size);
  }

 private:
  union {  // 8 bytes alignment
    uint8_t m_Buf[Size];
    uint64_t ll[Size / 8];
  };
};
typedef Tag<32> IdentHash;

#pragma pack(1)
struct Keys {
  uint8_t private_key[256];
  uint8_t signing_private_key[20];
  uint8_t public_key[256];
  uint8_t signing_key[128];
};

const uint8_t CERTIFICATE_TYPE_NULL = 0;
const uint8_t CERTIFICATE_TYPE_HASHCASH = 1;
const uint8_t CERTIFICATE_TYPE_HIDDEN = 2;
const uint8_t CERTIFICATE_TYPE_SIGNED = 3;
const uint8_t CERTIFICATE_TYPE_MULTIPLE = 4;
const uint8_t CERTIFICATE_TYPE_KEY = 5;

struct Identity {
  uint8_t public_key[256];
  uint8_t signing_key[128];

  struct {
    uint8_t type;
    uint16_t length;
  } certificate;

  Identity() = default;

  explicit Identity(
      const Keys& keys) {
    *this = keys;
  }

  Identity& operator=(const Keys& keys);

  size_t FromBuffer(
      const uint8_t* buf,
      size_t len);

  IdentHash Hash() const;
};
#pragma pack()
Keys CreateRandomKeys();

const size_t DEFAULT_IDENTITY_SIZE = sizeof(Identity);  // 387 bytes

const uint16_t CRYPTO_KEY_TYPE_ELGAMAL = 0;
const uint16_t SIGNING_KEY_TYPE_DSA_SHA1 = 0;
const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA256_P256 = 1;
const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA384_P384 = 2;
const uint16_t SIGNING_KEY_TYPE_ECDSA_SHA512_P521 = 3;
const uint16_t SIGNING_KEY_TYPE_RSA_SHA256_2048 = 4;
const uint16_t SIGNING_KEY_TYPE_RSA_SHA384_3072 = 5;
const uint16_t SIGNING_KEY_TYPE_RSA_SHA512_4096 = 6;
const uint16_t SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519 = 7;

typedef uint16_t SigningKeyType;
typedef uint16_t CryptoKeyType;

class IdentityEx {
 public:
  IdentityEx();
  ~IdentityEx();

  IdentityEx(
      const uint8_t* public_key,
      const uint8_t* signing_key,
      SigningKeyType type = SIGNING_KEY_TYPE_DSA_SHA1);

  IdentityEx(
      const uint8_t* buf,
      size_t len);

  IdentityEx(
      const IdentityEx& other);

  IdentityEx& operator=(const IdentityEx& other);

  IdentityEx& operator=(const Identity& standard);

  size_t FromBuffer(
      const uint8_t* buf,
      size_t len);

  size_t ToBuffer(
      uint8_t* buf,
      size_t len) const;

  size_t FromBase64(
      const std::string& s);

  std::string ToBase64() const;

  const Identity& GetStandardIdentity() const {
    return m_StandardIdentity;
  }

  const IdentHash& GetIdentHash() const {
    return m_IdentHash;
  }

  size_t GetFullLen() const {
    return m_ExtendedLen + DEFAULT_IDENTITY_SIZE;
  }

  size_t GetSigningPublicKeyLen() const;

  size_t GetSigningPrivateKeyLen() const;

  size_t GetSignatureLen() const;

  bool Verify(
      const uint8_t* buf,
      size_t len,
      const uint8_t* signature) const;

  SigningKeyType GetSigningKeyType() const;

  CryptoKeyType GetCryptoKeyType() const;

  void DropVerifier();  // to save memory

 private:
  void CreateVerifier() const;

 private:
  Identity m_StandardIdentity;
  IdentHash m_IdentHash;
  mutable std::unique_ptr<i2p::crypto::Verifier> m_Verifier;
  size_t m_ExtendedLen;
  std::unique_ptr<std::uint8_t[]> m_ExtendedBuffer;
};

class PrivateKeys {  // for eepsites
 public:
  PrivateKeys();
  ~PrivateKeys();

  PrivateKeys(
      const PrivateKeys& other)
      : m_Signer(nullptr) {
        *this = other;
      }

  explicit PrivateKeys(
      const Keys& keys)
      : m_Signer(nullptr) {
        *this = keys;
      }

  PrivateKeys& operator=(const Keys& keys);

  PrivateKeys& operator=(const PrivateKeys& other);

  const IdentityEx& GetPublic() const {
    return m_Public;
  }

  const uint8_t* GetPrivateKey() const {
    return m_PrivateKey;
  }

  const uint8_t* GetSigningPrivateKey() const {
    return m_SigningPrivateKey;
  }

  void Sign(
      const uint8_t* buf,
      int len,
      uint8_t* signature) const;

  size_t GetFullLen() const {
    return m_Public.GetFullLen() + 256 + m_Public.GetSigningPrivateKeyLen();
  }

  size_t FromBuffer(
      const uint8_t* buf,
      size_t len);

  size_t ToBuffer(
      uint8_t* buf,
      size_t len) const;

  size_t FromBase64(
      const std::string& s);

  std::string ToBase64() const;

  static PrivateKeys CreateRandomKeys(
      SigningKeyType type = SIGNING_KEY_TYPE_DSA_SHA1);

 private:
  void CreateSigner();

 private:
  IdentityEx m_Public;
  uint8_t m_PrivateKey[256];
  // assume private key doesn't exceed 1024 bytes
  uint8_t m_SigningPrivateKey[1024];
  std::unique_ptr<i2p::crypto::Signer> m_Signer;
};

// kademlia
struct XORMetric {
  union {
    uint8_t metric[32];
    uint64_t metric_ll[4];
  };

  void SetMin() {
    memset(metric, 0, 32);
  }

  void SetMax() {
    memset(metric, 0xFF, 32);
  }

  bool operator<(const XORMetric& other) const {
    return memcmp(metric, other.metric, 32) < 0;
  }
};

IdentHash CreateRoutingKey(
    const IdentHash& ident);

XORMetric operator^(
    const IdentHash& key1,
    const IdentHash& key2);

// destination for delivery instructions
class RoutingDestination {
 public:
  RoutingDestination() {}
  virtual ~RoutingDestination() {}

  virtual const IdentHash& GetIdentHash() const = 0;

  virtual const uint8_t* GetEncryptionPublicKey() const = 0;

  virtual bool IsDestination() const = 0;  // for garlic

  std::unique_ptr<const i2p::crypto::ElGamalEncryption>& GetElGamalEncryption() const {
    if (!m_ElGamalEncryption)
      m_ElGamalEncryption.reset(
          new i2p::crypto::ElGamalEncryption(GetEncryptionPublicKey()));
    return m_ElGamalEncryption;
  }

 private:
  // use lazy initialization
  mutable std::unique_ptr<const i2p::crypto::ElGamalEncryption> m_ElGamalEncryption;
};

class LocalDestination {
 public:
  virtual ~LocalDestination() {}

  virtual const PrivateKeys& GetPrivateKeys() const = 0;

  virtual const uint8_t* GetEncryptionPrivateKey() const = 0;

  virtual const uint8_t* GetEncryptionPublicKey() const = 0;

  const IdentityEx& GetIdentity() const {
    return GetPrivateKeys().GetPublic();
  }

  const IdentHash& GetIdentHash() const {
    return GetIdentity().GetIdentHash();
  }

  void Sign(
      const uint8_t* buf,
      int len,
      uint8_t* signature) const {
    GetPrivateKeys().Sign(
        buf,
        len,
        signature);
  }
};

}  // namespace data
}  // namespace i2p

#endif  // SRC_CORE_IDENTITY_H_
