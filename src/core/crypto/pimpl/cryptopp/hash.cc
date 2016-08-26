/**                                                                                           //
 * Copyright (c) 2015-2016, The Kovri I2P Router Project                                      //
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
 */

#include "crypto/hash.h"

#include <cryptopp/md5.h>
#include <cryptopp/sha.h>

#include <cstdint>

#include "util/log.h"

namespace i2p {
namespace crypto {

/**
 *
 * MD5
 *
 */

/// @class MD5Impl
/// @brief MD5 implementation
class MD5::MD5Impl {
 public:
  MD5Impl() {}
  ~MD5Impl() {}

  void CalculateDigest(
      std::uint8_t* digest,
      const std::uint8_t* input,
      std::size_t length) {
    try {
      m_MD5.CalculateDigest(
          digest,
          input,
          length);
    } catch (CryptoPP::Exception e) {
      LogPrint(eLogError,
          "MD5Impl: CalculateDigest() caught exception '", e.what(), "'");
    }
  }

 private:
  CryptoPP::Weak1::MD5 m_MD5;
};

MD5::MD5()
    : m_MD5Pimpl(
          std::make_unique<MD5Impl>()) {}

MD5::~MD5() {}

void MD5::CalculateDigest(
    std::uint8_t* digest,
    const std::uint8_t* input,
    std::size_t length) {
  m_MD5Pimpl->CalculateDigest(digest, input, length);
}

/**
 *
 * SHA256
 *
 */

/// @class SHA256Impl
/// @brief SHA256 implementation
class SHA256::SHA256Impl {
 public:
  SHA256Impl() {}
  ~SHA256Impl() {}

  void CalculateDigest(
      std::uint8_t* digest,
      const std::uint8_t* input,
      std::size_t length) {
    try {
      m_SHA256.CalculateDigest(
          digest,
          input,
          length);
    } catch (CryptoPP::Exception e) {
      LogPrint(eLogError,
          "SHA256Impl: CalculateDigest() caught exception '", e.what(), "'");
    }
  }

  std::size_t VerifyDigest(
      std::uint8_t* digest,
      const std::uint8_t* input,
      std::size_t length) {
    return m_SHA256.VerifyDigest(
          digest,
          input,
          length);
  }

 private:
  CryptoPP::SHA256 m_SHA256;
};

SHA256::SHA256()
    : m_SHA256Pimpl(
          std::make_unique<SHA256Impl>()) {}

SHA256::~SHA256() {}

void SHA256::CalculateDigest(
    std::uint8_t* digest,
    const std::uint8_t* input,
    std::size_t length) {
  m_SHA256Pimpl->CalculateDigest(digest, input, length);
}

std::size_t SHA256::VerifyDigest(
    std::uint8_t* digest,
    const std::uint8_t* input,
    std::size_t length) {
  return m_SHA256Pimpl->VerifyDigest(digest, input, length);
}

/**
 *
 * SHA512
 *
 */

/// @class SHA512Impl
/// @brief SHA512 implementation
class SHA512::SHA512Impl {
 public:
  SHA512Impl() {}
  ~SHA512Impl() {}

  void CalculateDigest(
      std::uint8_t* digest,
      const std::uint8_t* input,
      std::size_t length) {
    try {
      m_SHA512.CalculateDigest(
          digest,
          input,
          length);
    } catch (CryptoPP::Exception e) {
      LogPrint(eLogError,
          "SHA512Impl: CalculateDigest() caught exception '", e.what(), "'");
    }
  }

  void Update(
      const std::uint8_t* input,
      std::size_t length) {
    try {
      m_SHA512.Update(input, length);
    } catch (CryptoPP::Exception e) {
      LogPrint(eLogError,
          "SHA512Impl: Update() caught exception '", e.what(), "'");
    }
  }

  void Final(
      std::uint8_t* digest) {
    try {
      m_SHA512.Final(digest);
    } catch (CryptoPP::Exception e) {
      LogPrint(eLogError,
          "SHA512Impl: Final() caught exception '", e.what(), "'");
    }
  }

 private:
  CryptoPP::SHA512 m_SHA512;
};

SHA512::SHA512()
    : m_SHA512Pimpl(
          std::make_unique<SHA512Impl>()) {}

SHA512::~SHA512() {}

void SHA512::CalculateDigest(
    std::uint8_t* digest,
    const std::uint8_t* input,
    std::size_t length) {
  m_SHA512Pimpl->CalculateDigest(digest, input, length);
}

void SHA512::Update(
    const std::uint8_t* input,
    std::size_t length) {
  m_SHA512Pimpl->Update(input, length);
}

void SHA512::Final(
    std::uint8_t* digest) {
  m_SHA512Pimpl->Final(digest);
}

}  //  namespace crypto
}  //  namespace i2p
