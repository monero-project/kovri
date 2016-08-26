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

#include "crypto/util/checksum.h"

#include <cryptopp/adler32.h>

#include <cstdint>

#include "util/log.h"

namespace i2p {
namespace crypto {
namespace util {

/// @class Adler32Impl
/// @brief Adler-32 implementation
class Adler32::Adler32Impl {
 public:
  Adler32Impl() {}
  ~Adler32Impl() {}

  void CalculateDigest(
      std::uint8_t* digest,
      const std::uint8_t* input,
      std::size_t length) {
    try {
      m_Adler32.CalculateDigest(
          digest,
          input,
          length);
    } catch (CryptoPP::Exception e) {
      LogPrint(eLogError,
          "Adler32: CalculateDigest() caught exception '", e.what(), "'");
    }
  }

  std::size_t VerifyDigest(
      std::uint8_t* digest,
      const std::uint8_t* input,
      std::size_t length) {
    return m_Adler32.VerifyDigest(
          digest,
          input,
          length);
  }

 private:
  CryptoPP::Adler32 m_Adler32;
};

Adler32::Adler32()
    : m_Adler32Pimpl(
          std::make_unique<Adler32Impl>()) {}

Adler32::~Adler32() {}

void Adler32::CalculateDigest(
    std::uint8_t* digest,
    const std::uint8_t* input,
    std::size_t length) {
  m_Adler32Pimpl->CalculateDigest(digest, input, length);
}

std::size_t Adler32::VerifyDigest(
    std::uint8_t* digest,
    const std::uint8_t* input,
    std::size_t length) {
  return m_Adler32Pimpl->VerifyDigest(digest, input, length);
}

}  // namespace util
}  // namespace crypto
}  // namespace i2p
