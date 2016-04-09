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

#ifndef SRC_CORE_CRYPTO_ZIP_H_
#define SRC_CORE_CRYPTO_ZIP_H_

#include <memory>
#include <cstdint>

namespace i2p {
namespace crypto {

/**
 * @brief Public decompressing implemention
 * @class Decompressor
 */
class Decompressor {
 public:
  Decompressor();
  ~Decompressor();

  /// @brief Data to decompress
  /// @param Data buffer
  /// @param Data length
  void Put(
      std::uint8_t* buffer,
      std::size_t length);

  /// @brief Uncompressed data to retrieve
  /// @param Uncompressed data buffer
  /// @param Uncompressed data length
  void Get(
      std::uint8_t* buffer,
      std::size_t length);

  /// @brief Provides the number of bytes ready for retrieval
  /// @returns The number of bytes ready for retrieval
  std::size_t MaxRetrievable();

  /// @brief Verifies uncompressed data using CRC-32
  /// @param A pointer to an existing hash
  /// @param A pointer to input as buffer
  /// @param Length the size of the buffer
  bool Verify(
      std::uint8_t* hash,
      std::uint8_t* data,
      std::size_t length);

 private:
  class DecompressorImpl;
  std::unique_ptr<DecompressorImpl> m_DecompressorPimpl;
};

}  // namespace util
}  // namespace i2p

#endif  // SRC_CORE_UTIL_ZIP_H_
