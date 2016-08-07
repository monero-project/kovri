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

#ifndef SRC_CORE_CRYPTO_UTIL_COMPRESSION_H_
#define SRC_CORE_CRYPTO_UTIL_COMPRESSION_H_

#include <memory>
#include <cstdint>

namespace i2p {
namespace crypto {
namespace util {

/// @class DeflateDecompressor
/// @brief RFC 1951 DEFLATE Decompressor
class DeflateDecompressor {
 public:
  DeflateDecompressor();
  ~DeflateDecompressor();

  /// @brief Input a byte buffer for processing
  /// @param buffer The byte buffer to process
  /// @param length The size of the string, in bytes
  /// @returns The number of bytes that remain in the block
  ///   (i.e., bytes not processed)
  std::size_t Put(
      std::uint8_t* buffer,
      std::size_t length);

  /// @brief Retrieve a block of bytes
  /// @param buffer A block of bytes
  /// @param length The number of bytes to get
  /// @returns The number of bytes consumed during the call
  /// @details Use the return value of to detect short reads
  std::size_t Get(
      std::uint8_t* buffer,
      std::size_t length);

  /// @brief Provides the number of bytes ready for retrieval
  /// @returns The number of bytes ready for retrieval
  std::size_t MaxRetrievable();

  /// @brief Verifies uncompressed data using CRC-32
  /// @param hash A pointer to an existing hash
  /// @param data A pointer to input as buffer
  /// @param length Length the size of the buffer
  /// @return False on failure
  bool Verify(
      std::uint8_t* hash,
      std::uint8_t* data,
      std::size_t length);

 private:
  class DeflateDecompressorImpl;
  std::unique_ptr<DeflateDecompressorImpl> m_DeflateDecompressorPimpl;
};

/// @class Gzip
/// @brief RFC 1952 GZIP Compressor
class Gzip {
 public:
  Gzip();
  ~Gzip();

  /// @brief Gets library's minimum deflate level
  /// @return Minimum deflate level
  std::size_t GetMinDeflateLevel();

  /// @brief Gets library's default deflate level
  /// @return Default deflate level
  std::size_t GetDefaultDeflateLevel();

  /// @brief Gets library's default deflate level
  /// @return Maximum deflate level
  std::size_t GetMaxDeflateLevel();

  /// @brief Sets compression deflate level
  void SetDeflateLevel(
      std::size_t level);

  /// @brief Input a byte buffer for processing
  /// @param buffer The byte buffer to process
  /// @param length The size of the string, in bytes
  /// @returns The number of bytes that remain in the block
  ///   (i.e., bytes not processed)
  std::size_t Put(
      const std::uint8_t* buffer,
      std::size_t length);

  /// @brief Retrieve a block of bytes
  /// @param buffer A block of bytes
  /// @param length The number of bytes to get
  /// @returns The number of bytes consumed during the call
  /// @details Use the return value of to detect short reads
  std::size_t Get(
      std::uint8_t* buffer,
      std::size_t length);

  /// @brief Provides the number of bytes ready for retrieval
  /// @returns The number of bytes ready for retrieval
  std::size_t MaxRetrievable();

 private:
  class GzipImpl;
  std::unique_ptr<GzipImpl> m_GzipPimpl;
};

/// @class Gunzip
/// @brief RFC 1952 GZIP Decompressor
class Gunzip {
 public:
  Gunzip();
  ~Gunzip();

  /// @brief Input a byte buffer for processing
  /// @param buffer The byte buffer to process
  /// @param length The size of the string, in bytes
  /// @returns The number of bytes that remain in the block
  ///   (i.e., bytes not processed)
  std::size_t Put(
      const std::uint8_t* buffer,
      std::size_t length);

  /// @brief Retrieve a block of bytes
  /// @param buffer A block of bytes
  /// @param length The number of bytes to get
  /// @returns The number of bytes consumed during the call
  /// @details Use the return value of to detect short reads
  std::size_t Get(
      std::uint8_t* buffer,
      std::size_t length);

  /// @brief Provides the number of bytes ready for retrieval
  /// @returns The number of bytes ready for retrieval
  std::size_t MaxRetrievable();

 private:
  class GunzipImpl;
  std::unique_ptr<GunzipImpl> m_GunzipPimpl;
};

}  // namespace util
}  // namespace crypto
}  // namespace i2p

#endif  // SRC_CORE_CRYPTO_UTIL_COMPRESSION_H_
