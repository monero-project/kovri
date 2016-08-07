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

#ifndef SRC_CORE_CRYPTO_UTIL_CHECKSUM_H_
#define SRC_CORE_CRYPTO_UTIL_CHECKSUM_H_

#include <cstdint>
#include <memory>

namespace i2p {
namespace crypto {
namespace util {

/// @class Adler32
/// @brief Adler-32
class Adler32 {
 public:
  Adler32();
  ~Adler32();

  /// @brief Updates the hash with additional input and
  ///   computes the hash of the current message
  /// @details Only use this if your input is in one piece
  /// @details CalculateDigest() restarts the hash for the next message
  /// @param digest A pointer to the buffer to receive the hash
  /// @param input The additional input as a buffer
  /// @param length The size of the buffer, in bytes
  void CalculateDigest(
      std::uint8_t* digest,
      const std::uint8_t* input,
      std::size_t length);

  /// @brief Updates the hash with additional input and
  ///   verifies the hash of the current message
  /// @details Only use this if your input is in one piece
  /// @details Restarts the hash for the next nmessage.
  /// @param digest A pointer to the buffer of an existing hash
  /// @param input The additional input as a buffer
  /// @param length The size of the buffer, in bytes
  /// @returns True if the existing hash matches the computed hash
  std::size_t VerifyDigest(
      std::uint8_t* digest,
      const std::uint8_t* input,
      std::size_t length);

 private:
  class Adler32Impl;
  std::unique_ptr<Adler32Impl> m_Adler32Pimpl;
};

}  // namespace util
}  // namespace crypto
}  // namespace i2p

#endif  // SRC_CORE_CRYPTO_UTIL_CHECKSUM_H_
