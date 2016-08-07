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

#ifndef SRC_CORE_CRYPTO_DIFFIEHELLMAN_H_
#define SRC_CORE_CRYPTO_DIFFIEHELLMAN_H_

#include <memory>
#include <cstdint>

namespace i2p {
namespace crypto {

/// @class DiffieHellman
/// @brief Diffie-Hellman
class DiffieHellman {
 public:
  DiffieHellman();
  ~DiffieHellman();

  /// @brief Generate private/public key pair
  /// @param private_key Private key
  /// @param public_key Public key
  void GenerateKeyPair(
      std::uint8_t* private_key,
      std::uint8_t* public_key);

  /// @brief Agreed value from your private key and other party's public key
  /// @param agreed_value Agreed upon value
  /// @param private_key Your private key
  /// @param other_public_key Other party's public key
  /// @return False on failure
  bool Agree(
      std::uint8_t* agreed_value,
      const std::uint8_t* private_key,
      const std::uint8_t* other_public_key);

 private:
  class DiffieHellmanImpl;
  std::unique_ptr<DiffieHellmanImpl> m_DiffieHellmanPimpl;
};

}  // namespace crypto
}  // namespace i2p

#endif  // SRC_CORE_CRYPTO_DIFFIEHELLMAN_H_
