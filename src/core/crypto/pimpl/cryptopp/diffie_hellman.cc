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

#include "crypto/diffie_hellman.h"

#include <cryptopp/dh.h>
#include <cryptopp/osrng.h>

#include <cstdint>

#include "crypto_const.h"
#include "util/log.h"

namespace i2p {
namespace crypto {

/// @class DiffieHellmanImpl
/// @brief Diffie-Hellman implementation
class DiffieHellman::DiffieHellmanImpl {
 public:
  /// @brief Initializes with ElGamal constants on construction
  DiffieHellmanImpl()
      : m_DH(i2p::crypto::elgp, i2p::crypto::elgg) {}

  /// @brief Generate private/public key pair
  /// @param private_key Private key
  /// @param public_key Public key
  void GenerateKeyPair(
      std::uint8_t* private_key,
      std::uint8_t* public_key) {
    try {
      m_DH.GenerateKeyPair(
          m_PRNG,
          private_key,
          public_key);
    } catch (CryptoPP::Exception e) {
      LogPrint(eLogError,
          "DiffieHellman: GenerateKeyPair() caught exception '", e.what(), "'");
    }
  }

  /// @brief Agreed value from your private key and other party's public key
  /// @param agreed_value Agreed upon value
  /// @param private_key Your private key
  /// @param other_public_key Other party's public key
  /// @return False on failure
  bool Agree(
      std::uint8_t* agreed_value,
      const std::uint8_t* private_key,
      const std::uint8_t* other_public_key) {
    return m_DH.Agree(
        agreed_value,
        private_key,
        other_public_key);
  }

 private:
  CryptoPP::DH m_DH;
  CryptoPP::AutoSeededRandomPool m_PRNG;
};

DiffieHellman::DiffieHellman()
    : m_DiffieHellmanPimpl(
          std::make_unique<DiffieHellmanImpl>()) {}

DiffieHellman::~DiffieHellman() {}

void DiffieHellman::GenerateKeyPair(
    std::uint8_t* private_key,
    std::uint8_t* public_key) {
  m_DiffieHellmanPimpl->GenerateKeyPair(
      private_key,
      public_key);
}

bool DiffieHellman::Agree(
    std::uint8_t* agreed_value,
    const std::uint8_t* private_key,
    const std::uint8_t* other_public_key) {
  return m_DiffieHellmanPimpl->Agree(
      agreed_value,
      private_key,
      other_public_key);
}

}  // namespace crypto
}  // namespace i2p
