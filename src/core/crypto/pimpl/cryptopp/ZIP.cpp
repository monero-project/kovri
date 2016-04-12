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

#include "util/ZIP.h"

#include <cryptopp/crc.h>
#include <cryptopp/zinflate.h>

#include <cstdint>

#include "util/Log.h"

namespace i2p {
namespace crypto {

class Decompressor::DecompressorImpl {
 public:
  /// @brief Puts data into decompressor (inflator)
  /// @param buffer A pointer to the byte buffer to process
  /// @param length Length of the size of string (in bytes)
  /// @return False on failure
  bool Put(
      std::uint8_t* buffer,
      std::size_t length) {
    // We must append a null byte. See #141.
    *buffer += '\0';
    length += 1;
    try {
      m_Inflator.Put(buffer, length);
      // Signal the end of messages to the object
      m_Inflator.MessageEnd();
    } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError,
          "Decompressor: could not put data. Exception: '", e.what(), "'");
      return false;
    }
    return true;
  }

  /// @brief Retrieve a block of uncompressed bytes
  /// @param buffer A pointer to a block of bytes
  /// @param length The number of bytes to Get
  /// @return False on failure
  bool Get(
      std::uint8_t* buffer,
      std::size_t length) {
    try {
      m_Inflator.Get(buffer, length);
    } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError,
          "Decompressor: could not get data. Exception: '", e.what(), "'");
      return false;
    }
    return true;
  }

  /// @brief Provides the number of bytes ready for retrieval
  /// @returns The number of bytes ready for retrieval
  std::size_t MaxRetrievable() {
    std::size_t max;
    try {
      max = m_Inflator.MaxRetrievable();
    } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError,
          "Decompressor: could not get max. Exception: '", e.what(), "'");
      max = 0;
    }
    return max;
  }

  /// @brief Verifies uncompressed data using CRC-32
  /// @param hash A pointer to an existing hash
  /// @param data A pointer to input as buffer
  /// @param length Length of the size of buffer (in bytes)
  /// @return False on failure
  bool Verify(
      std::uint8_t* hash,
      std::uint8_t* data,
      std::size_t length) {
    bool verify;
    try {
      verify = CryptoPP::CRC32().VerifyDigest(hash, data, length);
    } catch (CryptoPP::Exception& e) {
      LogPrint(eLogError,
          "Decompressor: could not verify digest. Exception: '", e.what(), "'");
      return false;
    }
    return verify;
  }

 private:
  CryptoPP::Inflator m_Inflator;
};

Decompressor::Decompressor()
    : m_DecompressorPimpl(new DecompressorImpl()) {}

Decompressor::~Decompressor() {}

void Decompressor::Put(
    std::uint8_t* buffer,
     std::size_t length) {
  m_DecompressorPimpl->Put(buffer, length);
}

void Decompressor::Get(
    std::uint8_t* buffer,
    std::size_t length) {
  m_DecompressorPimpl->Get(buffer, length);
}

std::size_t Decompressor::MaxRetrievable() {
  return m_DecompressorPimpl->MaxRetrievable();
}

bool Decompressor::Verify(
    std::uint8_t* hash,
    std::uint8_t* data,
    std::size_t length) {
  return m_DecompressorPimpl->Verify(hash, data, length);
}

}  // namespace crypto
}  // namespace i2p
