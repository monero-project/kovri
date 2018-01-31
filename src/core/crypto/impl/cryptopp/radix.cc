/**                                                                                           //
 * Copyright (c) 2015-2018, The Kovri I2P Router Project                                      //
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

#include "core/crypto/radix.h"

#include <cryptopp/base32.h>
#include <cryptopp/base64.h>

#include <cstdint>
#include <string>
#include <vector>

namespace kovri
{
namespace core
{
template <typename T>
std::string Radix<T>::m_Base32Alphabet("abcdefghijklmnopqrstuvwxyz234567");

const std::string& Base32::GetAlphabet() noexcept
{
  return m_Base32Alphabet;
}

std::string Base32::Encode(const std::uint8_t* in, const std::uint64_t len)
{
  // Prepare encoder
  CryptoPP::AlgorithmParameters static const params(CryptoPP::MakeParameters(
      CryptoPP::Name::EncodingLookupArray(),
      reinterpret_cast<const CryptoPP::byte*>(m_Base32Alphabet.c_str())));

  // Encode
  return Radix::Encode<CryptoPP::Base32Encoder>(params, in, len);
}

std::vector<std::uint8_t> Base32::Decode(
    const char* in,
    const std::uint64_t len)
{
  // Prepare decoder
  int lookup[256];
  CryptoPP::Base32Decoder::InitializeDecodingLookupArray(
      lookup,
      reinterpret_cast<const CryptoPP::byte*>(GetAlphabet().c_str()),
      GetAlphabet().size(),
      true);

  CryptoPP::AlgorithmParameters const params(CryptoPP::MakeParameters(
      CryptoPP::Name::DecodingLookupArray(),
      reinterpret_cast<const int*>(lookup)));

  // Decode
  return Radix::Decode<CryptoPP::Base32Decoder>(params, in, len);
}

template <typename T>
std::string Radix<T>::m_Base64Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~");

const std::string& Base64::GetAlphabet() noexcept
{
  return m_Base64Alphabet;
}

std::string Base64::Encode(const std::uint8_t* in, const std::uint64_t len)
{
  // Prepare encoder
  CryptoPP::AlgorithmParameters static const params(
      CryptoPP::MakeParameters(CryptoPP::Name::InsertLineBreaks(), false)(
          CryptoPP::Name::EncodingLookupArray(),
          reinterpret_cast<const CryptoPP::byte*>(m_Base64Alphabet.c_str())));

  // Encode
  return Radix::Encode<CryptoPP::Base64Encoder>(params, in, len);
}

std::vector<std::uint8_t> Base64::Decode(
    const char* in,
    const std::uint64_t len)
{
  // Prepare decoder
  int lookup[256];
  CryptoPP::Base64Decoder::InitializeDecodingLookupArray(
      lookup,
      reinterpret_cast<const CryptoPP::byte*>(m_Base64Alphabet.c_str()),
      GetAlphabet().size(),
      false);

  CryptoPP::AlgorithmParameters const params(CryptoPP::MakeParameters(
      CryptoPP::Name::DecodingLookupArray(),
      reinterpret_cast<const int*>(lookup)));

  // Decode
  return Radix::Decode<CryptoPP::Base64Decoder>(params, in, len);
}

}  // namespace core
}  // namespace kovri
