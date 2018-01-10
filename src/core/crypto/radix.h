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

#ifndef SRC_CORE_CRYPTO_RADIX_H_
#define SRC_CORE_CRYPTO_RADIX_H_

#include <cstdint>
#include <string>
#include <vector>

#include <cryptopp/base32.h>
#include <cryptopp/base64.h>

namespace kovri
{
namespace core
{
class RadixBase
{
 public:
  virtual ~RadixBase() = default;

  virtual std::string RadixEncode(
      const std::uint8_t* in,
      const std::uint64_t len) = 0;

  virtual std::vector<std::uint8_t> RadixDecode(
      const char* in,
      const std::uint64_t len) = 0;

  virtual std::string RadixGetAlphabet() = 0;
};

template <class T>
class Radix : public RadixBase
{
 public:
  virtual ~Radix() = default;

  virtual std::string RadixEncode(
      const std::uint8_t* in,
      const std::uint64_t len)
  {
    return T::Encode(in, len);
  }

  virtual std::vector<std::uint8_t> RadixDecode(
      const char* in,
      const std::uint64_t len)
  {
    return T::Decode(in, len);
  }

  virtual std::string RadixGetAlphabet()
  {
    return T::GetAlphabet();
  }

 protected:
  static std::string m_Base32Alphabet, m_Base64Alphabet;

  template <typename Base_N>
  static std::string Encode(
      const CryptoPP::AlgorithmParameters& params,
      const std::uint8_t* in,
      const std::uint64_t len)
  {
    if (!in || !len)
      throw std::runtime_error("Encoder: null arg(s)");

    Base_N encoder;
    encoder.IsolatedInitialize(params);

    std::string out;
    encoder.Attach(new CryptoPP::StringSink(out));
    encoder.Put(in, len);
    encoder.MessageEnd();

    return out;
  }

  template <typename Base_N>
  static std::vector<std::uint8_t> Decode(
      const CryptoPP::AlgorithmParameters& params,
      const char* in,
      const std::uint64_t len)
  {
    if (!in || !len)
      throw std::runtime_error("Decoder: null arg(s)");

    Base_N decoder;
    decoder.IsolatedInitialize(params);
    decoder.Put(reinterpret_cast<const CryptoPP::byte*>(in), len);
    decoder.MessageEnd();

    const CryptoPP::word64 size = decoder.MaxRetrievable();
    if (!size || size > SIZE_MAX)
      throw std::runtime_error("Radix: invalid decoded size");

    std::vector<std::uint8_t> out(size);
    decoder.Get(reinterpret_cast<CryptoPP::byte*>(&out[0]), out.size());

    return out;
  }
};

/// @brief Base32 implementation
/// @details Replaces DUDE with RFC 4648 alphabet
class Base32 final : public Radix<Base32>
{
 public:
  /// @brief RFC 4648 alphabet Base32 encoder
  /// @param in Decoded data
  /// @param len Size of decoded data
  /// @return String of encoded data
  static std::string Encode(const std::uint8_t* in, const std::uint64_t len);

  /// @brief RFC 4648 alphabet Base32 decoder
  /// @param in Encoded data
  /// @param len Size of Encoded data
  /// @return Byte vector of decoded data
  static std::vector<std::uint8_t> Decode(
      const char* in,
      const std::uint64_t len);

  /// @returns RFC 4648 base32 alphabet
  static const std::string& GetAlphabet() noexcept;
};

/// @brief Base64 implementation
/// @details Replaces RFC 4648 with I2P-defined alphabet
class Base64 final : public Radix<Base64>
{
 public:
  /// @brief I2P alphabet Base64 encoder
  /// @param in Decoded data
  /// @param len Size of decoded data
  /// @return String of encoded data
  static std::string Encode(const std::uint8_t* in, const std::uint64_t len);

  /// @brief I2P alphabet Base64 decoder
  /// @param in Encoded data
  /// @param len Size of Encoded data
  /// @return Byte vector of decoded data
  static std::vector<std::uint8_t> Decode(
      const char* in,
      const std::uint64_t len);

  /// @brief I2P base64 alphabet
  static const std::string& GetAlphabet() noexcept;
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_CRYPTO_RADIX_H_
