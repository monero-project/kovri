/**                                                                                           //
 * Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
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
 *                                                                                            //
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project          //
 */

#ifndef SRC_CORE_UTIL_TAG_H_
#define SRC_CORE_UTIL_TAG_H_

#include <cassert>
#include <cstdint>
#include <cstring>

#include <exception>
#include <string>
#include <vector>

#include "core/crypto/radix.h"

namespace kovri
{
namespace core
{
// TODO(anonimal): realistically, we'll never need this large a type.
//   The only need is for our HMAC impl but that should be re-written
//   so we don't suffer performance loss everywhere else Tag is used.
template <std::uint64_t Size>
class alignas(8) Tag
{
 public:
  static_assert(Size, "Null tag size not allowed");
  static_assert(Size % 8 == 0, "The tag size must be a multiple of 8.");

  Tag() : m_Buf{} {}

  Tag(const std::uint8_t* buf)
  {
    assert(buf);
    if (!buf)
      throw std::invalid_argument("Null buffer not allowed");
    std::memcpy(m_Buf, buf, Size);
  }

  std::uint8_t* operator()()
  {
    return m_Buf;
  }

  const std::uint8_t* operator()() const
  {
    return m_Buf;
  }

  operator std::uint8_t*()
  {
    return m_Buf;
  }

  operator const std::uint8_t*() const
  {
    return m_Buf;
  }

  const std::uint64_t* GetLL() const
  {
    return reinterpret_cast<const std::uint64_t*>(m_Buf);
  }

  bool operator==(const Tag<Size>& other) const
  {
    return !std::memcmp(m_Buf, other.m_Buf, Size);
  }

  bool operator<(const Tag<Size>& other) const
  {
    return std::memcmp(m_Buf, other.m_Buf, Size) < 0;
  }

  bool IsZero() const
  {
    for (std::uint64_t i = 0; i < Size / 8; i++)
      if (GetLL()[i])
        return false;
    return true;
  }

  std::string ToBase32() const
  {
    return core::Base32::Encode(m_Buf, Size);
  }

  std::string ToBase64() const
  {
    return core::Base64::Encode(m_Buf, Size);
  }

  void FromBase32(const std::string& encoded)
  {
    std::vector<std::uint8_t> const decoded =
        core::Base32::Decode(encoded.c_str(), encoded.length());

    if (decoded.size() > Size)
      throw std::length_error("Tag: decoded base32 size too large");

    std::memcpy(m_Buf, decoded.data(), decoded.size());
  }

  void FromBase64(const std::string& encoded)
  {
    std::vector<std::uint8_t> const decoded =
        core::Base64::Decode(encoded.c_str(), encoded.length());

    if (decoded.size() > Size)
      throw std::length_error("Tag: decoded base64 size too large");

    std::memcpy(m_Buf, decoded.data(), decoded.size());
  }

  decltype(Size) size() const
  {
    return Size;
  }

 private:
  std::uint8_t m_Buf[Size];  ///< 8-byte aligned.
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_UTIL_TAG_H_
