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

#ifndef SRC_CORE_UTIL_BUFFER_H_
#define SRC_CORE_UTIL_BUFFER_H_

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <exception>
#include <string>

namespace kovri
{
namespace core
{
// TODO(anonimal): Boost.Buffer?
// TODO(anonimal): SecBlock buffer
// TODO(anonimal): This class should eventually replace Tag

/// @brief A simple mutable array with sliding scale of element count (similar to vector)
template <std::size_t MinElem = 0, std::size_t MaxElem = 4096>
class Buffer final
{
  static_assert(MaxElem, "Null max size");

 public:
  Buffer() : m_Length(MaxElem) {}

  Buffer(const std::uint8_t* buf, const std::size_t len)
  {
    set_buffer(buf, len);
  }

  explicit Buffer(const std::size_t len)
  {
    set_length(len);
  }

  explicit Buffer(const Buffer&) = delete;

  ~Buffer() = default;

  bool operator==(Buffer& other)
  {
    return (get() == other.get() && size() == other.size());
  }

  bool operator!=(Buffer& other)
  {
    return (get() != other.get() || size() != other.size());
  }

  void operator()(const std::uint8_t* buf, const std::size_t len)
  {
    set_buffer(buf, len);
  }

  std::size_t operator()(const std::size_t len)
  {
    return set_length(len);
  }

 public:
  const auto& get() const noexcept
  {
    return m_Buffer;
  }

  const std::uint8_t* data() const noexcept
  {
    return m_Buffer.data();
  }

  std::uint8_t* data() noexcept
  {
    return m_Buffer.data();
  }

  std::size_t capacity() const noexcept
  {
    return m_Buffer.size();
  }

  std::size_t size() const noexcept
  {
    return m_Length;
  }

  void clear()
  {
    m_Buffer.fill(0);
    m_Length = 0;
  }

 private:
  void set_buffer(
      const std::uint8_t* data,
      const std::size_t len)
  {
    assert(data || len);

    if (!data)
      throw std::invalid_argument("Buffer: null source");

    std::copy(data, data + set_length(len), m_Buffer.begin());
  }

  std::size_t set_length(const std::size_t len)
  {
    assert(len);

    if (len < MinElem || len > MaxElem)
      throw std::length_error("Buffer: invalid length" + std::to_string(len));

    m_Length = len;
    return m_Length;
  }

 private:
  std::array<std::uint8_t, MaxElem> m_Buffer{{}};
  std::size_t m_Length{};  ///< Number of expected elements
};
}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_UTIL_BUFFER_H_
