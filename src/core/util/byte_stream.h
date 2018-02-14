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

#ifndef SRC_CORE_UTIL_BYTE_STREAM_H_
#define SRC_CORE_UTIL_BYTE_STREAM_H_

#include <boost/asio.hpp>
#include <boost/endian/conversion.hpp>

#include <cstddef>
#include <cstdint>
#include <ios>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace kovri
{
namespace core
{
// TODO(anonimal): our interfaces should use const pointer - but doing so will break
//   our current SSU implementation. Finish the SSU rewrite and use const correctness!
/// @class ByteStream
/// @brief Base class for I/O byte streaming
class ByteStream
{
 public:
  // TODO(anonimal): assert/throw nulls
  explicit ByteStream(std::uint8_t* data, std::size_t len);
  explicit ByteStream(std::size_t len);

  virtual ~ByteStream() = default;

  virtual void SkipBytes(std::size_t len) = 0;

  /// @brief Get the first unconsumed/unwritten byte in the stream
  /// @return Pointer to the first byte
  const std::uint8_t* Data() const noexcept
  {
    return m_Data - m_Counter;
  }

  /// @brief Total size of stream given at initialization
  /// @return Total size
  std::size_t Size() const noexcept
  {
    return m_Size;
  }

  /// @brief Get the current position in the stream
  /// @return Pointer to current byte position
  const std::uint8_t* Tellp() const noexcept
  {
    return m_Data;
  }

  /// @brief Remaining length of the stream after consumption/production
  std::size_t Gcount() const noexcept
  {
    return m_Length;
  }

 protected:
  std::uint8_t* m_Data;
  std::size_t m_Size, m_Length;
  std::size_t m_Counter;  ///< Counter for amount of incremented data

  /// @brief Advances the internal data pointer by the given amount
  /// @param len The amount by which to advance the data pointer
  /// @throw std::length_error if amount exceeds the remaining data length
  void Advance(std::size_t len);
};

/// @class InputByteStream
/// @brief Wraps an array of bytes to provide stream-like functionality.
class InputByteStream : public ByteStream
{
 public:
  /// @brief Constructs the byte stream from a given array of bytes
  /// @param data Pointer to the array of bytes
  /// @param len Length of the array of bytes
  explicit InputByteStream(std::uint8_t* data, std::size_t len);

  virtual ~InputByteStream() = default;

  /// @brief Advances internal pointer
  /// @param len Number of bytes to skip
  virtual void SkipBytes(std::size_t len);

  /// @brief Consume a given amount of bytes + return a pointer to first consumed byte
  /// @return a pointer to the first byte that was consumed (m_Data + amount)
  /// @throw std::length_error if amount exceeds the remaining data length
  std::uint8_t* ReadBytes(std::size_t amount);

  /// @brief Reads unsigned integral value from given buffer
  /// @param buf Buffer to read from
  /// @return Unsigned integral value read from byte(s)
  /// @param big_to_native Endian conversion from big endian to host endian
  template <typename UInt>
  static UInt Read(const std::uint8_t* buf, const bool big_to_native = true)
  {
    static_assert(
        std::is_integral<UInt>::value || std::is_signed<UInt>(),
        "InputByteStream: invalid type (unsigned integral only)");

    UInt size;
    std::memcpy(&size, buf, sizeof(size));
    if (big_to_native)
      boost::endian::big_to_native_inplace(size);
    return size;
  }

  /// @brief Reads unsigned integral value from stream byte(s)
  /// @return Unsigned integral value read from byte(s)
  template <typename UInt>
  UInt Read(const bool big_to_native = true)
  {
    return Read<UInt>(ReadBytes(sizeof(UInt)), big_to_native);
  }
};

/// @class OutputByteStream
/// @brief Wraps an array of bytes to provide stream-like functionality.
class OutputByteStream : public ByteStream
{
 public:
  /// @brief Constructs the byte stream from a given array of bytes
  /// @param data Pointer to the array of bytes
  /// @param len Length of the array of bytes
  explicit OutputByteStream(std::uint8_t* data, std::size_t len);

  /// @brief Constructs the byte stream with a given number of bytes
  /// @param len Length of bytes to construct
  explicit OutputByteStream(std::size_t len);

  virtual ~OutputByteStream() = default;

  /// @brief Advances internal pointer after writing zero-initialized memory
  /// @param len Number of bytes to "skip"
  virtual void SkipBytes(std::size_t len);

  /// @brief Writes data into data member buffer
  /// @note Increments buffer pointer position after writing data
  /// @param data Pointer to data to write
  /// @param len Length of data
  /// @param allow_null_data Allow setting data member buffer with len constant byte 0
  void WriteData(
      const std::uint8_t* data,
      const std::size_t len,
      const bool allow_null_data = false);

  /// @brief Writes an unsigned integral value into given buffer
  /// @note Converts data from host order to big endian (when applicable)
  /// @param buf Buffer to write to
  /// @param data Data to write
  /// @param native_to_big Endian conversion from host endian to big endian
  template <typename UInt>
  static void
  Write(std::uint8_t* buf, UInt data, const bool native_to_big = true)
  {
    static_assert(
        std::is_integral<UInt>::value || std::is_signed<UInt>(),
        "OutputByteStream: invalid type (unsigned integral only)");

    if (native_to_big)
      boost::endian::native_to_big_inplace(data);
    std::memcpy(buf, &data, sizeof(data));
  }

  /// @brief Writes an unsigned integral value into member 'stream'
  /// @note Increments buffer pointer position after writing data
  /// @param data Data to write
  template <typename UInt>
  void Write(UInt data, const bool native_to_big = true)
  {
    std::uint8_t buf[sizeof(data)]{};
    Write(buf, data, native_to_big);  // Write to buffer
    WriteData(buf, sizeof(buf));  // Write buffer to stream
  }
};

/// @brief Returns hex encoding of given data
/// @param data Pointer to data
/// @param size Total size of data
const std::string GetFormattedHex(const std::uint8_t* data, std::size_t size);

/// @brief Returns vector of bytes representing address
/// @param address IP v4 or v6 address
std::vector<std::uint8_t> AddressToByteVector(
    const boost::asio::ip::address& address);

// TODO(anonimal): remove from global namespace
namespace
{
/// @brief Return underlying type (for enumerators)
/// @param type Enumerator
/// @warning Should be used with enumerations only
/// @notes  C++14 required, courtesy of Scott Meyers (2014)
template <typename T>
constexpr auto GetType(T type) noexcept
{
  return static_cast<std::underlying_type_t<T>>(type);
}
}  // namespace

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_UTIL_BYTE_STREAM_H_
