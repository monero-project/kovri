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
/// @class InputByteStream
/// @brief Wraps an array of bytes to provide stream-like functionality.
class InputByteStream
{
 public:
  InputByteStream() = default;

  /// @brief Constructs the byte stream from a given array of bytes
  /// @param data Pointer to the array of bytes
  /// @param len Length of the array of bytes
  InputByteStream(std::uint8_t* data, std::size_t len);

  /// @brief Advances the internal data pointer by the given amount
  /// @param amount the amount by which to advance the data pointer
  /// @throw std::length_error if amount exceeds the remaining data length
  void ConsumeData(std::size_t amount);

  /// @brief Consume a given amount of bytes + return a pointer to first consumed byte
  /// @return a pointer to the first byte that was consumed (m_Data + amount)
  /// @throw std::length_error if amount exceeds the remaining data length
  std::uint8_t* ReadBytes(std::size_t amount);

  /// @brief Reads unsigned integral value from stream byte(s)
  /// @note Converts from big endian to host order (when applicable)
  /// @return Size value read from byte(s)
  template <typename UInt>
  UInt Read()
  {
    static_assert(
        std::is_integral<UInt>::value || std::is_signed<UInt>(),
        "InputByteStream: invalid type (unsigned integral only)");

    UInt size;
    std::memcpy(&size, ReadBytes(sizeof(UInt)), sizeof(UInt));
    return boost::endian::big_to_native(size);
  }

 protected:
  std::uint8_t* m_Data;  ///< Pointer to first unparsed byte of the stream
  std::size_t m_Length{};  ///< Remaining length of the stream
};

/// @class OutputByteStream
/// @brief Wraps an array of bytes to provide stream-like functionality.
class OutputByteStream
{
 public:
  OutputByteStream() = default;

  /// @brief Constructs the byte stream from a given array of bytes
  /// @param data Pointer to the array of bytes
  /// @param len Length of the array of bytes
  OutputByteStream(std::uint8_t* data, std::size_t len);

  /// @brief Advances the internal data pointer by the given amount
  /// @param amount The amount by which to advance the data pointer
  /// @throw std::length_error if amount exceeds the remaining buffer length
  // TODO(unassigned): rename to something less confusing
  void ProduceData(std::size_t amount);

  /// @brief Writes data into buffer
  /// @note Increments buffer pointer position after writing data
  /// @param data Pointer to data to write
  /// @param len Length of data
  void WriteData(const std::uint8_t* data, std::size_t len);

  /// @brief Writes an unsigned integral value into buffer
  /// @note Converts data from host order to big endian (when applicable)
  /// @note Increments buffer pointer position after writing data
  /// @param data Data to write
  template <typename UInt>
  void Write(UInt data)
  {
    static_assert(
        std::is_integral<UInt>::value || std::is_signed<UInt>(),
        "InputByteStream: invalid type (unsigned integral only)");

    std::uint8_t buf[sizeof(data)] = {};
    const UInt value = boost::endian::native_to_big(data);

    std::memcpy(buf, &value, sizeof(value));
    WriteData(buf, sizeof(value));
  }

  // TODO(unassigned): see comments in #510

  /// @brief Get current pointer position of written data
  std::uint8_t* GetPosition() const;

  /// @brief Gets pointer to beginning of written data
  std::uint8_t* GetData() const;

  /// @brief Gets total stream size given during construction
  std::size_t GetSize() const;

 protected:
  std::uint8_t* m_Data;  ///< Pointer to the first unwritten byte
  std::size_t m_Length{};  ///< Remaining length of the stream
  std::size_t m_Counter{};  ///< Counter for amount of incremented data
  std::size_t m_Size{};  ///< Total size of stream given at initialization
};

/// @brief Returns hex encoding of given data
/// @param data Pointer to data
/// @param size Total size of data
const std::string GetFormattedHex(const std::uint8_t* data, std::size_t size);

/// @brief Returns vector of bytes representing address
/// @param address IP v4 or v6 address
std::unique_ptr<std::vector<std::uint8_t>> AddressToByteVector(
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
