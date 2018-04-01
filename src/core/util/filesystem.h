/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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

#ifndef SRC_CORE_UTIL_FILESYSTEM_H_
#define SRC_CORE_UTIL_FILESYSTEM_H_

#include <boost/filesystem.hpp>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "core/util/log.h"

namespace kovri {
namespace core {

/// @class StringStream
/// @details A wrapper for casting and strongly-typed classes
/// @param String to be treated as stream
class StringStream {
 public:
  StringStream();
  ~StringStream();

  /// @brief Stream to read from
  StringStream(const std::string& stream);

  /// @brief Stream to write to
  StringStream(std::string& stream);

  /// @brief Stream to write to using specified delimiter and terminator
  StringStream(const std::string& delimiter, const std::string& terminator);

  template <typename SizeCast = std::size_t, typename Buffer, typename Size>
  void Read(Buffer* buf, Size&& size)
  {
    m_Stream.read(
        reinterpret_cast<char*>(buf),
        static_cast<SizeCast>(std::forward<Size>(size)));
  }

  template <typename SizeCast = std::size_t, typename Buffer, typename Size>
  void Write(Buffer* buf, Size&& size)
  {
    m_Stream.write(
        reinterpret_cast<const char*>(buf),
        static_cast<SizeCast>(std::forward<Size>(size)));
  }

  template <typename SizeCast = std::size_t, typename Offset>
  void Seekg(Offset&& off, std::ios_base::seekdir way) {
    m_Stream.seekg(
      static_cast<SizeCast>(std::forward<Offset>(off)),
      way);
  }

  std::size_t Tellg() {
    return m_Stream.tellg();
  }

  bool EndOfFile() const {
    return m_Stream.eof() ? true : false;
  }

  std::string Str() const {
    return m_Stream.str();
  }

  void Str(const std::string& string)
  {
    m_Stream.str(string);
  }

  // TODO(anonimal): getter/setter for read stream size

 public:
  /// @return Tuple of key pair (key/value) + size read of stream
  // TODO(anonimal): std::pair refactor, use member for read stream size
  std::tuple<std::string, std::string, std::size_t> ReadKeyPair();

  /// @return String value of stream amount as described in byte
  std::string ReadStringFromByte();

  /// @brief Write key value pair (with delimiter and terminator) to stream
  /// @warning Writes size of key then key, size of value and then value
  void WriteKeyPair(const std::string& key, const std::string& value);

  /// @brief Write byte containing string length followed by string
  void WriteByteAndString(const std::string& string);

 public:
  void SetDelimiter(const std::string& delimiter) noexcept
  {
    m_Delimiter = delimiter;
  }

  const std::string& GetDelimiter() const noexcept
  {
    return m_Delimiter;
  }

  void SetTerminator(const std::string& terminator) noexcept
  {
    m_Terminator = terminator;
  }

  const std::string& GetTerminator() const noexcept
  {
    return m_Terminator;
  }

 private:
  std::stringstream m_Stream;
  std::string m_Delimiter, m_Terminator;
};

/// @class FileStream
/// @details A wrapper for iostream management
/// @param path : empty or "-" to use cin/cout, otherwise filename
template <typename StreamType, typename FileStreamType>
class FileStream {
 public:
  // TODO(anonimal): fix documentation

  /// @brief Read from stream
  /// @param buf : buffer to read from
  /// @param size : number of byte to read
  /// @return false on failure, true otherwise
  template <typename SizeCast = std::size_t, typename Buffer, typename Size>
  bool Read(Buffer* buf, Size&& size) {
    m_Stream->read(
        reinterpret_cast<char*>(buf),
        static_cast<SizeCast>(std::forward<Size>(size)));
    if (m_Stream->bad())
      {
        LOG(error) << "Error while reading input ! " << strerror(errno);
        return false;
      }
    return true;
  }

  /// @brief Read All data from stream
  /// @param size : number of byte read
  /// @return Allocated buffer, null ptr on failure
  template <typename Buffer, typename Size>
  std::unique_ptr<Buffer[]> ReadAll(Size* size)
  {
    std::unique_ptr<Buffer[]> buf;
    // Read input length and allocate buffer
    Seekg(0, std::ios_base::end);
    if (Fail())
      {
        LOG(error) << "FileStream: input does not support seekg ";
        return buf;
      }
    Size length = Tellg();
    LOG(trace) << "FileStream: input length " << length;
    if (length == 0)
      {
        LOG(error) << "FileStream: Empty input ";
        return buf;
      }
    *size = length;
    buf.reset(new Buffer[length + 1]);
    // Read input
    Seekg(0, std::ios_base::beg);
    if (!Read(buf.get(), length))
      {
        LOG(error) << "FileStream: Failed to read input";
        return buf;
      }
    return buf;
  }

  std::vector<std::uint8_t> ReadAll()
  {
    Seekg(0, std::ios::end);
    if (Fail())
      throw std::runtime_error("FileStream: input does not support seekg");

    const auto len = Tellg();
    LOG(trace) << "FileStream: input length " << len;
    if (!len)
      throw std::runtime_error("FileStream: empty input");

    Seekg(0, std::ios::beg);

    std::vector<std::uint8_t> buf(len);
    if (!Read(buf.data(), buf.size()))
      throw std::runtime_error("FileStream: Failed to read input");

    return buf;
  }

  /// @brief Write to stream
  /// @param buf : buffer to write to
  /// @param size : number of byte to write
  /// @return false on failure, true otherwise
  template <typename SizeCast = std::size_t, typename Buffer, typename Size>
  bool Write(Buffer* buf, Size&& size) {
    m_Stream->write(
        reinterpret_cast<char*>(buf),
        static_cast<SizeCast>(std::forward<Size>(size)));
    if (m_Stream->bad())
      {
        LOG(error) << "Error : Output to stream failed ! " << strerror(errno);
        return false;
      }

    m_Stream->flush();
    return true;
  }

  bool EndOfFile() const {
    return m_Stream->eof() ? true : false;
  }

  bool Fail() const {
    return m_Stream->fail() ? true : false;
  }

  bool Good() const {
    return m_Stream->good() ? true : false;
  }

  bool Bad() const {
    return m_Stream->bad() ? true : false;
  }

  std::streamsize Count() const {
    return m_Stream->gcount();
  }

  template <typename SizeCast = std::size_t, typename Offset>
  void Seekg(Offset&& off, std::ios_base::seekdir way)
  {
    m_Stream->seekg(static_cast<SizeCast>(std::forward<Offset>(off)), way);
  }

  std::size_t Tellg() const
  {
    return m_Stream->tellg();
  }

 protected:
  explicit FileStream(
      const std::string& path,
      std::ios_base::openmode mode,
      StreamType *def) {
    if (path.empty() || path == "-")  // from default stream
      m_Stream.reset(def, [](...) {});  // noop : don't delete
    else  // from file
      m_Stream.reset(new FileStreamType(path.c_str(), mode));
  }

 private:
  std::shared_ptr<StreamType> m_Stream;
};

/// @class InputFileStream
/// @details Specialization of FileStream for inputs
class InputFileStream : public FileStream<std::istream, std::ifstream> {
 public:
  explicit InputFileStream(
      const std::string& path,
      std::ios_base::openmode mode)
      : FileStream<std::istream, std::ifstream>(path, mode, &std::cin) {
  }
};

/// @class OutputFileStream
/// @details Specialization of FileStream for outputs
class OutputFileStream : public FileStream<std::ostream, std::ofstream> {
 public:
  explicit OutputFileStream(
      const std::string& path,
      std::ios_base::openmode mode)
      : FileStream<std::ostream, std::ofstream>(path, mode, &std::cout) {
  }
};

/// @brief Tests existence of path / creates if it does not exist
/// @param Boost.Filesystem path
/// @return Created path
const boost::filesystem::path EnsurePath(const boost::filesystem::path& path);

/// @brief Key for directory paths
enum struct Path : std::uint8_t
{
  /// @brief Kovri default data directory
  DefaultData,

  /// @brief Kovri data directory
  Data,

  /// @brief Core data directory
  Core,

  /// @brief Client data directory
  Client,

  /// @brief Configuration files
  Config,

  /// @brief Log storage
  Logs,

  /// @brief Network Database
  NetDb,

  /// @brief Peer Profiles
  Profiles,

  /// @brief X.509 certificates for TLS negotiation
  TLS,

  /// @brief X.509 certificates for SU3 verification
  SU3,

  /// @brief Address book related
  AddressBook,

  /// @brief Client (tunnel) keys
  ClientKeys,
};

/// @return Filesystem paths
/// @param path Key of which path to return
/// @notes On custom path, or default path:
///   Windows < Vista: C:\Documents and Settings\Username\Application Data\Kovri
///   Windows >= Vista: C:\Users\Username\AppData\Roaming\Kovri
///   OS X: ~/Library/Application Support/Kovri
///   *nix: ~/.kovri
boost::filesystem::path GetPath(Path path);

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_UTIL_FILESYSTEM_H_
