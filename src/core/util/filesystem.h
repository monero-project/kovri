/**                                                                                           //
 * Copyright (c) 2013-2016, The Kovri I2P Router Project                                      //
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
#include <sstream>
#include <string>

namespace i2p {
namespace util {
namespace filesystem {

/// @class StringStream
/// @details A wrapper for casting and strongly-typed classes
/// @param String to be treated as stream
class StringStream {
 public:
  StringStream(const std::string& stream) {
    m_Stream.str(stream);
  }

  template <typename SizeCast = std::size_t, typename Buffer, typename Size>
  void Read(Buffer& buf, Size&& size) {
    m_Stream.read(
        reinterpret_cast<char *>(&buf),
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

  bool EndOfFile() {
    return m_Stream.eof() ? true : false;
  }

  std::string Str() {
    return m_Stream.str();
  }

 private:
  std::stringstream m_Stream;
};

/// @return the full path of a file within the kovri directory
std::string GetFullPath(const std::string& filename);

/// @return the path to certificates for SU3 verification
boost::filesystem::path GetSU3CertsPath();

/// @return the path to SSL certificates for TLS/SSL negotiation
boost::filesystem::path GetSSLCertsPath();

/// @return the path to log storage
const boost::filesystem::path GetLogsPath();

}  // namespace filesystem
}  // namespace util
}  // namespace i2p

#endif  // SRC_CORE_UTIL_FILESYSTEM_H_
