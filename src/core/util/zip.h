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

#ifndef SRC_CORE_UTIL_ZIP_H_
#define SRC_CORE_UTIL_ZIP_H_

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "util/filesystem.h"

namespace i2p {
namespace util {

/**
 * We currently implement a very minimal adherence to the ZIP specification:
 * https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
 * https://en.wikipedia.org/wiki/Zip_%28file_format%29
 */

/**
 * @class ZIP
 * @brief ZIP implementation
 * @param zip String in ZIP file format
 * @param length Content length (length of zip)
 * @param pos Starting position (optional)
 */
class ZIP {
 public:
  ZIP(const std::string& zip,
      std::size_t len,
      std::size_t pos = 0)
      : Descriptor(),
        m_Stream(zip),
        m_Data(std::make_unique<Data>()) {
          m_Data->content_length = len;
          m_Data->content_position = pos;
          m_Data->local_file_count = 0;
        }

  /// @brief Unzipped content (map of unzipped local files)
  /// @param Local file key
  /// @param Local file content
  std::unordered_map<std::size_t, std::vector<std::uint8_t>> m_Contents;

  /// @brief Unzip'ing implementation
  /// @return false on failure
  bool Unzip();

  // TODO(unassigned): create a Zip() implementation.
  // Example use-case: creating a reseed file to distribute.

 private:
  /// @brief Prepares local file in stream for decompression
  /// @return false on failure
  bool PrepareLocalFile();

  /// @brief Finds data descriptor in while preparing local file
  /// @return false on failure
  bool FindDataDescriptor();

  /// @brief Uncompresses local file within stream
  /// @return false on failure
  bool DecompressLocalFile();

 private:
  enum struct Signature : const std::uint32_t {
    header = 0x04034b50,
    central_dir_header = 0x02014b50,
  };

  const struct Descriptor {
    std::uint16_t bit_flag = 0x0008;
    std::array<std::uint8_t, 4> signature {{ 0x50, 0x4b, 0x07, 0x08 }};
  } Descriptor;

  enum struct Method : const std::uint8_t {
    stored = 0,
    deflate = 8,
  };

  enum struct Offset : const std::uint8_t {
    version = 2,      // ZIP version
    unused = 1,       // Unused byte
    descriptor = 12,  // CRC-32 + compressed size + uncompressed size
    last_mod = 4,     // file time + file date
  };

  enum struct Size : const std::uint8_t {
    header_signature = 4,
    bit_flag = 2,
    compression_method = 2,
    crc_32 = 4,
    compressed_size = 4,
    uncompressed_size = 4,
    local_filename_length = 2,
    extra_field_length = 2,
    // SU3-specific RI filename length (*NOT* a part of ZIP spec)
    // "routerInfo-(44 character base 64 router hash).dat"
    ri_filename_length = 59,
  };

  struct Data {
    std::size_t content_position;
    std::uint64_t content_length;
    std::uint32_t header_signature;
    std::uint16_t bit_flag, compression_method;
    std::uint32_t compressed_size, uncompressed_size;
    std::array<std::uint8_t, static_cast<std::size_t>(Size::crc_32)> crc_32;
    std::uint16_t local_filename_length;
    std::array<char,
      static_cast<std::size_t>(Size::ri_filename_length) + 1> local_filename;
    std::uint16_t extra_field_length;
    std::uint16_t local_file_count;
    std::vector<std::uint8_t> compressed, uncompressed;
  };

  // ZIP stream
  i2p::util::filesystem::StringStream m_Stream;

  // ZIP spec-defined data
  std::unique_ptr<Data> m_Data;
};

}  // namespace util
}  // namespace i2p

#endif  // SRC_CORE_UTIL_ZIP_H_
