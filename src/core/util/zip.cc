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

#include "zip.h"

#include <istream>
#include <string>
#include <vector>

#include "log.h"
#include "crypto/util/compression.h"
#include "util/i2p_endian.h"

namespace i2p {
namespace util {

/**
 * ZIP implementation
 *
 * 1. Validates local file header signature
 * 2. Prepares local file
 *   - Set endianness where needed
 *   - Get/set data
 *   - Perform sanity tests
 * 3. Decompress local file
 *   - Store in a map
 */
bool ZIP::Unzip() {
  try {
    // Set position in stream
    m_Stream.Seekg(m_Data->content_position, std::ios::beg);
    // Process local files, one after another
    while (!m_Stream.EndOfFile()) {
      // Validate local file's header signature
      m_Stream.Read(m_Data->header_signature, Size::header_signature);
      m_Data->header_signature = le32toh(m_Data->header_signature);
      if (m_Data->header_signature ==
          static_cast<std::size_t>(Signature::header)) {
        LogPrint(eLogDebug, "ZIP: preparing local file...");
        if (!PrepareLocalFile())
          return false;
        LogPrint(eLogDebug, "ZIP: decompressing local file...");
        if (!DecompressLocalFile())
          return false;
        // Skip data descriptor section if present
        if (m_Data->bit_flag & Descriptor.bit_flag)
          m_Stream.Seekg(Offset::descriptor, std::ios::cur);
      } else {
        if (m_Data->header_signature !=
            static_cast<std::size_t>(Signature::central_dir_header)) {
          LogPrint(eLogError, "ZIP: missing central directory header");
          return false;
        }
        break;  // No more files to extract
      }
      // Ensure that given content length is unzipped
      std::size_t end = m_Stream.Tellg();
      if ((end - m_Data->content_position) >= m_Data->content_length)
        break;
    }
  } catch (const std::exception& e) {
    LogPrint(eLogError,
        "ZIP: caught exception '", e.what(), "' during unzip");
    return false;
  }
  LogPrint(eLogDebug, "ZIP: successfully unzipped stream");
  return true;
}

bool ZIP::PrepareLocalFile() {
  try {
    // Skip version needed to extract
    m_Stream.Seekg(Offset::version, std::ios::cur);
    // Prepare bit flag
    m_Stream.Read(m_Data->bit_flag, Size::bit_flag);
    m_Data->bit_flag = le16toh(m_Data->bit_flag);
    // Prepare compression method (sanity test done later)
    m_Stream.Read(m_Data->compression_method, Size::compression_method);
    m_Data->compression_method = le16toh(m_Data->compression_method);
    // Unused offset
    m_Stream.Seekg(Offset::last_mod, std::ios::cur);
    // Get CRC-32 checksum
    m_Stream.Read(*m_Data->crc_32.data(), Size::crc_32);
    if (!m_Data->crc_32.data()) {
      LogPrint(eLogWarn, "ZIP: CRC-32 checksum was null");
      return false;
    }
    // Prepare compressed file size
    m_Stream.Read(m_Data->compressed_size, Size::compressed_size);
    m_Data->compressed_size = le32toh(m_Data->compressed_size);
    if (!m_Data->compressed_size)
      LogPrint(eLogWarn, "ZIP: compressed file size was null");
    // Prepare uncompressed file size
    m_Stream.Read(m_Data->uncompressed_size, Size::uncompressed_size);
    m_Data->uncompressed_size = le32toh(m_Data->uncompressed_size);
    // Prepare local filename length
    m_Stream.Read(m_Data->local_filename_length, Size::local_filename_length);
    m_Data->local_filename_length = le16toh(m_Data->local_filename_length);
    // If we expand ZIP beyond SU3, we'll have to remove this check
    if ((m_Data->local_filename_length !=
        static_cast<std::size_t>(Size::ri_filename_length))) {
      LogPrint(eLogError,
          "ZIP: archived filename length not appropriate: ",
          static_cast<std::size_t>(m_Data->local_filename_length));
      return false;
    }
    // Prepare extra field length
    m_Stream.Read(m_Data->extra_field_length, Size::extra_field_length);
    m_Data->extra_field_length = le16toh(m_Data->extra_field_length);
    // Get local filename
    // TODO(unassigned): we don't check if filename is base64 standard
    // ex., 'routerInfo-asdfj23kjf2lk3nfnakjlsnfjklsdnfln23f.dat' (as defined in SU3 spec).
    // If we don't extend ZIP beyond SU3, we may wish to enforce a regex check.
    m_Stream.Read(*m_Data->local_filename.data(), m_Data->local_filename_length);
    // Skip extra field
    m_Stream.Seekg(m_Data->extra_field_length, std::ios::cur);
    // Verify if data descriptor is present
    if (m_Data->bit_flag & Descriptor.bit_flag) {
      std::size_t pos = m_Stream.Tellg();
      if (!FindDataDescriptor()) {
        LogPrint(eLogError, "ZIP: archive data descriptor not found");
        return false;
      }
      m_Stream.Read(*m_Data->crc_32.data(), Size::crc_32);
      m_Stream.Read(m_Data->compressed_size, Size::compressed_size);
      m_Stream.Read(m_Data->uncompressed_size, Size::uncompressed_size);
      // We consider the signature as part of compressed data
      m_Data->compressed_size +=
        static_cast<std::size_t>(Size::header_signature);
      // Now we know both compressed and uncompressed size
      m_Stream.Seekg(pos, std::ios::beg);  // Back to compressed data
    }
  } catch (const std::exception& e) {
    LogPrint(eLogError,
        "ZIP: caught exception '", e.what(), "' during preparation");
    return false;
  }
  LogPrint(eLogDebug, "ZIP: successfully prepared file");
  return true;
}

bool ZIP::FindDataDescriptor() {
  std::size_t next_ind = 0;
  while (!m_Stream.EndOfFile()) {
    std::uint8_t next_byte;
    m_Stream.Read(next_byte, 1);
    if (next_byte == Descriptor.signature.at(next_ind)) {
      next_ind++;
      if (next_ind >= Descriptor.signature.size())
        return true;
    } else {
      next_ind = 0;
    }
  }
  return false;
}

bool ZIP::DecompressLocalFile() {
  LogPrint(eLogDebug,
      "ZIP: processing file ", m_Data->local_filename.data(),
      " ", m_Data->compressed_size, " bytes");
  try {
    // Resize for next file
    m_Data->compressed.resize(m_Data->compressed_size);
    // Read in compressed data
    m_Stream.Read(*m_Data->compressed.data(), m_Data->compressed.size());
    switch (m_Data->compression_method) {
      case static_cast<std::size_t>(Method::deflate): {
        LogPrint(eLogDebug, "ZIP: file uses compression method 'deflate'");
        // Instantiate decompressor
        i2p::crypto::util::DeflateDecompressor decompressor;
        // Put in data to decompress
        decompressor.Put(
            m_Data->compressed.data(),
            m_Data->compressed.size());
        // Test if uncompressed size will be valid
        if (decompressor.MaxRetrievable() <= m_Data->uncompressed_size) {
          // Resize for next file
          m_Data->uncompressed.resize(m_Data->uncompressed_size);
          decompressor.Get(
              m_Data->uncompressed.data(),
              m_Data->uncompressed.size());
          // Verify checksum
          if ((decompressor.Verify(
                  m_Data->crc_32.data(),
                  m_Data->uncompressed.data(),
                  m_Data->uncompressed.size()))) {  // Checksum passed
            // Store/map the uncompressed file
            m_Contents.insert(
                { m_Data->local_file_count, std::move(m_Data->uncompressed) });
          } else {
            LogPrint(eLogError, "ZIP: CRC-32 Failed");
            return false;
          }
        } else {
          LogPrint(eLogError,
              "ZIP: actual uncompressed size ", decompressor.MaxRetrievable(),
              " exceeds ", m_Data->uncompressed_size, " from header");
          return false;
        }
        break;
      }
      case static_cast<std::size_t>(Method::stored): {
        LogPrint(eLogDebug, "ZIP: file uses compression method 'stored'");
        // Store/map the local file as-is
        m_Contents.insert(
            { m_Data->local_file_count, std::move(m_Data->compressed) });
        break;
      }
      default:
        LogPrint(eLogError,
            "ZIP: file uses an unsupported compression method");
        return false;
    }
  } catch (...) {
    LogPrint(eLogError, "ZIP: caught exception during decompression");
    return false;
  }
  LogPrint(eLogDebug, "ZIP: successfully processed file");
  m_Data->local_file_count++;  // Move onto next file for processing
  return true;
}

}  // namespace util
}  // namespace i2p
