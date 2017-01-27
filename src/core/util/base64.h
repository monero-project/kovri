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

#ifndef SRC_CORE_UTIL_BASE64_H_
#define SRC_CORE_UTIL_BASE64_H_

#include <string.h>

#include <cstddef>
#include <cstdint>

namespace kovri {
namespace core {

  /*
   * Base64 encodes an array of bytes.
   * @return the number of characters written to the output buffer
   * @param in_buffer array of input bytes to be encoded
   * @param in_count length of the input array
   * @param out_buffer array to store output characters
   * @param len length of the output buffer
   * @note zero is returned when the output buffer is too small
   */
  std::size_t ByteStreamToBase64(
      const std::uint8_t* in_buffer,
      std::size_t in_count,
      char* out_buffer,
      std::size_t len);
  /**
   * Decodes base 64 encoded data to an array of bytes.
   * @return the number of bytes written to the output buffer
   * @param in_buffer array of input characters to be decoded
   * @param in_count length of the input array
   * @param out_buffer array to store output bytes
   * @param len length of the output buffer
   * @todo Do not return a negative value on failure, size_t could be unsigned.
   * @note zero is returned when the output buffer is too small
   */
  std::size_t Base64ToByteStream(
      const char* in_buffer,
      std::size_t in_count,
      std::uint8_t* out_buffer,
      std::size_t len);

  const char* GetBase64SubstitutionTable();
  /**
   * Decodes base 32 encoded data to an array of bytes.
   * @return the number of bytes written to the output buffer
   * @param in_buf array of input characters to be decoded
   * @param len length of the input buffer
   * @param out_buf array to store output bytes
   * @param out_len length of the output array
   * @note zero is returned when the output buffer is too small
   */
  std::size_t Base32ToByteStream(
      const char* in_buf,
      std::size_t len,
      std::uint8_t* out_buf,
      std::size_t out_len);
  /**
   * Base 32 encodes an array of bytes.
   * @return the number of bytes written to the output buffer
   * @param in_buf array of input bytes to be encoded
   * @param len length of the input buffer
   * @param out_buf array to store output characters
   * @param out_len length of the output array
   * @note zero is returned when the output buffer is too small
   */
  std::size_t ByteStreamToBase32(
      const std::uint8_t* in_buf,
      std::size_t len,
      char* out_buf,
      std::size_t out_len);

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_UTIL_BASE64_H_
