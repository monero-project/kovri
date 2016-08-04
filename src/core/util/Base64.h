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

#ifndef SRC_CORE_UTIL_BASE64_H_
#define SRC_CORE_UTIL_BASE64_H_

#include <inttypes.h>
#include <string.h>

namespace i2p {
namespace util {

  /*
   * Base64 encodes an array of bytes.
   * @return the number of characters written to the output buffer
   * @param InBuffer array of input bytes to be encoded
   * @param InCount length of the input array
   * @param OutBuffer array to store output characters
   * @param len length of the output buffer
   * @note zero is returned when the output buffer is too small
   */
  size_t ByteStreamToBase64(
      const uint8_t* InBuffer,
      size_t InCount,
      char* OutBuffer,
      size_t len);
  /**
   * Decodes base 64 encoded data to an array of bytes.
   * @return the number of bytes written to the output buffer
   * @param InBuffer array of input characters to be decoded
   * @param InCount length of the input array
   * @param OutBuffer array to store output bytes
   * @param len length of the output buffer
   * @todo Do not return a negative value on failure, size_t could be unsigned.
   * @note zero is returned when the output buffer is too small
   */
  size_t Base64ToByteStream(
      const char* InBuffer,
      size_t InCount,
      uint8_t* OutBuffer,
      size_t len);

  const char* GetBase64SubstitutionTable();
  /**
   * Decodes base 32 encoded data to an array of bytes.
   * @return the number of bytes written to the output buffer
   * @param inBuf array of input characters to be decoded
   * @param len length of the input buffer
   * @param outBuf array to store output bytes
   * @param outLen length of the output array
   * @note zero is returned when the output buffer is too small
   */
  size_t Base32ToByteStream(
      const char* inBuf,
      size_t len,
      uint8_t* outBuf,
      size_t outLen);
  /**
   * Base 32 encodes an array of bytes.
   * @return the number of bytes written to the output buffer
   * @param inBuf array of input bytes to be encoded
   * @param len length of the input buffer
   * @param outBuf array to store output characters
   * @param outLen length of the output array
   * @note zero is returned when the output buffer is too small
   */
  size_t ByteStreamToBase32(
      const uint8_t* inBuf,
      size_t len,
      char* outBuf,
      size_t outLen);

}  // namespace util
}  // namespace i2p

#endif  // SRC_CORE_UTIL_BASE64_H_
