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

#include "i2p_endian.h"

// http://habrahabr.ru/post/121811/
// http://codepad.org/2ycmkz2y

#include "little_big_endian.h"

#ifdef NEEDS_LOCAL_ENDIAN
uint16_t htobe16(
    uint16_t int16) {
  BigEndian<uint16_t> u16(int16);
  return u16.raw_value;
}

uint32_t htobe32(
    uint32_t int32) {
  BigEndian<uint32_t> u32(int32);
  return u32.raw_value;
}

uint64_t htobe64(
    uint64_t int64) {
  BigEndian<uint64_t> u64(int64);
  return u64.raw_value;
}

uint16_t be16toh(
    uint16_t big16) {
  LittleEndian<uint16_t> u16(big16);
  return u16.raw_value;
}

uint32_t be32toh(
    uint32_t big32) {
  LittleEndian<uint32_t> u32(big32);
  return u32.raw_value;
}

uint64_t be64toh(
    uint64_t big64) {
  LittleEndian<uint64_t> u64(big64);
  return u64.raw_value;
}
#endif

/* it can be used in Windows 8
#include <Winsock2.h>

uint16_t htobe16(
    uint16_t int16) {
  return htons(int16);
}

uint32_t htobe32(
    uint32_t int32) {
  return htonl(int32);
}

uint64_t htobe64(
    uint64_t int64) {
  // http://msdn.microsoft.com/en-us/library/windows/desktop/jj710199%28v=vs.85%29.aspx
  //return htonll(int64);
  return 0;
}

uint16_t be16toh(
    uint16_t big16) {
  return ntohs(big16);
}

uint32_t be32toh(
    uint32_t big32) {
  return ntohl(big32);
}

uint64_t be64toh(
    uint64_t big64) {
  // http://msdn.microsoft.com/en-us/library/windows/desktop/jj710199%28v=vs.85%29.aspx
  //return ntohll(big64);
  return 0;
}
*/
