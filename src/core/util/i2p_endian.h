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

#ifndef SRC_CORE_UTIL_I2P_ENDIAN_H_
#define SRC_CORE_UTIL_I2P_ENDIAN_H_

#include <inttypes.h>
#include <string.h>

#if defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__)
#include <endian.h>
#elif __FreeBSD__
#include <sys/endian.h>
#elif defined(__APPLE__) && defined(__MACH__)

#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#else
#define NEEDS_LOCAL_ENDIAN
#include <cstdint>
uint16_t htobe16(uint16_t int16);
uint32_t htobe32(uint32_t int32);
uint64_t htobe64(uint64_t int64);

uint16_t be16toh(uint16_t big16);
uint32_t be32toh(uint32_t big32);
uint64_t be64toh(uint64_t big64);

// assume LittleEndine
#define htole16
#define htole32
#define htole64
#define le16toh
#define le32toh
#define le64toh

#endif

inline uint16_t buf16toh(
    const void* buf) {
  uint16_t b16;
  memcpy(&b16, buf, sizeof(uint16_t));
  return b16;
}

inline uint32_t buf32toh(
    const void* buf) {
  uint32_t b32;
  memcpy(&b32, buf, sizeof(uint32_t));
  return b32;
}

inline uint64_t buf64toh(
    const void* buf) {
  uint64_t b64;
  memcpy(&b64, buf, sizeof(uint64_t));
  return b64;
}

inline uint16_t bufbe16toh(
    const void* buf) {
  return be16toh(buf16toh(buf));
}

inline uint32_t bufbe32toh(
    const void* buf) {
  return be32toh(buf32toh(buf));
}

inline uint64_t bufbe64toh(
    const void* buf) {
  return be64toh(buf64toh(buf));
}

inline void htobuf16(
    void* buf,
    uint16_t b16) {
  memcpy(buf, &b16, sizeof(uint16_t));
}

inline void htobuf32(
    void* buf,
    uint32_t b32) {
  memcpy(buf, &b32, sizeof(uint32_t));
}

inline void htobuf64(
    void* buf,
    uint64_t b64) {
  memcpy(buf, &b64, sizeof(uint64_t));
}

inline void htobe16buf(
    void* buf,
    uint16_t big16) {
  htobuf16(buf, htobe16(big16));
}

inline void htobe32buf(
    void* buf,
    uint32_t big32) {
  htobuf32(buf, htobe32(big32));
}

inline void htobe64buf(
    void* buf,
    uint64_t big64) {
  htobuf64(buf, htobe64(big64));
}

#endif  // SRC_CORE_UTIL_I2P_ENDIAN_H_
