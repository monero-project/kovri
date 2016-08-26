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

#ifndef SRC_CORE_CRYPTO_HMAC_H_
#define SRC_CORE_CRYPTO_HMAC_H_

#include <inttypes.h>
#include <string.h>

#include "hash.h"
#include "identity.h"

namespace i2p {
namespace crypto {

const uint64_t IPAD = 0x3636363636363636;
const uint64_t OPAD = 0x5C5C5C5C5C5C5C5C;

typedef i2p::data::Tag<32> MACKey;

inline void HMACMD5Digest(
    uint8_t* msg,
    size_t len,
    const MACKey& key,
    uint8_t* digest) {
  // key is 32 bytes
  // digest is 16 bytes
  // block size is 64 bytes
  uint64_t buf[256];
  // ikeypad
  buf[0] = key.GetLL()[0] ^ IPAD;
  buf[1] = key.GetLL()[1] ^ IPAD;
  buf[2] = key.GetLL()[2] ^ IPAD;
  buf[3] = key.GetLL()[3] ^ IPAD;
  buf[4] = IPAD;
  buf[5] = IPAD;
  buf[6] = IPAD;
  buf[7] = IPAD;
  // concatenate with msg
  memcpy(buf + 8, msg, len);
  // calculate first hash
  uint8_t hash[16];  // MD5
  i2p::crypto::MD5().CalculateDigest(
      hash,
      reinterpret_cast<uint8_t *>(buf),
      len + 64);
  // okeypad
  buf[0] = key.GetLL()[0] ^ OPAD;
  buf[1] = key.GetLL()[1] ^ OPAD;
  buf[2] = key.GetLL()[2] ^ OPAD;
  buf[3] = key.GetLL()[3] ^ OPAD;
  buf[4] = OPAD;
  buf[5] = OPAD;
  buf[6] = OPAD;
  buf[7] = OPAD;
  // copy first hash after okeypad
  memcpy(buf + 8, hash, 16);
  // fill next 16 bytes with zeros (first hash size assumed 32 bytes in I2P)
  memset(buf + 10, 0, 16);
  // calculate digest
  i2p::crypto::MD5().CalculateDigest(
      digest,
      reinterpret_cast<uint8_t *>(buf),
      96);
}

}  // namespace crypto
}  // namespace i2p

#endif  // SRC_CORE_CRYPTO_HMAC_H_
