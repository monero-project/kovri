/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SRC_CORE_RESEED_H_
#define SRC_CORE_RESEED_H_

#include <cryptopp/rsa.h>

#include <iostream>
#include <map>
#include <string>

#include "Identity.h"

namespace i2p {
namespace data {

class Reseeder {
  typedef Tag<512> PublicKey;
  std::map<std::string, PublicKey> m_SigningKeys;

  int ReseedFromSU3(
      const std::string& host);

  int ProcessSU3Stream(
      std::istream& s);

  bool FindZipDataDescriptor(
      std::istream& s);

  bool ProcessSU3Cert(
      const std::string& filename);

  std::string ProcessSU3Cert(
      CryptoPP::ByteQueue& queue);  // returns issuer's name

 public:
  Reseeder();
  ~Reseeder();
  int ReseedNowSU3();
  bool LoadSU3Certs();
};

const char SU3_MAGIC_NUMBER[]="I2Psu3";
const uint32_t ZIP_HEADER_SIGNATURE = 0x04034B50;
const uint32_t ZIP_CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50;
const uint16_t ZIP_BIT_FLAG_DATA_DESCRIPTOR = 0x0008;
const uint8_t ZIP_DATA_DESCRIPTOR_SIGNATURE[] = { 0x50, 0x4B, 0x07, 0x08 };
const char CERTIFICATE_HEADER[] = "-----BEGIN CERTIFICATE-----";
const char CERTIFICATE_FOOTER[] = "-----END CERTIFICATE-----";

}  // namespace data
}  // namespace i2p

#endif  // SRC_CORE_RESEED_H_
