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

#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include "core/crypto/aes.h"

BOOST_AUTO_TEST_SUITE(AESTests)

BOOST_AUTO_TEST_CASE(XorZeroCipherBlocks) {
  kovri::core::CipherBlock block = {0};
  block ^= block;
  const kovri::core::CipherBlock result = {0};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      result.buf, result.buf + 16,
      block.buf, block.buf + 16);
}

BOOST_AUTO_TEST_CASE(XorSelfCipherBlocks) {
  kovri::core::CipherBlock block = {
    0xc9, 0x4c, 0xaf, 0x5, 0x9c, 0x1c, 0x10, 0x1e, 0x20, 0xb3, 0x7e,
    0xcf, 0xf5, 0xbf, 0xf0, 0xd6
  };
  block ^= block;
  const kovri::core::CipherBlock result = {0};
  BOOST_CHECK_EQUAL_COLLECTIONS(
      result.buf, result.buf + 16,
      block.buf, block.buf + 16);
}

BOOST_AUTO_TEST_CASE(XorCipherBlocks) {
  const kovri::core::CipherBlock block1 = {
    0xc9, 0x4c, 0xaf, 0x5, 0x9c, 0x1c, 0x10, 0x1e, 0x20, 0xb3, 0x7e,
    0xcf, 0xf5, 0xbf, 0xf0, 0xd6
  };
  kovri::core::CipherBlock block2 = {
    0x2e, 0xfb, 0x26, 0xa9, 0x90, 0x3b, 0xf7, 0xc8, 0x5c, 0xfe, 0x20,
    0x23, 0x1d, 0xaf, 0x67, 0xac
  };
  block2 ^= block1;
  const kovri::core::CipherBlock result = {
    0xe7, 0xb7, 0x89, 0xac, 0xc, 0x27, 0xe7, 0xd6, 0x7c, 0x4d, 0x5e,
    0xec, 0xe8, 0x10, 0x97, 0x7a
  };
  BOOST_CHECK_EQUAL_COLLECTIONS(
      block2.buf, block2.buf + 16,
      result.buf, result.buf + 16);
}

// NIST test parameters
// see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
struct AesCbcFixture {
  AesCbcFixture()
    : cbc_encrypt(
          kovri::core::AESKey(key),
          iv),
      cbc_decrypt(
          kovri::core::AESKey(key),
          iv) {}
  uint8_t key[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73,
    0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07,
    0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
    0xdf, 0xf4
  };
  uint8_t iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  kovri::core::CBCEncryption cbc_encrypt;
  kovri::core::CBCDecryption cbc_decrypt;
};

BOOST_FIXTURE_TEST_CASE(AesCbcSingleBlockEncrypt, AesCbcFixture) {
  uint8_t output[16] = {};
  const uint8_t input[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
    0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  };
  const uint8_t result[] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e,
    0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6
  };
  cbc_encrypt.Encrypt(input, output);
  BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 16, result, result + 16);
}

BOOST_FIXTURE_TEST_CASE(AesCbcSingleBlockDecrypt, AesCbcFixture) {
  uint8_t output[16] = {};
  const uint8_t input[] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e,
    0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6
  };
  const uint8_t result[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
    0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  };
  cbc_decrypt.Decrypt(input, output);
  BOOST_CHECK_EQUAL_COLLECTIONS(output, output + 16, result, result + 16);
}

BOOST_FIXTURE_TEST_CASE(AesCbcEncrypt, AesCbcFixture) {
  kovri::core::CipherBlock output[4] = {};
  kovri::core::CipherBlock input[4] = {};
  input[0] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
    0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  };
  input[1] = {
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
    0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
  };
  input[2] = {
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
    0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
  };
  input[3] = {
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b,
    0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
  };
  kovri::core::CipherBlock result[4] = {};
  result[0] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e,
    0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6
  };
  result[1] = {
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f,
    0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d
  };
  result[2] = {
    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30,
    0xe2, 0x63, 0x04, 0x23, 0x14, 0x61
  };
  result[3] = {
    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c,
    0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
  };
  cbc_encrypt.Encrypt(4, input, output);
  for (int i = 0; i < 3; ++i) {
    BOOST_CHECK_EQUAL_COLLECTIONS(
      output[i].buf, output[i].buf + 16,
      result[i].buf, result[i].buf + 16);
  }
}

BOOST_FIXTURE_TEST_CASE(AesCbcDecrypt, AesCbcFixture) {
  kovri::core::CipherBlock output[4] = {};
  kovri::core::CipherBlock input[4] = {};
  input[0] = {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e,
    0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6
  };
  input[1] = {
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f,
    0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d
  };
  input[2] = {
    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30,
    0xe2, 0x63, 0x04, 0x23, 0x14, 0x61
  };
  input[3] = {
    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c,
    0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
  };
  kovri::core::CipherBlock result[4] = {};
  result[0] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
    0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
  };
  result[1] = {
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7,
    0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
  };
  result[2] = {
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
    0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
  };
  result[3] = {
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b,
    0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
  };
  cbc_decrypt.Decrypt(4, input, output);
  for (int i = 0; i < 3; ++i) {
    BOOST_CHECK_EQUAL_COLLECTIONS(
      output[i].buf, output[i].buf + 16,
      result[i].buf, result[i].buf + 16);
  }
}

BOOST_AUTO_TEST_SUITE_END()
