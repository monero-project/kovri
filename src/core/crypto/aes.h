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

#ifndef SRC_CORE_CRYPTO_AES_H_
#define SRC_CORE_CRYPTO_AES_H_

#include <inttypes.h>

#include <cstdint>
#include <memory>

#include "identity.h"

namespace i2p {
namespace crypto {

struct CipherBlock {
  uint8_t buf[16];
  void operator^=(const CipherBlock& other) {  // XOR
#if defined(__x86_64__)  // for Intel x64
    __asm__(
        "movups (%[buf]), %%xmm0 \n"
        "movups (%[other]), %%xmm1 \n"
        "pxor %%xmm1, %%xmm0 \n"
        "movups %%xmm0, (%[buf]) \n"
        :
        : [buf]"r"(buf), [other]"r"(other.buf)
        : "%xmm0", "%xmm1", "memory");
#else
    // TODO(unassigned): implement it better
    for (int i = 0; i < 16; i++)
      buf[i] ^= other.buf[i];
#endif
  }
};

typedef i2p::data::Tag<32> AESKey;

template<std::size_t Size>
class AESAlignedBuffer {  // 16 bytes alignment
 public:
  AESAlignedBuffer() {
    m_Buf = m_UnalignedBuffer;
    std::uint8_t rem = ((std::size_t)m_Buf) & 0x0f;
    if (rem)
      m_Buf += (16 - rem);
  }

  operator std::uint8_t* () {
    return m_Buf;
  }

  operator const std::uint8_t* () const {
    return m_Buf;
  }

 private:
  std::uint8_t m_UnalignedBuffer[Size + 15];  // up to 15 bytes alignment
  std::uint8_t* m_Buf;
};

/// @brief Checks for AES-NI support in Intel/AMD processors
/// @note https://en.wikipedia.org/wiki/CPUID
/// @return True if supported, false if not
bool AESNIExists();

/// @brief Returns result of AESNIExists()
/// @note Used for runtime AES-NI implementation
/// @return True we are using AES-NI, false if not
bool UsingAESNI();

/**
 *
 * ECB
 *
 */

/// @class ECBEncryption
class ECBEncryption {
 public:
  ECBEncryption();
  ~ECBEncryption();

  std::uint8_t* GetKeySchedule();  // Only for AES-NI

  void SetKey(
      const AESKey& key);

  void Encrypt(
      const CipherBlock* in,
      CipherBlock* out);

 private:
  class ECBEncryptionImpl;
  std::unique_ptr<ECBEncryptionImpl> m_ECBEncryptionPimpl;
};

/// @class ECBDecryption
class ECBDecryption {
 public:
  ECBDecryption();
  ~ECBDecryption();

  std::uint8_t* GetKeySchedule();  // Only for AES-NI

  void SetKey(
      const AESKey& key);

  void Decrypt(
      const CipherBlock* in,
      CipherBlock* out);

 private:
  class ECBDecryptionImpl;
  std::unique_ptr<ECBDecryptionImpl> m_ECBDecryptionPimpl;
};

/**
 *
 * CBC
 *
 */

/// @class CBCEncryption
class CBCEncryption {
 public:
  CBCEncryption();
  ~CBCEncryption();

  CBCEncryption(
      const AESKey& key,
      const std::uint8_t* iv);

  // 32 bytes
  void SetKey(
      const AESKey& key);

  // 16 bytes
  void SetIV(
      const std::uint8_t* iv);

  void Encrypt(
      int numBlocks,
      const CipherBlock* in,
      CipherBlock* out);

  void Encrypt(
      const std::uint8_t* in,
      std::size_t len,
      std::uint8_t* out);

  // One block
  void Encrypt(
      const uint8_t* in,
      std::uint8_t* out);

 private:
  class CBCEncryptionImpl;
  std::unique_ptr<CBCEncryptionImpl> m_CBCEncryptionPimpl;
};

/// @class CBCDecryption
class CBCDecryption {
 public:
  CBCDecryption();
  ~CBCDecryption();

  CBCDecryption(
      const AESKey& key,
      const std::uint8_t* iv);

  // 32 bytes
  void SetKey(
      const AESKey& key);

  // 16 bytes
  void SetIV(
      const std::uint8_t* iv);

  void Decrypt(
      int numBlocks,
      const CipherBlock* in,
      CipherBlock* out);

  void Decrypt(
      const std::uint8_t* in,
      std::size_t len,
      std::uint8_t* out);

  // One block
  void Decrypt(
      const std::uint8_t* in,
      std::uint8_t* out);

 private:
  class CBCDecryptionImpl;
  std::unique_ptr<CBCDecryptionImpl> m_CBCDecryptionPimpl;
};

}  // namespace crypto
}  // namespace i2p

#endif  // SRC_CORE_CRYPTO_AES_H_
