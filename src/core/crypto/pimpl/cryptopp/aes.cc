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

#include "crypto/aes.h"

#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

#include <stdlib.h>

#include "aesni_macros.h"
#include "util/log.h"

namespace i2p {
namespace crypto {

/// TODO(unassigned): if we switch libraries, we should move AES-NI elsewhere.
/// TODO(unassigned): MSVC x86-64 support?
bool AESNIExists() {
  unsigned int eax, ecx;  // We only need ECX
  const unsigned int flag = (1 << 25);  // ECX bit 25 for AES-NI
  LogPrint(eLogInfo, "Crypto: checking for AES-NI...");
  __asm__ __volatile__(
      "cpuid"
      : "=a"(eax), "=c"(ecx)  // 0x2000000;
      : "a"(1), "c"(0)
      : "%ebx", "%edx");
  if ((ecx & flag) == flag) {
    LogPrint(eLogInfo, "Crypto: AES-NI is available!");
  } else {
    LogPrint(eLogInfo, "Crypto: AES-NI is not available. Using library.");
    return false;
  }
  return true;
}

// Initialize once to avoid repeated tests for AES-NI
// TODO(unassigned): better place to initialize?
bool aesni(AESNIExists());

// For runtime AES-NI
bool UsingAESNI() {
  return aesni;
}

/// @class ECBCryptoAESNI
/// @brief AES-NI base class for ECB
class ECBCryptoAESNI {
 public:
  std::uint8_t* GetKeySchedule() {
    return m_KeySchedule;
  }

 protected:
  void ExpandKey(
      const AESKey& key) {
    __asm__(
        "movups (%[key]), %%xmm1 \n"
        "movups 16(%[key]), %%xmm3 \n"
        "movaps %%xmm1, (%[sched]) \n"
        "movaps %%xmm3, 16(%[sched]) \n"
        "aeskeygenassist $1, %%xmm3, %%xmm2 \n"
        KeyExpansion256(32,48)
        "aeskeygenassist $2, %%xmm3, %%xmm2 \n"
        KeyExpansion256(64,80)
        "aeskeygenassist $4, %%xmm3, %%xmm2 \n"
        KeyExpansion256(96,112)
        "aeskeygenassist $8, %%xmm3, %%xmm2 \n"
        KeyExpansion256(128,144)
        "aeskeygenassist $16, %%xmm3, %%xmm2 \n"
        KeyExpansion256(160,176)
        "aeskeygenassist $32, %%xmm3, %%xmm2 \n"
        KeyExpansion256(192,208)
        "aeskeygenassist $64, %%xmm3, %%xmm2 \n"
        // key expansion final
        "pshufd $0xff, %%xmm2, %%xmm2 \n"
        "movaps %%xmm1, %%xmm4 \n"
        "pslldq $4, %%xmm4 \n"
        "pxor %%xmm4, %%xmm1 \n"
        "pslldq $4, %%xmm4 \n"
        "pxor %%xmm4, %%xmm1 \n"
        "pslldq $4, %%xmm4 \n"
        "pxor %%xmm4, %%xmm1 \n"
        "pxor %%xmm2, %%xmm1 \n"
        "movups %%xmm1, 224(%[sched]) \n"
        : // Output
        : [key]"r"((const std::uint8_t *)key), [sched]"r"(GetKeySchedule()) // Input
        : "%xmm1", "%xmm2", "%xmm3", "%xmm4", "memory"); // Clobbered
  }

 private:
  AESAlignedBuffer<240> m_KeySchedule;  // 14 rounds for AES-256, 240 bytes
};

/**
 *
 * ECB Encryption
 *
 */

/// @class ECBEncryptionImpl
/// @brief ECB encryption implementation
class ECBEncryption::ECBEncryptionImpl : public ECBCryptoAESNI {
 public:
  ECBEncryptionImpl() {}
  ~ECBEncryptionImpl() {}

  std::uint8_t* GetKeySchedule() {
    return ECBCryptoAESNI::GetKeySchedule();
  }

  void SetKey(
      const AESKey& key) {
    if (UsingAESNI()) {
      ExpandKey(key);
    } else {
      try {
        m_Encryption.SetKey(key, 32);
      } catch (CryptoPP::Exception e) {
        LogPrint(eLogError,
            "ECBEncryptionImpl: SetKey() caught exception '", e.what(), "'");
      }
    }
  }

  void Encrypt(
      const CipherBlock* in,
      CipherBlock* out) {
    if (UsingAESNI()) {
      __asm__(
          "movups (%[in]), %%xmm0 \n"
          EncryptAES256(sched)
          "movups %%xmm0, (%[out]) \n"
          :
          : [sched]"r"(GetKeySchedule()), [in]"r"(in), [out]"r"(out)
          : "%xmm0", "memory");
    } else {
      try {
        m_Encryption.ProcessData(out->buf, in->buf, 16);
      } catch (CryptoPP::Exception e) {
        LogPrint(eLogError,
            "ECBEncryptionImpl: Encrypt() caught exception '", e.what(), "'");
      }
    }
  }

 private:
  CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption m_Encryption;
};

ECBEncryption::ECBEncryption()
    : m_ECBEncryptionPimpl(
          std::make_unique<ECBEncryptionImpl>()) {}

ECBEncryption::~ECBEncryption() {}

std::uint8_t* ECBEncryption::GetKeySchedule() {
  return m_ECBEncryptionPimpl->GetKeySchedule();
}

void ECBEncryption::ECBEncryption::SetKey(
    const AESKey& key) {
  m_ECBEncryptionPimpl->SetKey(key);
}

void ECBEncryption::Encrypt(
    const CipherBlock* in,
    CipherBlock* out) {
  m_ECBEncryptionPimpl->Encrypt(in, out);
}

/**
 *
 * ECB Decryption
 *
 */

/// @class ECBDecryptionImpl
/// @brief ECB decryption implementation
class ECBDecryption::ECBDecryptionImpl : public ECBCryptoAESNI {
 public:
  ECBDecryptionImpl() {}
  ~ECBDecryptionImpl() {}

  std::uint8_t* GetKeySchedule() {
    return ECBCryptoAESNI::GetKeySchedule();
  }

  void SetKey(
      const AESKey& key) {
    if (UsingAESNI()) {
      ExpandKey(key);  // expand encryption key first
      // then invert it using aesimc
      __asm__(
          CallAESIMC(16)
          CallAESIMC(32)
          CallAESIMC(48)
          CallAESIMC(64)
          CallAESIMC(80)
          CallAESIMC(96)
          CallAESIMC(112)
          CallAESIMC(128)
          CallAESIMC(144)
          CallAESIMC(160)
          CallAESIMC(176)
          CallAESIMC(192)
          CallAESIMC(208)
          :
          : [shed]"r"(GetKeySchedule())
          : "%xmm0", "memory");
    } else {
      try {
        m_Decryption.SetKey(key, 32);
      } catch (CryptoPP::Exception e) {
        LogPrint(eLogError,
            "ECBDecryptionImpl: SetKey() caught exception '", e.what(), "'");
      }
    }
  }

  void Decrypt(
      const CipherBlock* in,
      CipherBlock* out) {
    if (UsingAESNI()) {
      __asm__(
          "movups (%[in]), %%xmm0 \n"
          DecryptAES256(sched)
          "movups %%xmm0, (%[out]) \n"
          :
          : [sched]"r"(GetKeySchedule()), [in]"r"(in), [out]"r"(out)
          : "%xmm0", "memory");
    } else {
      try {
        m_Decryption.ProcessData(out->buf, in->buf, 16);
      } catch (CryptoPP::Exception e) {
        LogPrint(eLogError,
            "ECBDecryptionImpl: Decrypt() caught exception '", e.what(), "'");
      }
    }
  }

 private:
  CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption m_Decryption;
};

ECBDecryption::ECBDecryption()
    : m_ECBDecryptionPimpl(
          std::make_unique<ECBDecryptionImpl>()) {}

ECBDecryption::~ECBDecryption() {}

std::uint8_t* ECBDecryption::GetKeySchedule() {
  return m_ECBDecryptionPimpl->GetKeySchedule();
}

void ECBDecryption::SetKey(
    const AESKey& key) {
  m_ECBDecryptionPimpl->SetKey(key);
}

void ECBDecryption::Decrypt(
    const CipherBlock* in,
    CipherBlock* out) {
  m_ECBDecryptionPimpl->Decrypt(in, out);
}

/**
 *
 * CBC Encryption
 *
 */

/// @class CBCEncryptionImpl
/// @brief CBC encryption implementation
class CBCEncryption::CBCEncryptionImpl {
 public:
  CBCEncryptionImpl() {
    memset(m_LastBlock.buf, 0, 16);
  }

  CBCEncryptionImpl(
      const AESKey& key,
      const std::uint8_t* iv)
      : CBCEncryptionImpl() {
    SetKey(key);
    SetIV(iv);
  }

  void SetKey(  // 32 bytes
      const AESKey& key) {
    m_ECBEncryption.SetKey(key);
  }

  void SetIV(  // 16 bytes
      const std::uint8_t* iv) {
    memcpy(m_LastBlock.buf, iv, 16);
  }

  void Encrypt(
      int num_blocks,
      const CipherBlock* in,
      CipherBlock* out) {
    if (UsingAESNI()) {
      __asm__(
          "movups (%[iv]), %%xmm1 \n"
          "1: \n"
          "movups (%[in]), %%xmm0 \n"
          "pxor %%xmm1, %%xmm0 \n"
          EncryptAES256(sched)
          "movaps %%xmm0, %%xmm1 \n"
          "movups %%xmm0, (%[out]) \n"
          "add $16, %[in] \n"
          "add $16, %[out] \n"
          "dec %[num] \n"
          "jnz 1b \n"
          "movups %%xmm1, (%[iv]) \n"
          :
          : [iv]"r"(&m_LastBlock),
            [sched]"r"(m_ECBEncryption.GetKeySchedule()),
            [in]"r"(in), [out]"r"(out), [num]"r"(num_blocks)
          : "%xmm0", "%xmm1", "cc", "memory");
    } else {
      for (int i = 0; i < num_blocks; i++) {
        m_LastBlock ^= in[i];
        m_ECBEncryption.Encrypt(&m_LastBlock, &m_LastBlock);
        out[i] = m_LastBlock;
      }
    }
  }

  void Encrypt(
      const std::uint8_t* in,
      std::size_t len,
      std::uint8_t* out) {
    // len/16
    int num_blocks = len >> 4;
    if (num_blocks > 0)
      Encrypt(
          num_blocks,
          reinterpret_cast<const CipherBlock *>(in),
          reinterpret_cast<CipherBlock *>(out));
  }

  void Encrypt(
      const std::uint8_t* in,
      std::uint8_t* out) {
    if (UsingAESNI()) {
      __asm__(
          "movups (%[iv]), %%xmm1 \n"
          "movups (%[in]), %%xmm0 \n"
          "pxor %%xmm1, %%xmm0 \n"
          EncryptAES256(sched)
          "movups %%xmm0, (%[out]) \n"
          "movups %%xmm0, (%[iv]) \n"
          :
          : [iv]"r"(&m_LastBlock),
            [sched]"r"(m_ECBEncryption.GetKeySchedule()),
            [in]"r"(in), [out]"r"(out)
          : "%xmm0", "%xmm1", "memory");
    } else {
      Encrypt(
          1,
          reinterpret_cast<const CipherBlock *>(in),
          reinterpret_cast<CipherBlock *>(out));
    }
  }

 private:
  CipherBlock m_LastBlock;
  ECBEncryption m_ECBEncryption;
};

CBCEncryption::CBCEncryption()
    : m_CBCEncryptionPimpl(
          std::make_unique<CBCEncryptionImpl>()) {}

CBCEncryption::CBCEncryption(
    const AESKey& key,
    const std::uint8_t* iv)
    : m_CBCEncryptionPimpl(
          std::make_unique<CBCEncryptionImpl>(key, iv)) {}

CBCEncryption::~CBCEncryption() {}

void CBCEncryption::SetKey(
    const AESKey& key) {
  m_CBCEncryptionPimpl->SetKey(key);
}

void CBCEncryption::SetIV(
    const std::uint8_t* iv) {
  m_CBCEncryptionPimpl->SetIV(iv);
}

void CBCEncryption::Encrypt(
    int num_blocks,
    const CipherBlock* in,
    CipherBlock* out) {
  m_CBCEncryptionPimpl->Encrypt(num_blocks, in, out);
}

void CBCEncryption::Encrypt(
    const std::uint8_t* in,
    std::size_t len,
    std::uint8_t* out) {
  m_CBCEncryptionPimpl->Encrypt(in, len, out);
}

void CBCEncryption::Encrypt(
  const std::uint8_t* in,
  std::uint8_t* out) {
  m_CBCEncryptionPimpl->Encrypt(in, out);
}

/**
 *
 * CBC Decryption
 *
 */

/// @class CBCDecryptionImpl
/// @brief CBC decryption implementation
class CBCDecryption::CBCDecryptionImpl {
 public:
  CBCDecryptionImpl() {
    memset(m_IV.buf, 0, 16);
  }

  CBCDecryptionImpl(
      const AESKey& key,
      const std::uint8_t* iv)
      : CBCDecryptionImpl() {
    SetKey(key);
    SetIV(iv);
  }

  void SetKey(  // 32 bytes
      const AESKey& key) {
    m_ECBDecryption.SetKey(key);
  }

  void SetIV(  // 16 bytes
      const std::uint8_t* iv) {
    memcpy(m_IV.buf, iv, 16);
  }

  void Decrypt(
      int num_blocks,
      const CipherBlock* in,
      CipherBlock* out) {
    if (UsingAESNI()) {
      __asm__(
        "movups (%[iv]), %%xmm1 \n"
        "1: \n"
        "movups (%[in]), %%xmm0 \n"
        "movaps %%xmm0, %%xmm2 \n"
        DecryptAES256(sched)
        "pxor %%xmm1, %%xmm0 \n"
        "movups %%xmm0, (%[out]) \n"
        "movaps %%xmm2, %%xmm1 \n"
        "add $16, %[in] \n"
        "add $16, %[out] \n"
        "dec %[num] \n"
        "jnz 1b \n"
        "movups %%xmm1, (%[iv]) \n"
        :
        : [iv]"r"(&m_IV), [sched]"r"(m_ECBDecryption.GetKeySchedule ()),
          [in]"r"(in), [out]"r"(out), [num]"r"(num_blocks)
        : "%xmm0", "%xmm1", "%xmm2", "cc", "memory");
    } else {
      for (int i = 0; i < num_blocks; i++) {
        CipherBlock tmp = in[i];
        m_ECBDecryption.Decrypt(in + i, out + i);
        out[i] ^= m_IV;
        m_IV = tmp;
      }
    }
  }

  void Decrypt(
    const std::uint8_t* in,
    std::size_t len,
    std::uint8_t* out) {
    int num_blocks = len >> 4;
    if (num_blocks > 0)
      Decrypt(
        num_blocks,
        reinterpret_cast<const CipherBlock *>(in),
        reinterpret_cast<CipherBlock *>(out));
  }

  // One block
  void Decrypt(
      const std::uint8_t* in,
      std::uint8_t* out) {
    if (UsingAESNI()) {
      __asm__(
        "movups (%[iv]), %%xmm1 \n"
        "movups (%[in]), %%xmm0 \n"
        "movups %%xmm0, (%[iv]) \n"
        DecryptAES256(sched)
        "pxor %%xmm1, %%xmm0 \n"
        "movups %%xmm0, (%[out]) \n"
        :
        : [iv]"r"(&m_IV), [sched]"r"(m_ECBDecryption.GetKeySchedule()),
          [in]"r"(in), [out]"r"(out)
        : "%xmm0", "%xmm1", "memory");
    } else {
      Decrypt(
          1,
          reinterpret_cast<const CipherBlock *>(in),
          reinterpret_cast<CipherBlock *>(out));
    }
  }

 private:
  CipherBlock m_IV;
  ECBDecryption m_ECBDecryption;
};

CBCDecryption::CBCDecryption()
    : m_CBCDecryptionPimpl(
          std::make_unique<CBCDecryptionImpl>()) {}

CBCDecryption::CBCDecryption(
    const AESKey& key,
    const std::uint8_t* iv)
    : m_CBCDecryptionPimpl(
          std::make_unique<CBCDecryptionImpl>(key, iv)) {}

CBCDecryption::~CBCDecryption() {}

void CBCDecryption::SetKey(
    const AESKey& key) {
  m_CBCDecryptionPimpl->SetKey(key);
}

void CBCDecryption::SetIV(
    const std::uint8_t* iv) {
  m_CBCDecryptionPimpl->SetIV(iv);
}

void CBCDecryption::Decrypt(
    int num_blocks,
    const CipherBlock* in,
    CipherBlock* out) {
  m_CBCDecryptionPimpl->Decrypt(num_blocks, in, out);
}

void CBCDecryption::Decrypt(
    const std::uint8_t* in,
    std::size_t len,
    std::uint8_t* out) {
  m_CBCDecryptionPimpl->Decrypt(in, len, out);
}

void CBCDecryption::Decrypt(
  const std::uint8_t* in,
  std::uint8_t* out) {
  m_CBCDecryptionPimpl->Decrypt(in, out);
}

}  //  namespace crypto
}  //  namespace i2p
