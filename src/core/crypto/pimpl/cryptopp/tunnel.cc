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

#include "crypto/tunnel.h"

#include <cstdint>

#include "aesni_macros.h"
#include "crypto/aes.h"
#include "tunnel/tunnel_base.h"

namespace i2p {
namespace crypto {

/// @class TunnelEncryptionImpl
/// @brief Tunnel encryption implementation
class TunnelEncryption::TunnelEncryptionImpl {
 public:
  TunnelEncryptionImpl() {}
  ~TunnelEncryptionImpl() {}

  void SetKeys(
      const AESKey& layer_key,
      const AESKey& iv_key) {
    if (UsingAESNI())
      m_ECBLayerEncryption.SetKey(layer_key);
    else
      m_CBCLayerEncryption.SetKey(layer_key);
    m_IVEncryption.SetKey(iv_key);
  }

  void Encrypt(
      const std::uint8_t* in,
      std::uint8_t* out) {
    if (UsingAESNI()) {
      __asm__(
          // encrypt IV
          "movups (%[in]), %%xmm0 \n"
          EncryptAES256(sched_iv)
          "movaps %%xmm0, %%xmm1 \n"
          // double IV encryption
          EncryptAES256(sched_iv)
          "movups %%xmm0, (%[out]) \n"
          // encrypt data, IV is xmm1
          "1: \n"
          "add $16, %[in] \n"
          "add $16, %[out] \n"
          "movups (%[in]), %%xmm0 \n"
          "pxor %%xmm1, %%xmm0 \n"
          EncryptAES256(sched_l)
          "movaps %%xmm0, %%xmm1 \n"
          "movups %%xmm0, (%[out]) \n"
          "dec %[num] \n"
          "jnz 1b \n"
          :
          : [sched_iv]"r"(m_IVEncryption.GetKeySchedule()),
            [sched_l]"r"(m_ECBLayerEncryption.GetKeySchedule()),
            [in]"r"(in), [out]"r"(out), [num]"r"(63)  // 63 blocks = 1008 bytes
          : "%xmm0", "%xmm1", "cc", "memory");
    } else {
      m_IVEncryption.Encrypt(  // iv
          (const CipherBlock *)in,
          reinterpret_cast<CipherBlock *>(out));
      m_CBCLayerEncryption.SetIV(out);
      m_CBCLayerEncryption.Encrypt(  // data
          in + 16,
          i2p::tunnel::TUNNEL_DATA_ENCRYPTED_SIZE,
          out + 16);
      m_IVEncryption.Encrypt(  // double iv
          reinterpret_cast<CipherBlock *>(out),
          reinterpret_cast<CipherBlock *>(out));
    }
  }

 private:
  ECBEncryption m_IVEncryption;
  ECBEncryption m_ECBLayerEncryption;  // For AES-NI
  CBCEncryption m_CBCLayerEncryption;
};

TunnelEncryption::TunnelEncryption()
    : m_TunnelEncryptionPimpl(
          std::make_unique<TunnelEncryptionImpl>()) {}

TunnelEncryption::~TunnelEncryption() {}

void TunnelEncryption::SetKeys(
      const AESKey& layer_key,
      const AESKey& iv_key) {
  m_TunnelEncryptionPimpl->SetKeys(layer_key, iv_key);
}

void TunnelEncryption::Encrypt(
      const std::uint8_t* in,
      std::uint8_t* out) {
  m_TunnelEncryptionPimpl->Encrypt(in, out);
}

/// @class TunnelDecryptionImpl
/// @brief Tunnel decryption implementation
class TunnelDecryption::TunnelDecryptionImpl {
 public:
  TunnelDecryptionImpl() {}
  ~TunnelDecryptionImpl() {}

  void SetKeys(
      const AESKey& layer_key,
      const AESKey& iv_key) {
    if (UsingAESNI())
      m_ECBLayerDecryption.SetKey(layer_key);
    else
      m_CBCLayerDecryption.SetKey(layer_key);
    m_IVDecryption.SetKey(iv_key);
  }

  void Decrypt(
      const std::uint8_t* in,
      std::uint8_t* out) {
    if (UsingAESNI()) {
      __asm__(
          // decrypt IV
          "movups (%[in]), %%xmm0 \n"
          DecryptAES256(sched_iv)
          "movaps %%xmm0, %%xmm1 \n"
          // double IV encryption
          DecryptAES256(sched_iv)
          "movups %%xmm0, (%[out]) \n"
          // decrypt data, IV is xmm1
          "1: \n"
          "add $16, %[in] \n"
          "add $16, %[out] \n"
          "movups (%[in]), %%xmm0 \n"
          "movaps %%xmm0, %%xmm2 \n"
          DecryptAES256(sched_l)
          "pxor %%xmm1, %%xmm0 \n"
          "movups %%xmm0, (%[out]) \n"
          "movaps %%xmm2, %%xmm1 \n"
          "dec %[num] \n"
          "jnz 1b \n"
          :
          : [sched_iv]"r"(m_IVDecryption.GetKeySchedule()),
            [sched_l]"r"(m_ECBLayerDecryption.GetKeySchedule()),
            [in]"r"(in), [out]"r"(out), [num]"r"(63)  // 63 blocks = 1008 bytes
          : "%xmm0", "%xmm1", "%xmm2", "cc", "memory");
    } else {
      m_IVDecryption.Decrypt(
          (const CipherBlock *)in,
          reinterpret_cast<CipherBlock *>(out));  // iv
      m_CBCLayerDecryption.SetIV(out);
      m_CBCLayerDecryption.Decrypt(  // data
          in + 16,
          i2p::tunnel::TUNNEL_DATA_ENCRYPTED_SIZE,
          out + 16);
      m_IVDecryption.Decrypt(  // double iv
          reinterpret_cast<CipherBlock *>(out),
          reinterpret_cast<CipherBlock *>(out));
    }
  }

 private:
  ECBDecryption m_IVDecryption;
  ECBDecryption m_ECBLayerDecryption;  // For AES-NI
  CBCDecryption m_CBCLayerDecryption;
};

TunnelDecryption::TunnelDecryption()
    : m_TunnelDecryptionPimpl(
          std::make_unique<TunnelDecryptionImpl>()) {}

TunnelDecryption::~TunnelDecryption() {}

void TunnelDecryption::SetKeys(
      const AESKey& layer_key,
      const AESKey& iv_key) {
  m_TunnelDecryptionPimpl->SetKeys(layer_key, iv_key);
}

void TunnelDecryption::Decrypt(
      const std::uint8_t* in,
      std::uint8_t* out) {
  m_TunnelDecryptionPimpl->Decrypt(in, out);
}

}  // namespace crypto
}  // namespace i2p
