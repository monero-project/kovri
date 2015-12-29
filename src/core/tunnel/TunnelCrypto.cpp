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

#include "TunnelCrypto.h"
#include "TunnelBase.h"
#include "crypto/AESNIMacros.h" 

namespace i2p {
namespace crypto {

void TunnelEncryption::SetKeys (const AESKey& layerKey, const AESKey& ivKey)
{
    m_LayerEncryption.SetKey (layerKey);
    m_IVEncryption.SetKey (ivKey);
}

void TunnelEncryption::Encrypt (const uint8_t * in, uint8_t * out)
{
#ifdef AESNI
    __asm__
    (
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
        : [sched_iv]"r"(m_IVEncryption.GetKeySchedule ()), [sched_l]"r"(m_LayerEncryption.GetKeySchedule ()), 
          [in]"r"(in), [out]"r"(out), [num]"r"(63) // 63 blocks = 1008 bytes
        : "%xmm0", "%xmm1", "cc", "memory"
    );
#else
    m_IVEncryption.Encrypt ((const CipherBlock *)in, (CipherBlock *)out); // iv
    m_LayerEncryption.SetIV (out);
    m_LayerEncryption.Encrypt (in + 16, i2p::tunnel::TUNNEL_DATA_ENCRYPTED_SIZE, out + 16); // data
    m_IVEncryption.Encrypt ((CipherBlock *)out, (CipherBlock *)out); // double iv
#endif
    }

void TunnelDecryption::Decrypt (const uint8_t * in, uint8_t * out)
{
#ifdef AESNI
    __asm__
    (
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
        : [sched_iv]"r"(m_IVDecryption.GetKeySchedule ()), [sched_l]"r"(m_LayerDecryption.GetKeySchedule ()), 
          [in]"r"(in), [out]"r"(out), [num]"r"(63) // 63 blocks = 1008 bytes
        : "%xmm0", "%xmm1", "%xmm2", "cc", "memory"
    );
#else
    m_IVDecryption.Decrypt ((const CipherBlock *)in, (CipherBlock *)out); // iv
    m_LayerDecryption.SetIV (out);  
    m_LayerDecryption.Decrypt (in + 16, i2p::tunnel::TUNNEL_DATA_ENCRYPTED_SIZE, out + 16); // data
    m_IVDecryption.Decrypt ((CipherBlock *)out, (CipherBlock *)out); // double iv
#endif
}

} // crypto
} // i2p
