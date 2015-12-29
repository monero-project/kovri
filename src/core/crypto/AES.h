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

#ifndef AES_H__
#define AES_H__

#include <inttypes.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include "Identity.h"

namespace i2p
{
namespace crypto
{   
    struct CipherBlock 
    {
        uint8_t buf[16];

        void operator^=(const CipherBlock& other) // XOR
        {
#if defined(__x86_64__) // for Intel x64 
            __asm__
            (
                "movups (%[buf]), %%xmm0 \n"    
                "movups (%[other]), %%xmm1 \n"  
                "pxor %%xmm1, %%xmm0 \n"
                "movups %%xmm0, (%[buf]) \n"
                : 
                : [buf]"r"(buf), [other]"r"(other.buf) 
                : "%xmm0", "%xmm1", "memory"
            );          
#else
            // TODO(unassigned): implement it better
            for (int i = 0; i < 16; i++)
                buf[i] ^= other.buf[i];
#endif
        }    
    };

    typedef i2p::data::Tag<32> AESKey;
    
    template<size_t sz>
    class AESAlignedBuffer // 16 bytes alignment
    {
        public:
        
            AESAlignedBuffer ()
            {
                m_Buf = m_UnalignedBuffer;
                uint8_t rem = ((size_t)m_Buf) & 0x0f;
                if (rem)
                    m_Buf += (16 - rem);
            }
        
            operator uint8_t * () { return m_Buf; };
            operator const uint8_t * () const { return m_Buf; };

        private:

            uint8_t m_UnalignedBuffer[sz + 15]; // up to 15 bytes alignment
            uint8_t * m_Buf;
    };          


#ifdef AESNI
    class ECBCryptoAESNI
    {   
        public:

            uint8_t * GetKeySchedule () { return m_KeySchedule; };

        protected:

            void ExpandKey (const AESKey& key);
        
        private:

            AESAlignedBuffer<240> m_KeySchedule;  // 14 rounds for AES-256, 240 bytes
    };  

    class ECBEncryptionAESNI: public ECBCryptoAESNI
    {
        public:
        
            void SetKey (const AESKey& key) { ExpandKey (key); };
            void Encrypt (const CipherBlock * in, CipherBlock * out); 
    };  

    class ECBDecryptionAESNI: public ECBCryptoAESNI
    {
        public:
        
            void SetKey (const AESKey& key);
            void Decrypt (const CipherBlock * in, CipherBlock * out);     
    };  

    typedef ECBEncryptionAESNI ECBEncryption;
    typedef ECBDecryptionAESNI ECBDecryption;

#else // use crypto++

    class ECBEncryption
    {
        public:
        
            void SetKey (const AESKey& key) 
            { 
                m_Encryption.SetKey (key, 32); 
            }
            void Encrypt (const CipherBlock * in, CipherBlock * out)
            {
                m_Encryption.ProcessData (out->buf, in->buf, 16);
            }   

        private:

            CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption m_Encryption;
    };  

    class ECBDecryption
    {
        public:
        
            void SetKey (const AESKey& key) 
            { 
                m_Decryption.SetKey (key, 32); 
            }
            void Decrypt (const CipherBlock * in, CipherBlock * out)
            {
                m_Decryption.ProcessData (out->buf, in->buf, 16);
            }   

        private:

            CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption m_Decryption;
    };      


#endif          

    class CBCEncryption
    {
        public:
    
            CBCEncryption () { memset (m_LastBlock.buf, 0, 16); };
            CBCEncryption(const AESKey& key, const uint8_t* iv)
                : CBCEncryption()
            {
                SetKey(key);
                SetIV(iv);
            }

            void SetKey (const AESKey& key) { m_ECBEncryption.SetKey (key); }; // 32 bytes
            void SetIV (const uint8_t * iv) { memcpy (m_LastBlock.buf, iv, 16); }; // 16 bytes

            void Encrypt (int numBlocks, const CipherBlock * in, CipherBlock * out);
            void Encrypt (const uint8_t * in, std::size_t len, uint8_t * out);
            void Encrypt (const uint8_t * in, uint8_t * out); // one block

        private:

            CipherBlock m_LastBlock;
            
            ECBEncryption m_ECBEncryption;
    };

    class CBCDecryption
    {
        public:
    
            CBCDecryption () { memset (m_IV.buf, 0, 16); };

            CBCDecryption(const AESKey& key, const uint8_t* iv)
                : CBCDecryption()
            {
                SetKey(key);
                SetIV(iv);
            }

            void SetKey (const AESKey& key) { m_ECBDecryption.SetKey (key); }; // 32 bytes
            void SetIV (const uint8_t * iv) { memcpy (m_IV.buf, iv, 16); }; // 16 bytes

            void Decrypt (int numBlocks, const CipherBlock * in, CipherBlock * out);
            void Decrypt (const uint8_t * in, std::size_t len, uint8_t * out);
            void Decrypt (const uint8_t * in, uint8_t * out); // one block

        private:

            CipherBlock m_IV;
            ECBDecryption m_ECBDecryption;
    };  

}
}

#endif
