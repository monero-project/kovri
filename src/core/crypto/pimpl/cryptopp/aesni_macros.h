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

#ifndef SRC_CORE_CRYPTO_PIMPL_CRYPTOPP_AESNIMACROS_H_
#define SRC_CORE_CRYPTO_PIMPL_CRYPTOPP_AESNIMACROS_H_

#define KeyExpansion256(round0, round1) \
  "pshufd $0xff, %%xmm2, %%xmm2 \n" \
  "movaps %%xmm1, %%xmm4 \n" \
  "pslldq $4, %%xmm4 \n" \
  "pxor %%xmm4, %%xmm1 \n" \
  "pslldq $4, %%xmm4 \n" \
  "pxor %%xmm4, %%xmm1 \n" \
  "pslldq $4, %%xmm4 \n" \
  "pxor %%xmm4, %%xmm1 \n" \
  "pxor %%xmm2, %%xmm1 \n" \
  "movaps %%xmm1, "#round0"(%[sched]) \n" \
  "aeskeygenassist $0, %%xmm1, %%xmm4 \n" \
  "pshufd $0xaa, %%xmm4, %%xmm2 \n" \
  "movaps %%xmm3, %%xmm4 \n" \
  "pslldq $4, %%xmm4 \n" \
  "pxor %%xmm4, %%xmm3 \n" \
  "pslldq $4, %%xmm4 \n" \
  "pxor %%xmm4, %%xmm3 \n" \
  "pslldq $4, %%xmm4 \n" \
  "pxor %%xmm4, %%xmm3 \n" \
  "pxor %%xmm2, %%xmm3 \n" \
  "movaps %%xmm3, "#round1"(%[sched]) \n"

#define EncryptAES256(sched) \
  "pxor (%["#sched"]), %%xmm0 \n" \
  "aesenc 16(%["#sched"]), %%xmm0 \n" \
  "aesenc 32(%["#sched"]), %%xmm0 \n" \
  "aesenc 48(%["#sched"]), %%xmm0 \n" \
  "aesenc 64(%["#sched"]), %%xmm0 \n" \
  "aesenc 80(%["#sched"]), %%xmm0 \n" \
  "aesenc 96(%["#sched"]), %%xmm0 \n" \
  "aesenc 112(%["#sched"]), %%xmm0 \n" \
  "aesenc 128(%["#sched"]), %%xmm0 \n" \
  "aesenc 144(%["#sched"]), %%xmm0 \n" \
  "aesenc 160(%["#sched"]), %%xmm0 \n" \
  "aesenc 176(%["#sched"]), %%xmm0 \n" \
  "aesenc 192(%["#sched"]), %%xmm0 \n" \
  "aesenc 208(%["#sched"]), %%xmm0 \n" \
  "aesenclast 224(%["#sched"]), %%xmm0 \n"

#define DecryptAES256(sched) \
  "pxor 224(%["#sched"]), %%xmm0 \n" \
  "aesdec 208(%["#sched"]), %%xmm0 \n" \
  "aesdec 192(%["#sched"]), %%xmm0 \n" \
  "aesdec 176(%["#sched"]), %%xmm0 \n" \
  "aesdec 160(%["#sched"]), %%xmm0 \n" \
  "aesdec 144(%["#sched"]), %%xmm0 \n" \
  "aesdec 128(%["#sched"]), %%xmm0 \n" \
  "aesdec 112(%["#sched"]), %%xmm0 \n" \
  "aesdec 96(%["#sched"]), %%xmm0 \n" \
  "aesdec 80(%["#sched"]), %%xmm0 \n" \
  "aesdec 64(%["#sched"]), %%xmm0 \n" \
  "aesdec 48(%["#sched"]), %%xmm0 \n" \
  "aesdec 32(%["#sched"]), %%xmm0 \n" \
  "aesdec 16(%["#sched"]), %%xmm0 \n" \
  "aesdeclast (%["#sched"]), %%xmm0 \n"

#define CallAESIMC(offset) \
  "movaps "#offset"(%[shed]), %%xmm0 \n"  \
  "aesimc %%xmm0, %%xmm0 \n" \
  "movaps %%xmm0, "#offset"(%[shed]) \n"

#endif  // SRC_CORE_CRYPTO_PIMPL_CRYPTOPP_AESNIMACROS_H_
