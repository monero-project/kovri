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

#include <chrono>
#include <iostream>

#include "crypto/rand.h"
#include "crypto/signature.h"

typedef void (*KeyGenerator)(uint8_t*,uint8_t*) ;

template<class Verifier, class Signer>
void benchmark(
    std::size_t count,
    std::size_t public_key_size,
    std::size_t private_key_size,
    std::size_t signature_size,
    KeyGenerator generator) {
  typedef std::chrono::time_point<std::chrono::high_resolution_clock> TimePoint;
  uint8_t private_key[private_key_size];
  uint8_t public_key[public_key_size];
  generator(private_key, public_key);
  Verifier verifier(public_key);
  Signer signer(private_key);
  uint8_t message[512] = {};
  uint8_t output[signature_size];
  std::chrono::nanoseconds sign_duration(0);
  std::chrono::nanoseconds verify_duration(0);
  for (std::size_t i = 0; i < count; ++i) {
    try {
      i2p::crypto::RandBytes(message, 512);
      TimePoint begin1 = std::chrono::high_resolution_clock::now();
      signer.Sign(message, 512, output);
      TimePoint end1 = std::chrono::high_resolution_clock::now();
      sign_duration +=
        std::chrono::duration_cast<std::chrono::nanoseconds>(end1 - begin1);
      TimePoint begin2 = std::chrono::high_resolution_clock::now();
      verifier.Verify(message, 512, output);
      TimePoint end2 = std::chrono::high_resolution_clock::now();
      verify_duration +=
        std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - begin2);
    } catch (...) {  // Crypto-specific exceptions are (should be) caught internally
      std::cout << "!!! benchmark() caught exception" << std::endl;
      break;
    }
  }
  std::cout << "Conducted " << count << " experiments." << std::endl;
  std::cout << "Total sign time: " <<
    std::chrono::duration_cast<std::chrono::milliseconds>(
        sign_duration).count() << std::endl;
  std::cout << "Total verify time: " <<
    std::chrono::duration_cast<std::chrono::milliseconds>(
        verify_duration).count() << std::endl;
}

int main() {
  const size_t benchmark_count = 1000;
  std::cout << "--------DSA---------" << std::endl;
  benchmark<i2p::crypto::DSAVerifier, i2p::crypto::DSASigner>(
    benchmark_count,
    i2p::crypto::DSA_PUBLIC_KEY_LENGTH,
    i2p::crypto::DSA_PRIVATE_KEY_LENGTH,
    i2p::crypto::DSA_SIGNATURE_LENGTH,
    i2p::crypto::CreateDSARandomKeys);
  std::cout << "-----ECDSAP256------" << std::endl;
  benchmark<i2p::crypto::ECDSAP256Verifier, i2p::crypto::ECDSAP256Signer>(
    benchmark_count,
    i2p::crypto::ECDSAP256_KEY_LENGTH,
    i2p::crypto::ECDSAP256_KEY_LENGTH / 2,
    i2p::crypto::ECDSAP256_KEY_LENGTH,
    i2p::crypto::CreateECDSAP256RandomKeys);
  std::cout << "-----ECDSAP384------" << std::endl;
  benchmark<i2p::crypto::ECDSAP384Verifier, i2p::crypto::ECDSAP384Signer>(
    benchmark_count,
    i2p::crypto::ECDSAP384_KEY_LENGTH,
    i2p::crypto::ECDSAP384_KEY_LENGTH / 2,
    i2p::crypto::ECDSAP384_KEY_LENGTH,
    i2p::crypto::CreateECDSAP384RandomKeys);
  std::cout << "-----ECDSAP521------" << std::endl;
  benchmark<i2p::crypto::ECDSAP521Verifier, i2p::crypto::ECDSAP521Signer>(
    benchmark_count,
    i2p::crypto::ECDSAP521_KEY_LENGTH,
    i2p::crypto::ECDSAP521_KEY_LENGTH / 2,
    i2p::crypto::ECDSAP521_KEY_LENGTH,
    i2p::crypto::CreateECDSAP521RandomKeys);
  std::cout << "-----EDDSA25519-----" << std::endl;
  benchmark<i2p::crypto::EDDSA25519Verifier, i2p::crypto::EDDSA25519Signer>(
    benchmark_count,
    i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH,
    i2p::crypto::EDDSA25519_PRIVATE_KEY_LENGTH,
    i2p::crypto::EDDSA25519_SIGNATURE_LENGTH,
    i2p::crypto::CreateEDDSARandomKeys);
}
