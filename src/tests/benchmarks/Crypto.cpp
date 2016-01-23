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

#include <cryptopp/osrng.h>

#include <chrono>
#include <iostream>

#include "Alloc.h"
#include "crypto/Rand.h"
#include "crypto/Signature.h"

typedef void (*KeyGenerator)(uint8_t*,uint8_t*) ;

template<class Verifier, class Signer>
void benchmark(
    std::size_t count,
    std::size_t public_key_size,
    std::size_t private_key_size,
    std::size_t signature_size,
    KeyGenerator generator) {
  typedef std::chrono::time_point<std::chrono::high_resolution_clock> TimePoint;
  std::size_t badVerify = 0;
  i2p::Buffer private_key(private_key_size);
  i2p::Buffer public_key(public_key_size);
  generator(private_key, public_key);
  Verifier verifier(public_key);
  Signer signer(private_key);
  i2p::Buffer message(512);
  i2p::Buffer output(signature_size);
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
      if( ! verifier.Verify(message, 512, output) ) {
        badVerify ++;
      }
      TimePoint end2 = std::chrono::high_resolution_clock::now();
      verify_duration +=
        std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - begin2);
    } catch ( CryptoPP::Exception & ex ) {
      std::cout << "!!! " << ex.what() << std::endl;
      break;
    }
  }
  std::cout << "Conducted " << count << " experiments." << std::endl;
  std::cout << "Bad Signatures: " << badVerify << std::endl;
  std::cout << "Total sign time: " <<
    std::chrono::duration_cast<std::chrono::milliseconds>(
        sign_duration).count() << std::endl;
  std::cout << "Total verify time: " <<
    std::chrono::duration_cast<std::chrono::milliseconds>(
        verify_duration).count() << std::endl;
}


int main() {
  // TODO(unassigned): don't use namespace using-directives
  const size_t benchmark_count = 1000;
  using namespace i2p::crypto;
  std::cout << "--------DSA---------" << std::endl;
  benchmark<DSAVerifier, DSASigner>(
    benchmark_count, DSA_PUBLIC_KEY_LENGTH,
    DSA_PRIVATE_KEY_LENGTH, DSA_SIGNATURE_LENGTH,
    CreateDSARandomKeys);
  std::cout << "-----ECDSAP256------" << std::endl;
  benchmark<ECDSAP256Verifier, ECDSAP256Signer>(
    benchmark_count, ECDSAP256_KEY_LENGTH,
    ECDSAP256_KEY_LENGTH / 2, ECDSAP256_KEY_LENGTH,
    CreateECDSAP256RandomKeys);
  std::cout << "-----ECDSAP384------" << std::endl;
  benchmark<ECDSAP384Verifier, ECDSAP384Signer>(
    benchmark_count, ECDSAP384_KEY_LENGTH,
    ECDSAP384_KEY_LENGTH / 2, ECDSAP384_KEY_LENGTH,
    CreateECDSAP384RandomKeys);
  std::cout << "-----ECDSAP521------" << std::endl;
  benchmark<ECDSAP521Verifier, ECDSAP521Signer>(
    benchmark_count, ECDSAP521_KEY_LENGTH,
    ECDSAP521_KEY_LENGTH / 2, ECDSAP521_KEY_LENGTH,
    CreateECDSAP521RandomKeys);
  std::cout << "-----EDDSA25519-----" << std::endl;
  benchmark<EDDSA25519Verifier, EDDSA25519Signer>(
    benchmark_count, EDDSA25519_PUBLIC_KEY_LENGTH,
    EDDSA25519_PRIVATE_KEY_LENGTH, EDDSA25519_SIGNATURE_LENGTH,
    CreateEDDSARandomKeys);
}
