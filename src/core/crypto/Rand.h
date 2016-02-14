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

#ifndef SRC_CORE_CRYPTO_RAND_H_
#define SRC_CORE_CRYPTO_RAND_H_

#include <cstdlib>
#include <random>
#include <stdexcept>

namespace i2p {
namespace crypto {

  /// Generate random bytes
  /// @param dataptr buffer to store result
  /// @param datalen size of buffer
  void RandBytes(
      uint8_t* dataptr,
      size_t datalen);

  /// Generate random of type T
  template<class T>
  T Rand() {
    T ret;
    // TODO(unassigned): alignment
    RandBytes((uint8_t*)&ret, sizeof(ret));
    return ret;
  }

  /// Returns a random integer of type T from a true
  /// range of integers (either signed or unsigned).
  ///
  /// CAUTION: as with usual good programming practice,
  /// if an implementer expects that x or y should meet their
  /// lower/upper-bound requirement, they should test that
  /// x or y is satisfied before implementing this function
  /// (e.g., if you expect x < y but y < x, a true range will
  /// still be produced - and your y function is likely broken).
  ///
  /// @param T : integer type
  /// @param x : assumed to be lowerbound (but not necessary)
  /// @param y : assumed to be upperbound (but not necessary)
  /// @return  : random number in range [x, y]
  template<class T>
  T RandInRange(T x, T y) {
    std::mt19937 mte(Rand<T>());
    std::uniform_int_distribution<T> d(x, y);
    return d(mte);
  }

}  // namespace crypto
}  // namespace i2p

#endif  // SRC_CORE_CRYPTO_RAND_H_
