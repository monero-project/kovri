/**                                                                                           //
 * Copyright (c) 2015-2016, The Kovri I2P Router Project                                      //
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
 */

#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include <limits>

#include "crypto/rand.h"

/// TODO(unassigned): unit-tests for all crypto::Rand* functions

BOOST_AUTO_TEST_SUITE(RandInRange)

template <class T>
struct Range {
  T repeated, count;
  T min, max, result;
  T Test();
  Range()
      : repeated(0),
        count(0),
        min(0),
        max(std::numeric_limits<T>::max()) {
          result = Test();
        }
};

template <class T>
T Range<T>::Test() {
  do {
    repeated = result;
    result = i2p::crypto::RandInRange<T>(min, max);
    count++;
  } while ((count != 100));  // Arbitrary number
  return ((result >= min) &&
          (result <= max) &&
          (result != repeated));  // A bit harsh?
}

BOOST_AUTO_TEST_CASE(_uint8_t) {
  Range<uint8_t> test;
  BOOST_CHECK(test.result);
}

BOOST_AUTO_TEST_CASE(_uint16_t) {
  Range<uint16_t> test;
  BOOST_CHECK(test.result);
}

BOOST_AUTO_TEST_CASE(_uint32_t) {
  Range<uint32_t> test;
  BOOST_CHECK(test.result);
}

BOOST_AUTO_TEST_CASE(_uint64_t) {
  Range<uint64_t> test;
  BOOST_CHECK(test.result);
}

// Signed, so test for negative results
// regardless of initialized lowerbound
BOOST_AUTO_TEST_CASE(_int) {
  Range<int> test;
  BOOST_CHECK(test.result);
}

BOOST_AUTO_TEST_CASE(_long) {
  Range<long> test;
  BOOST_CHECK(test.result);
}

BOOST_AUTO_TEST_SUITE_END()
