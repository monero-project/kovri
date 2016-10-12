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

#include <algorithm>
#include <sstream>
#include <string>

#include "crypto/util/x509.h"

struct X509Fixture {
  const std::string cert =
    "-----BEGIN CERTIFICATE-----"
    "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"
    "Zl8pHXKEq3P6LDEtVSJkVUINrslW"
    "-----END CERTIFICATE-----";
};

class X509FixtureImpl : X509Fixture {
  std::stringstream ss;

 public:
  X509FixtureImpl(
      const std::string& cert)
      : ss(cert) {}

  bool GetSigningKey() {
    i2p::crypto::util::X509 x509;
    auto key = x509.GetSigningKey(ss);
    return key.empty();
  }
};

BOOST_FIXTURE_TEST_SUITE(X509, X509Fixture);

// First, test that the cert is valid
BOOST_AUTO_TEST_CASE(GoodX509) {
  X509FixtureImpl x509(cert);
  BOOST_CHECK(!x509.GetSigningKey());
}

// Now, test with bad bytes
BOOST_AUTO_TEST_CASE(BadHeader) {
  std::string str(cert);
  str.front() = '+';
  X509FixtureImpl x509(str);
  BOOST_CHECK(x509.GetSigningKey());
}

BOOST_AUTO_TEST_CASE(BadFooter) {
  std::string str(cert);
  str.back() = '+';
  X509FixtureImpl x509(str);
  BOOST_CHECK(x509.GetSigningKey());
}

BOOST_AUTO_TEST_CASE(BadContent) {
  std::string str(cert);
  str.replace(100, 10, "A");
  X509FixtureImpl x509(str);
  BOOST_CHECK(x509.GetSigningKey());
}

BOOST_AUTO_TEST_SUITE_END()
