/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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

#include <boost/test/unit_test.hpp>

#include "client/util/http.h"

struct HTTPFixture
{
  class HTTP : public kovri::client::HTTP
  {
   public:
    using Client_t = Client;
    using Options_t = Options;
    using Request_t = Request;
    using Response_t = Response;
  };
  HTTP http;
};

BOOST_FIXTURE_TEST_SUITE(HTTPUtilityTests, HTTPFixture)

BOOST_AUTO_TEST_CASE(UriParse) {
  // Note: cpp-netlib has better tests.
  // We simply test our implementation here.
  http.SetURI("https://domain.org:8443/path/file.type");
  BOOST_CHECK(http.GetURI().is_valid() && !http.HostIsI2P());

  http.SetURI("3;axc807uasdfh123m,nafsdklfj;;klj0a9u01q3");
  BOOST_CHECK(!http.GetURI().is_valid());

  http.SetURI("http://username:password@udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt");
  BOOST_CHECK(http.GetURI().is_valid() && http.HostIsI2P());
}

BOOST_AUTO_TEST_CASE(GoodSNI)
{
  HTTP::Client_t client;
  HTTP::Response_t response;
  // Setup request for host requiring SNI
  HTTP::Request_t request("https://reseed.memcpy.io");
  // Ensure we set the proper SNI hostname
  request.sni_hostname(request.host());
  // Ensure the request itself does not throw
  BOOST_CHECK_NO_THROW(response = client.get(request));
  // Ensure no internal errors are thrown
  BOOST_CHECK_NO_THROW(response.status());
}

BOOST_AUTO_TEST_CASE(BadSNI)
{
  HTTP::Client_t client;
  HTTP::Response_t response;
  // Setup request for host requiring SNI
  HTTP::Request_t request("https://reseed.memcpy.io");
  // Ensure SNI hostname is unset
  request.sni_hostname("");
  // Ensure the request itself does not throw
  BOOST_CHECK_NO_THROW(response = client.get(request));
  // Expect a Boost system error (we unset the SNI hostname)
  BOOST_CHECK_THROW(response.status(), boost::system::system_error);
}

BOOST_AUTO_TEST_SUITE_END()
