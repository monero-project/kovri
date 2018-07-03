/**                                                                                           //
 * Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
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
#define BOOST_TEST_DYN_LINK

#include "client/proxy/http.h"

#include <boost/test/unit_test.hpp>

struct HTTPProxyRequestFixture
{
  class HTTPMessage
  {
   public:
    explicit HTTPMessage(const std::string& request) : m_Request(request)
    {
      m_Request.append("GET " + request + " HTTP/1.1\r\n\r\n");
      // TODO(unassigned): message class should have private handlers. This would be useful within its ctor.
      if (!m_Message.HandleData(m_Request))
        throw std::runtime_error("HTTPMessage: invalid request");
    }

    // TODO(unassigned): message API needs a proper interface
    kovri::client::HTTPMessage& get()
    {
      return m_Message;
    }

   private:
    std::string m_Request;
    // TODO(unassigned): message API needs a proper ctor
    kovri::client::HTTPMessage m_Message;
  };

  // Valid web-safe destination
  std::string const valid_dest = "0UVPqAA4xUSfPYPBca24h8fdokhwcJZ-5OsBYvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rt9SzLkcpwhOjXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdWCAPio5Z-YnRL46n0IHWOQPYYSSt-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MB-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7Q-EITwNlKN6~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA%3D%3D";
};

BOOST_AUTO_TEST_SUITE(HTTPMessageHeader)

BOOST_AUTO_TEST_CASE(Short)
{
  kovri::client::HTTPMessage tmp;
  BOOST_CHECK(!tmp.HandleData("GET kovri.i2p HTTP/1.1"));
}

BOOST_AUTO_TEST_CASE(MissingRequest)
{
  kovri::client::HTTPMessage tmp;
  BOOST_CHECK(!tmp.HandleData("GET HTTP/1.1"));
}

BOOST_AUTO_TEST_CASE(MissingHeaders)
{
  kovri::client::HTTPMessage tmp;
  BOOST_CHECK(!tmp.HandleData("\r\n"));
}

BOOST_AUTO_TEST_CASE(Valid)
{
  kovri::client::HTTPMessage tmp;
  BOOST_CHECK(
      tmp.HandleData("GET kovri.i2p HTTP/1.1\r\nUser-Agent: dummy\r\n\r\n"));
}

BOOST_AUTO_TEST_SUITE_END()

/**
 *
 * Jump service handler
 *
 */

BOOST_FIXTURE_TEST_SUITE(JumpServiceHandler, HTTPProxyRequestFixture)

BOOST_AUTO_TEST_CASE(Valid)
{
  std::string const request("stats.i2p?i2paddresshelper=" + valid_dest);
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  BOOST_CHECK(message.get().HandleJumpService());
}

BOOST_AUTO_TEST_CASE(WithURIQuery)
{
  std::string const request(
      "stats.i2p?some=key&i2paddresshelper=" + valid_dest);
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  BOOST_CHECK(message.get().HandleJumpService());
}

BOOST_AUTO_TEST_CASE(InvalidDest)
{
  std::string const request(
      "stats.i2p?i2paddresshelper=someinvalidbase64&i2paddresshelper="
      + valid_dest);
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  // TODO(unassigned): if this is an invalid test-case, then check false
  BOOST_CHECK(message.get().HandleJumpService());
}

BOOST_AUTO_TEST_CASE(InvalidDestWithURIQuery)
{
  std::string const request(
      "stats.i2p?some=key&i2paddresshelper=someinvalidbase64?i2paddresshelper="
      + valid_dest);
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  // TODO(unassigned): if this is an invalid test-case, then check false
  BOOST_CHECK(message.get().HandleJumpService());
}

BOOST_AUTO_TEST_CASE(InvalidHelper)
{
  std::string const request("stats.i2p?invalid=" + valid_dest);
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  BOOST_CHECK(!message.get().HandleJumpService());
}

BOOST_AUTO_TEST_CASE(InvalidHelperWithURIQuery)
{
  std::string const request("stats.i2p?some=key&invalid=" + valid_dest);
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  BOOST_CHECK(!message.get().HandleJumpService());
}

BOOST_AUTO_TEST_CASE(NoHelper)
{
  std::string const request("stats.i2p");
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  BOOST_CHECK(!message.get().HandleJumpService());
}

BOOST_AUTO_TEST_CASE(NoDest)
{
  std::string const request("stats.i2p?i2paddresshelper=");
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  BOOST_CHECK(!message.get().HandleJumpService());
}

BOOST_AUTO_TEST_SUITE_END()

/**
 *
 * HTTP request creation w/ jump service
 *
 */

BOOST_FIXTURE_TEST_SUITE(CreateHTTPRequest, HTTPProxyRequestFixture)

BOOST_AUTO_TEST_CASE(ValidHelper)
{
  std::string const request("stats.i2p?i2paddresshelper=" + valid_dest);
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  BOOST_CHECK(message.get().CreateHTTPRequest(false));
}

BOOST_AUTO_TEST_CASE(InvalidHelper)
{
  std::string const request("stats.i2p?invalid=" + valid_dest);
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  // TODO(unassigned): if this is an invalid test-case, then check false
  BOOST_CHECK(message.get().CreateHTTPRequest(false));
}

BOOST_AUTO_TEST_CASE(NoDest)
{
  std::string const request("stats.i2p?i2paddresshelper=");
  BOOST_CHECK_NO_THROW(HTTPMessage message(request));

  HTTPMessage message(request);
  BOOST_CHECK(!message.get().CreateHTTPRequest(false));
}

BOOST_AUTO_TEST_SUITE_END()

/**
 *
 * HTTP response creation
 *
 */

BOOST_AUTO_TEST_SUITE(CreateHTTPResponse)

BOOST_AUTO_TEST_CASE(ValidResponse)
{
  namespace client = kovri::client;
  const auto status = client::HTTPResponse::ok;

  BOOST_CHECK_NO_THROW(client::HTTPResponse response(status));

  client::HTTPResponse response(status);

  BOOST_CHECK(response.get().size());

  BOOST_CHECK_NE(
      response.get().find(std::to_string(status)), std::string::npos);

  BOOST_CHECK_NE(
      response.get().find(response.get_message(status)), std::string::npos);

  // TODO(oneiric): after Boost.Beast refactor, check response follows HTTP protocol
}

BOOST_AUTO_TEST_SUITE_END()
