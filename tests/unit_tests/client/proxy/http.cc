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
#include <boost/test/unit_test.hpp>
#include "client/proxy/http.h"

struct HTTPProxyRequestFixture
{
  enum struct FunctionName 
  {
    CreateHTTPRequest,
    ExtractIncomingRequest,
    HandleData,
    HandleJumpService
  };

  std::string CreateProxyHeader(const std::string uri) const
  {
    std::string proxy_header("GET ");
    proxy_header.append(uri);
    proxy_header.append(" HTTP/1.1\r\n\r\n");
    return proxy_header;
  }

  bool HandleProxyFunction(
      const std::string uri,
      FunctionName function_name) const
  {
    std::string const header = CreateProxyHeader(uri);
    kovri::client::HTTPMessage proxy_request;
    if (!proxy_request.HandleData(header))
      return false;
    switch (function_name)
      {
        case FunctionName::CreateHTTPRequest:
          if (!proxy_request.CreateHTTPRequest())
            return false;
          break;
        case FunctionName::ExtractIncomingRequest:
          if (!proxy_request.ExtractIncomingRequest())
            return false;
          break;
        case FunctionName::HandleJumpService:
          if (!proxy_request.HandleJumpService())
            return false;
          break;
        default:
          throw std::invalid_argument("unknown proxy function");
      }
    return true;
  }
};

BOOST_AUTO_TEST_SUITE(HTTPPProtocolTests)

BOOST_AUTO_TEST_CASE(Short) {
  kovri::client::HTTPMessage tmp;
  std::string tmpData = "GET guzzi.i2p HTTP/1.1";
  BOOST_CHECK(!tmp.HandleData(tmpData));
}
BOOST_AUTO_TEST_CASE(requestLineBad) {
  kovri::client::HTTPMessage tmp;
  std::string tmpData = "GET HTTP/1.1";
  BOOST_CHECK(!tmp.HandleData(tmpData));
}
BOOST_AUTO_TEST_CASE(noHeadersAtAll) {
  kovri::client::HTTPMessage tmp;
  std::string tmpData = "\r\n";
  BOOST_CHECK(!tmp.HandleData(tmpData));
}
BOOST_AUTO_TEST_CASE(ok) {
  kovri::client::HTTPMessage tmp;
  std::string tmpData = "GET guzzi.i2p ";
  tmpData+="HTTP/1.1\r\nUser-Agent: dummy\r\n\r\n";
  BOOST_CHECK(tmp.HandleData(tmpData));
}

BOOST_AUTO_TEST_SUITE_END()

/**
 *
 * Jump service request tests
 *
 */

BOOST_FIXTURE_TEST_SUITE(HTTPProxyJumpServiceTests, HTTPProxyRequestFixture)

BOOST_AUTO_TEST_CASE(JumpServiceI2PAddressHelper)
{
  // Valid jump service request
  std::string const valid_jump_request("stats.i2p?i2paddresshelper=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ-5OsBYvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rt9SzLkcpwhOjXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdWCAPio5Z-YnRL46n0IHWOQPYYSSt-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MB-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7Q-EITwNlKN6~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA%3D%3D");
  BOOST_CHECK(HandleProxyFunction(valid_jump_request, FunctionName::HandleJumpService));
}

BOOST_AUTO_TEST_CASE(JumpServiceI2PAddressHelperSecondParam)
{
  // Jump service request with preceding non-jump-service parameter
  std::string const valid_jump_following("stats.i2p?some=key&i2paddresshelper=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ4zWvELv-5OsBYTHKtnLzvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rpwhO3t0Zwe6jXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdW-YnRL46n0IHWOQPYYSSt-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MB-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7Q-EITwNlKN6~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA%3D%3D");
  BOOST_CHECK(HandleProxyFunction(valid_jump_following, FunctionName::HandleJumpService));
}

BOOST_AUTO_TEST_CASE(JumpServiceInvalidThenValidHelper)
{
  // Jump service helper with preceding invalid helper
  std::string const invalid_then_valid_jump("stats.i2p?i2paddresshelper=someinvalidbase64&i2paddresshelper=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ4zWvELv-5OsBYTHKtnLzvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rpwhO3t0Zwe6jXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdW-YnRL46n0IHWOQPYYSSt-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MB-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7Q-EITwNlKN6~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA%3D%3D");
  BOOST_CHECK(HandleProxyFunction(invalid_then_valid_jump, FunctionName::HandleJumpService));
}

BOOST_AUTO_TEST_CASE(JumpServiceMultiHelpersOutOfOrder)
{
  // Jump service helper with non-jump-service parameter,
  //   followed by an invalid jump service helper,
  //   followed by a valid jump service helper
  std::string const multi_invalid_then_valid_jump("stats.i2p?some=key&i2paddresshelper=someinvalidbase64?i2paddresshelper=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ4zWvELv-5OsBYTHKtnLzvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rpwhO3t0Zwe6jXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdW-YnRL46n0IHWOQPYYSSt-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MB-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7Q-EITwNlKN6~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA%3D%3D");
  BOOST_CHECK(HandleProxyFunction(multi_invalid_then_valid_jump, FunctionName::HandleJumpService));
}

BOOST_AUTO_TEST_CASE(JumpServiceInvalidHelperSingle)
{
  // Invalid single jump service helper
  std::string const invalid_single_jump("stats.i2p?i2paBBresshelper=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ4zWvELv-5OsBYTHKtnLzvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rt9SzLkcpwhO3t0Zwe6jXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdWCAPio5Z-YnRL46n0IHWOQPYYSStJMYPlPS-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVF2qwQRnBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MBw7pmABr-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7QRmT4X8X-EITwNlKN6r1t3uoQ~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA%3D%3D");
  BOOST_CHECK(!HandleProxyFunction(invalid_single_jump, FunctionName::HandleJumpService));
}

BOOST_AUTO_TEST_CASE(JumpServiceInvalidHelperMultiple)
{
  // Invalid jump service helper with preceding non-jump-service parameter
  std::string const invalid_multiple_jump("stats.i2p?some=key&i2paBBresshelper=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ4zWvELv-5OsBYTHKtnLzvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rt9SzLkcpwhO3t0Zwe6jXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdWCAPio5Z-YnRL46n0IHWOQPYYSStJMYPlPS-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVF2qwQRnBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MBw7pmABr-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7QRmT4X8X-EITwNlKN6r1t3uoQ~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA%3D%3D");
  BOOST_CHECK(!HandleProxyFunction(invalid_multiple_jump, FunctionName::HandleJumpService));
}

BOOST_AUTO_TEST_CASE(JumpServiceNoHelper)
{
  std::string const no_jump_helper("stats.i2p");
  BOOST_CHECK(!HandleProxyFunction(no_jump_helper, FunctionName::HandleJumpService));
}

BOOST_AUTO_TEST_CASE(JumpServiceNoBase64)
{
  std::string const no_jump_base64("stats.i2p?i2paddresshelper=");
  BOOST_CHECK(!HandleProxyFunction(no_jump_base64, FunctionName::HandleJumpService));
}

/**
 *
 * CreateHTTPRequest jump service tests
 *
 */

BOOST_AUTO_TEST_CASE(CreateHTTPRequestJumpService)
{
  // Valid jump service request
  std::string const valid_jump_request("stats.i2p?i2paddresshelper=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ-5OsBYvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rt9SzLkcpwhOjXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdWCAPio5Z-YnRL46n0IHWOQPYYSSt-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MB-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7Q-EITwNlKN6~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA%3D%3D");
  BOOST_CHECK(HandleProxyFunction(valid_jump_request, FunctionName::CreateHTTPRequest));
}

BOOST_AUTO_TEST_CASE(CreateHTTPRequestJumpServiceInvalid)
{
  // Invalid single jump service helper
  // Should pass, this could still be a valid HTTP proxy request
  std::string const invalid_single_jump("stats.i2p?i2paBBresshelper=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ4zWvELv-5OsBYTHKtnLzvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rt9SzLkcpwhO3t0Zwe6jXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdWCAPio5Z-YnRL46n0IHWOQPYYSStJMYPlPS-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVF2qwQRnBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MBw7pmABr-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7QRmT4X8X-EITwNlKN6r1t3uoQ~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA%3D%3D");
  BOOST_CHECK(HandleProxyFunction(invalid_single_jump, FunctionName::CreateHTTPRequest));
}

BOOST_AUTO_TEST_CASE(CreateHTTPRequestJumpServiceNoBase64)
{
  std::string const no_jump_base64("stats.i2p?i2paddresshelper=");
  BOOST_CHECK(!HandleProxyFunction(no_jump_base64, FunctionName::CreateHTTPRequest));
}

BOOST_AUTO_TEST_SUITE_END()
