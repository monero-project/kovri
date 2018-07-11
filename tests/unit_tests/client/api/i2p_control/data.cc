/**                                                                                           //
 * Copyright (c) 2015-2018, The Kovri I2P Router Project                                      //
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
 */

#include "tests/unit_tests/main.h"

#include <array>
#include <limits>
#include <type_traits>

#include "client/api/i2p_control/data.h"

typedef client::I2PControlResponse Response;
typedef client::I2PControlRequest Request;
typedef Response::ErrorCode ErrorCode;
typedef Response::Method Method;

struct I2PControlPacketFixture
{
  const std::string m_Version{"2.0"};
  std::uint8_t m_Key{0};
};

BOOST_FIXTURE_TEST_SUITE(I2PControlPacketTest, I2PControlPacketFixture)

BOOST_AUTO_TEST_CASE(Errors)
{
  Response response;
  // No error
  response.SetError(ErrorCode::None);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(0)));
  // Standard JSON-RPC2 error codes
  response.SetError(ErrorCode::InvalidRequest);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32600)));
  response.SetError(ErrorCode::MethodNotFound);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32601)));
  response.SetError(ErrorCode::InvalidParameters);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32602)));
  response.SetError(ErrorCode::InternalError);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32603)));
  response.SetError(ErrorCode::ParseError);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32700)));
  // I2PControl specific error codes
  response.SetError(ErrorCode::InvalidPassword);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32001)));
  response.SetError(ErrorCode::NoToken);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32002)));
  response.SetError(ErrorCode::NonexistentToken);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32003)));
  response.SetError(ErrorCode::ExpiredToken);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32004)));
  response.SetError(ErrorCode::UnspecifiedVersion);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32005)));
  response.SetError(ErrorCode::UnsupportedVersion);
  BOOST_CHECK_EQUAL(
      response.GetErrorMsg(), response.GetTrait(response.ErrorFromInt(-32006)));
}

BOOST_AUTO_TEST_CASE(DefaultRequestProperties)
{
  Request request;
  // Check default version
  BOOST_CHECK_EQUAL(request.GetVersion(), m_Version);
  // Check no default method
  BOOST_CHECK(request.GetMethod() == Method::Unknown);
  // Check no default params
  BOOST_CHECK_THROW(request.GetParams(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(DefaultResponseProperties)
{
  Response response;
  // Check default version
  BOOST_CHECK_EQUAL(response.GetVersion(), m_Version);
  // Check default with no error
  BOOST_CHECK(response.GetError() == Response::ErrorCode::None);
  // Check no default params
  BOOST_CHECK_THROW(response.GetParams(), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
