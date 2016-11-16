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

#include <boost/test/unit_test.hpp>
#include "client/context.h"
#include "client/proxy/http.h"
#include "client/proxy/http.cc"

BOOST_AUTO_TEST_SUITE(HTTPProxyTests)
kovri::client::ClientContext myContext;
std::shared_ptr<kovri::client::ClientDestination> aDestination = myContext.CreateNewLocalDestination();
kovri::client::HTTPProxyServer httpProxy("test","213rfadsgfsadf",4445,aDestination);
std::shared_ptr<boost::asio::ip::tcp::socket> socket;
//std::shared_ptr<kovri::client::I2PServiceHandler> handler = httpProxy.CreateHandler(socket);
auto handler = std::make_shared<kovri::client::HTTPProxyHandler>(&httpProxy, socket);

BOOST_AUTO_TEST_CASE(HandleData) {
  // Note: cpp-netlib has better tests.
  // We simply test our implementation here.
  //std::shared_ptr<boost::asio::ip::tcp::socket> socket;
  std::string bufferOK = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
  BOOST_CHECK(handler->HandleData((std::uint8_t*) bufferOK.c_str(),(std::size_t) bufferOK.size()));
  std::string bufferNoDoubleCR = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n";
  BOOST_CHECK(!handler->HandleData((std::uint8_t*)bufferNoDoubleCR.c_str(),(std::size_t)bufferNoDoubleCR.size()));
  std::string bufferNoMethod= "/index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
  BOOST_CHECK(!handler->HandleData((std::uint8_t*)bufferNoDoubleCR.c_str(),(std::size_t)bufferNoDoubleCR.size()));
}

BOOST_AUTO_TEST_SUITE_END()
