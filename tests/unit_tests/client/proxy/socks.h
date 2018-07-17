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

#ifndef TESTS_UNIT_TESTS_CLIENT_PROXY_SOCKS_H_
#define TESTS_UNIT_TESTS_CLIENT_PROXY_SOCKS_H_

#include "tests/unit_tests/main.h"

#include "client/proxy/socks.h"

struct SOCKSProxyFixture
{
  struct StubHandler : public client::SOCKSHandler
  {
    StubHandler(
        client::SOCKSServer* server,
        std::shared_ptr<boost::asio::ip::tcp::socket> socket)
        : client::SOCKSHandler(server, socket)
    {
    }

    // Type aliases to expose protected handler enums
    using State = client::SOCKSHandler::State;
    using AuthMethods = client::SOCKSHandler::AuthMethods;
    using AddressTypes = client::SOCKSHandler::AddressTypes;
    using ErrorTypes = client::SOCKSHandler::ErrorTypes;
    using CommandTypes = client::SOCKSHandler::CommandTypes;
    using SOCKSVersions = client::SOCKSHandler::SOCKSVersions;
    using Address = client::SOCKSHandler::Address;

    auto GenerateResponse(
        SOCKSVersions version = SOCKSVersions::SOCKS5,
        ErrorTypes error = ErrorTypes::SOCKS5Success,
        AddressTypes type = AddressTypes::DNS,
        const std::uint32_t ip = 0,
        const std::array<std::uint8_t, 16> ipv6 = {},
        const std::string& dns = "kovri.i2p",
        const std::uint16_t port = 0);

    bool HandleData(std::uint8_t* buf, const std::size_t len);

    void CheckResponse(const SOCKSVersions version, const ErrorTypes error);

    bool CheckHandleData(
        const SOCKSVersions version,
        const AddressTypes type,
        const CommandTypes cmd);

    bool CheckSOCKS5Auth(const AuthMethods auth);

    std::array<std::uint8_t, 8> v4_res {{
      // version, error
      0x00, 0x00,
      // port
      0x00, 0x00,
      // ip
      0x00, 0x00, 0x00, 0x00
    }};

    std::array<std::uint8_t, 16> v5_dns_res {{
      // version, error, reserved, address type
      0x05, 0x00, 0x00, 0x03,
      // address length
      0x09,
      // "kovri.i2p" in hex
      0x6b, 0x6f, 0x76, 0x72, 0x69, 0x2e, 0x69, 0x32, 0x70,
      // port
      0x00, 0x00
    }};

    std::array<std::uint8_t, 14> v4_req {{
      // version, command
      0x04, 0x01,
      // port
      0x00, 0x00,
      // IP
      0x00, 0x00, 0x00, 0x00,
      // user ID: "kovri" in hex, null-terminated
      0x6b, 0x6f, 0x76, 0x72, 0x69, 0x00
    }};

    std::array<std::uint8_t, 24> v4a_req {{
      // version, command
      0x04, 0x01,
      // port
      0x00, 0x00,
      // IP: intentionally invalid, see spec
      0x00, 0x00, 0x00, 0x01,
      // user ID: "kovri" in hex, null-terminated
      0x6b, 0x6f, 0x76, 0x72, 0x69, 0x00,
      // domain name: "kovri.i2p" in hex, null-terminated
      0x6b, 0x6f, 0x76, 0x72, 0x69, 0x2e, 0x69, 0x32, 0x70, 0x00
    }};

    std::array<std::uint8_t, 3> v5_greet_req {{
      // version, number methods, method(s)
      0x05, 0x01, 0x00
    }};

    std::array<std::uint8_t, 10> v5_ipv4_req {{
      // version, command, reserved
      0x05, 0x01, 0x00,
      // address type
      0x01,
      // IP
      0x00, 0x00, 0x00, 0x00,
      // port
      0x00, 0x00
    }};

    std::array<std::uint8_t, 16> v5_dns_req {{
      // version, command, reserved
      0x05, 0x01, 0x00,
      // address type
      0x03,
      // domain name: name size + "kovri.i2p" in hex
      0x09, 0x6b, 0x6f, 0x76, 0x72, 0x69, 0x2e, 0x69, 0x32, 0x70,
      // port
      0x00, 0x00
    }};

    std::array<std::uint8_t, 22> v5_ipv6_req {{
      // version, command, reserved
      0x05, 0x01, 0x00,
      // address type
      0x04,
      // IPv6 address
      0xfe, 0x80, 0x6f, 0x76, 0x72, 0x69, 0x2e, 0x69,
      0x32, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // port
      0x00, 0x00
    }};
  };

  SOCKSProxyFixture();

  std::shared_ptr<client::ClientDestination> dest;
  std::unique_ptr<client::SOCKSServer> server;
  std::shared_ptr<StubHandler> handler;
  std::shared_ptr<boost::asio::ip::tcp::socket> socket;

  const StubHandler::SOCKSVersions v4 = StubHandler::SOCKSVersions::SOCKS4;
  const StubHandler::SOCKSVersions v5 = StubHandler::SOCKSVersions::SOCKS5;
  const StubHandler::AddressTypes ipv4 = StubHandler::AddressTypes::IPv4;
  const StubHandler::AddressTypes dns = StubHandler::AddressTypes::DNS;
  const StubHandler::AddressTypes ipv6 = StubHandler::AddressTypes::IPv6;
};

#endif  // TESTS_UNIT_TESTS_CLIENT_PROXY_SOCKS_H_
