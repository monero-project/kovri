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

#include "tests/unit_tests/client/proxy/socks.h"

SOCKSProxyFixture::SOCKSProxyFixture()
{
  dest = std::make_shared<client::ClientDestination>(
      core::PrivateKeys::CreateRandomKeys(
          core::DEFAULT_CLIENT_SIGNING_KEY_TYPE),
      false,
      nullptr);
  server = std::make_unique<client::SOCKSServer>("127.0.0.1", 0, dest);
  socket = std::make_shared<boost::asio::ip::tcp::socket>(dest->GetService());
  handler = std::make_shared<StubHandler>(server.get(), socket);
}

auto SOCKSProxyFixture::StubHandler::GenerateResponse(
    SOCKSVersions version,
    ErrorTypes error,
    AddressTypes type,
    const std::uint32_t ip,
    const std::array<std::uint8_t, 16> ipv6,
    const std::string& dns,
    const std::uint16_t port)
{
  StubHandler::Address address;
  address.ip = ip;
  std::copy(ipv6.begin(), ipv6.end(), address.ipv6);
  address.dns.FromString(dns);

  return version == SOCKSVersions::SOCKS4
             ? client::SOCKSHandler::GenerateSOCKS4Response(
                   error, ip, port)
             : client::SOCKSHandler::GenerateSOCKS5Response(
                   error, type, address, port);
}

bool SOCKSProxyFixture::StubHandler::HandleData(std::uint8_t* buf, const std::size_t len)
{
  return client::SOCKSHandler::HandleData(buf, len);
}

void SOCKSProxyFixture::StubHandler::CheckResponse(
    const StubHandler::SOCKSVersions version,
    const StubHandler::ErrorTypes error)
{
  auto response = GenerateResponse(version, error);
  const auto buf = boost::asio::buffer_cast<const std::uint8_t*>(response);
  const std::size_t size = boost::asio::buffer_size(response);

  BOOST_CHECK(buf && size);

  auto res =
      version == StubHandler::SOCKSVersions::SOCKS4
          ? std::vector<std::uint8_t>(v4_res.begin(), v4_res.end())
          : std::vector<std::uint8_t>(v5_dns_res.begin(), v5_dns_res.end());

  // Set error code in response
  res[1] = error;

  BOOST_CHECK_EQUAL_COLLECTIONS(buf, buf + size, res.begin(), res.end());
}

bool SOCKSProxyFixture::StubHandler::CheckHandleData(
    const SOCKSVersions version,
    const AddressTypes type,
    const CommandTypes cmd)
{
  std::vector<std::uint8_t> req;

  if (version == SOCKSVersions::SOCKS4)
    {
      if (type == AddressTypes::IPv4)
        {
          req = std::vector<std::uint8_t>(v4_req.begin(), v4_req.end());
        }
      else
        {
          req = std::vector<std::uint8_t>(v4a_req.begin(), v4a_req.end());
        }
      // Set state machine to process connect request
      client::SOCKSHandler::EnterState(StubHandler::State::GetSOCKSVersion);
    }
  else
    {
      switch (type)
        {
          case StubHandler::AddressTypes::IPv4:
            req = std::vector<std::uint8_t>(
                v5_ipv4_req.begin(), v5_ipv4_req.end());
            break;
          case StubHandler::AddressTypes::DNS:
            req =
                std::vector<std::uint8_t>(v5_dns_req.begin(), v5_dns_req.end());
            break;
          case StubHandler::AddressTypes::IPv6:
            req = std::vector<std::uint8_t>(
                v5_ipv6_req.begin(), v5_ipv6_req.end());
            break;
          default:
            break;
        }
      // Set state machine to process connect request
      client::SOCKSHandler::EnterState(
          StubHandler::State::GetSOCKS5RequestVersion);
    }

  // Change default command
  req[1] = cmd;

  bool success;
  BOOST_CHECK_NO_THROW(
      success = client::SOCKSHandler::HandleData(req.data(), req.size()));
  return success;
}

bool SOCKSProxyFixture::StubHandler::CheckSOCKS5Auth(const AuthMethods auth)
{
  bool success;
  v5_greet_req[2] = auth;

  // Set state machine to process auth request
  client::SOCKSHandler::EnterState(State::GetSOCKSVersion);

  BOOST_CHECK_NO_THROW(
      success = client::SOCKSHandler::HandleData(
          v5_greet_req.data(), v5_greet_req.size()));

  return success;
}

BOOST_FIXTURE_TEST_SUITE(SOCKSProxyTests, SOCKSProxyFixture)

BOOST_AUTO_TEST_CASE(GoodSOCKS4Response)
{
  handler->CheckResponse(v4, StubHandler::ErrorTypes::SOCKS4Success);
}

BOOST_AUTO_TEST_CASE(FailSOCKS4Response)
{
  handler->CheckResponse(v4, StubHandler::ErrorTypes::SOCKS4Fail);
  handler->CheckResponse(v4, StubHandler::ErrorTypes::SOCKS4MissingIdent);
  handler->CheckResponse(v4, StubHandler::ErrorTypes::SOCKS4InvalidIdent);
}

BOOST_AUTO_TEST_CASE(GoodSOCKS5Response)
{
  handler->CheckResponse(v5, StubHandler::ErrorTypes::SOCKS5Success);
}

BOOST_AUTO_TEST_CASE(FailSOCKS5Response)
{
  handler->CheckResponse(v5, StubHandler::ErrorTypes::SOCKS5Fail);
  handler->CheckResponse(v5, StubHandler::ErrorTypes::SOCKS5RuleDenied);
  handler->CheckResponse(v5, StubHandler::ErrorTypes::SOCKS5NetworkUnreachable);
  handler->CheckResponse(v5, StubHandler::ErrorTypes::SOCKS5HostUnreachable);
  handler->CheckResponse(v5, StubHandler::ErrorTypes::SOCKS5ConnectionRefused);
  handler->CheckResponse(v5, StubHandler::ErrorTypes::SOCKS5Expired);
  handler->CheckResponse(v5, StubHandler::ErrorTypes::SOCKS5UnsupportedCommand);
  handler->CheckResponse(v5, StubHandler::ErrorTypes::SOCKS5UnsupportedAddress);
}

BOOST_AUTO_TEST_CASE(GoodSOCKS4aRequest)
{
  BOOST_CHECK(
      handler->CheckHandleData(v4, dns, StubHandler::CommandTypes::Connect));
}

BOOST_AUTO_TEST_CASE(GoodSOCKS5Request)
{
  BOOST_CHECK(
      handler->CheckHandleData(v5, dns, StubHandler::CommandTypes::Connect));
}

BOOST_AUTO_TEST_CASE(UnimplementedSOCKS4a)
{
  // TODO(oneiric): implement BIND command
  BOOST_CHECK(
      !handler->CheckHandleData(v4, dns, StubHandler::CommandTypes::Bind));
}

BOOST_AUTO_TEST_CASE(UnimplementedSOCKS5)
{
  // TODO(oneiric): implement BIND and UDP commands
  BOOST_CHECK(
      !handler->CheckHandleData(v5, dns, StubHandler::CommandTypes::Bind));
  BOOST_CHECK(
      !handler->CheckHandleData(v5, dns, StubHandler::CommandTypes::UDP));
}

BOOST_AUTO_TEST_CASE(UnsupportedSOCKS4)
{
  // SOCKS4 unsupported, no DNS option
  // IPv4 unsupported, cannot connect to raw IP in-net
  BOOST_CHECK(
      !handler->CheckHandleData(v4, ipv4, StubHandler::CommandTypes::Connect));
  BOOST_CHECK(
      !handler->CheckHandleData(v4, ipv4, StubHandler::CommandTypes::Bind));
}

BOOST_AUTO_TEST_CASE(UnsupportedSOCKS5)
{
  // IPv4 unsupported, cannot connect to raw IP in-net
  BOOST_CHECK(
      !handler->CheckHandleData(v5, ipv4, StubHandler::CommandTypes::Connect));
  BOOST_CHECK(
      !handler->CheckHandleData(v5, ipv4, StubHandler::CommandTypes::Bind));
  BOOST_CHECK(
      !handler->CheckHandleData(v5, ipv4, StubHandler::CommandTypes::UDP));

  // IPv6 unsupported, cannot connect to raw IP in-net
  BOOST_CHECK(
      !handler->CheckHandleData(v5, ipv6, StubHandler::CommandTypes::Connect));
  BOOST_CHECK(
      !handler->CheckHandleData(v5, ipv6, StubHandler::CommandTypes::Bind));
  BOOST_CHECK(
      !handler->CheckHandleData(v5, ipv6, StubHandler::CommandTypes::UDP));
}

BOOST_AUTO_TEST_CASE(GoodSOCKS5Auth)
{
  BOOST_CHECK(handler->CheckSOCKS5Auth(StubHandler::AuthMethods::None));
}

BOOST_AUTO_TEST_CASE(UnimplementedSOCKS5Auth)
{
  // TODO(oneiric): implement GSSAPI authentication
  BOOST_CHECK(!handler->CheckSOCKS5Auth(StubHandler::AuthMethods::GSSAPI));
  // TODO(oneiric): implement user-password authentication
  BOOST_CHECK(
      !handler->CheckSOCKS5Auth(StubHandler::AuthMethods::UserPassword));
}

BOOST_AUTO_TEST_CASE(InvalidSOCKS5Auth)
{
  BOOST_CHECK(!handler->CheckSOCKS5Auth(StubHandler::AuthMethods::Invalid));
}

BOOST_AUTO_TEST_SUITE_END()
