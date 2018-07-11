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

#include "client/api/i2p_control/data.h"
#include "client/util/json.h"

struct I2PControlSessionFixture
{
  // For convenience
  typedef client::I2PControlResponse Response;
  typedef client::I2PControlRequest Request;
  typedef Response::Method Method;
  typedef Response::MethodAuthenticate Auth;
  typedef Response::MethodEcho Echo;
  typedef Response::MethodI2PControl I2PControl;
  typedef Response::MethodRouterInfo RouterInfo;
  typedef Response::MethodRouterManager RouterManager;
  typedef Response::MethodNetworkSetting NetworkSetting;
  typedef Response::NetStatus NetStatus;

  // Values used in multiple fixtures
  const std::size_t m_ID{123};
  const std::size_t m_API{456};
  const std::string m_Password{"some_pass"};
  const std::string m_Token{"some_token"};
  const std::string m_Version{"2.0"};
  const std::string m_Address{"172.18.0.10"};
  const std::string m_Port{"15150"};

  // Response with error
  std::string m_ResponseWithError{
      "{\"id\":123,\"result\":{\"API\":456},\"jsonrpc\":\"2.0\","
      "\"error\":{\"code\":-32700,\"message\":\"Json parse error.\"}}"};
};

struct I2PControlAuthFixture : public I2PControlSessionFixture
{
  // Authenticate Request
  std::string m_AuthenticateRequest{
      "{\"id\":123,\"method\":\"Authenticate\",\"params\":{"
      "\"API\":456,"
      "\"Password\":\"some_pass\""
      "},\"jsonrpc\":\"2.0\"}"};

  // Authenticate Response
  std::string m_AuthenticateResponse{
      "{\"id\":123,\"result\":{"
      "\"API\":456,"
      "\"Token\":\"some_token\""
      "},\"jsonrpc\":\"2.0\"}"};
};

struct I2PControlEchoFixture : public I2PControlSessionFixture
{
  const std::string m_EchoMessage{"echo message"};

  // Echo Request
  std::string m_EchoRequest{
      "{\"id\":123,\"method\":\"Echo\",\"params\":{"
      "\"Token\":\"some_token\","
      "\"Echo\":\"echo message\""
      "},\"jsonrpc\":\"2.0\"}"};

  // Echo Response
  std::string m_EchoResponse{
      "{\"id\":123,\"result\":{"
      "\"Result\":\"echo message\""
      "},\"jsonrpc\":\"2.0\"}"};
};

struct I2PControlGetRateFixture : public I2PControlSessionFixture
{
  // GetRate Request
  std::string m_GetRateRequest{
      "{\"id\":123,\"method\":\"GetRate\",\"params\":{"
      "\"Token\":\"some_token\","
      "\"Stat\":\"stat_key\","
      "\"Period\":15,"
      "},\"jsonrpc\":\"2.0\"}"};

  // GetRate Response
  std::string m_I2PGetRateResponse{
      "{\"id\":123,\"result\":{"
      "\"Result\":1.15"
      "},\"jsonrpc\":\"2.0\"}"};
};
struct I2PControlControlFixture : public I2PControlSessionFixture
{
  // I2PControl Request
  std::string m_I2PControlRequest{
      "{\"id\":123,\"method\":\"I2PControl\",\"params\":{"
      "\"Token\":\"some_token\","
      "\"i2pcontrol.address\":\"172.18.0.10\","
      "\"i2pcontrol.password\":\"some_pass\","
      "\"i2pcontrol.port\":\"15150\""
      "},\"jsonrpc\":\"2.0\"}"};

  // I2PControl Response
  std::string m_I2PControlResponse{
      "{\"id\":123,\"result\":{\"i2pcontrol.address\":null,"
      "\"i2pcontrol.password\":null,"
      "\"i2pcontrol.port\":null,"
      "\"SettingsSaved\":true,"
      "\"RestartNeeded\":false"
      "},\"jsonrpc\":\"2.0\"}"};
};

struct I2PControlRouterInfoFixture : public I2PControlSessionFixture
{
  I2PControlRouterInfoFixture()
  {
    // Initialize json
    m_Json["3886212441"]["bytes"] = client::JsonObject(0);
    m_Json["3886212441"]["layout"] =
        client::JsonObject("me-->3886212441:nrkY-->");
  }

  const std::string m_Status{"some status"};
  const std::size_t m_Uptime{123456};
  const std::string m_KovriVersion{"some version"};
  const double m_BWIn1S{1.1};
  const double m_BWIn15S{15.15};
  const double m_BWOut1S{2.2};
  const double m_BWOut15S{25.25};
  Response::NetStatus m_NetStatus{NetStatus::Firewalled};
  const std::size_t m_Participants{5};
  const std::size_t m_ActivePeers{10};
  const std::size_t m_FastPeers{7};
  const std::size_t m_HighCapPeers{3};
  const std::size_t m_KnownPeers{50};
  const std::string m_DataPath{"/path/to/data/dir"};
  const std::size_t m_Floodfills{20};
  const std::size_t m_LeaseSets{30};
  const double m_TunnelsCreationSuccessRate{0.83};
  client::JsonObject m_Json;

  // RouterInfo Request
  std::string m_RouterInfoRequest{
      "{\"id\":123,\"method\":\"RouterInfo\",\"params\":{"
      "\"Token\":\"some_token\","
      "\"i2p.router.status\":null,"
      "\"i2p.router.uptime\":null,"
      "\"i2p.router.version\":null,"
      "\"i2p.router.net.bw.inbound.1s\":null,"
      "\"i2p.router.net.bw.inbound.15s\":null,"
      "\"i2p.router.net.bw.outbound.1s\":null,"
      "\"i2p.router.net.bw.outbound.15s\":null,"
      "\"i2p.router.net.status\":null,"
      "\"i2p.router.net.tunnels.participating\":null,"
      "\"i2p.router.netdb.activepeers\":null,"
      "\"i2p.router.netdb.fastpeers\":null,"
      "\"i2p.router.netdb.highcapacitypeers\":null,"
      "\"i2p.router.netdb.isreseeding\":null,"
      "\"i2p.router.netdb.knownpeers\":null,"
      "\"i2p.router.datapath\":null,"
      "\"i2p.router.netdb.floodfills\":null,"
      "\"i2p.router.netdb.leasesets\":null,"
      "\"i2p.router.net.tunnels.creationsuccessrate\":null,"
      "\"i2p.router.net.tunnels.inbound.list\":null,"
      "\"i2p.router.net.tunnels.outbound.list\":null"
      "},\"jsonrpc\":\"2.0\"}"};

  // RouterInfo Response
  std::string m_RouterInfoResponse{
      "{\"id\":123,\"result\":{"
      "\"i2p.router.status\":\"some status\","
      "\"i2p.router.uptime\":123456,"
      "\"i2p.router.version\":\"some version\","
      "\"i2p.router.net.bw.inbound.1s\":1.10,"
      "\"i2p.router.net.bw.inbound.15s\":15.15,"
      "\"i2p.router.net.bw.outbound.1s\":2.20,"
      "\"i2p.router.net.bw.outbound.15s\":25.25,"
      "\"i2p.router.net.status\":2,"
      "\"i2p.router.net.tunnels.participating\":5,"
      "\"i2p.router.netdb.activepeers\":10,"
      "\"i2p.router.netdb.fastpeers\":7,"
      "\"i2p.router.netdb.highcapacitypeers\":3,"
      "\"i2p.router.netdb.isreseeding\":false,"
      "\"i2p.router.netdb.knownpeers\":50,"
      "\"i2p.router.datapath\":\"/path/to/data/dir\","
      "\"i2p.router.netdb.floodfills\":20,"
      "\"i2p.router.netdb.leasesets\":30,"
      "\"i2p.router.net.tunnels.creationsuccessrate\":0.83,"
      "\"i2p.router.net.tunnels.inbound.list\":null,"
      "\"i2p.router.net.tunnels.outbound.list\":"
      "{\"3886212441\":{"
      "\"bytes\":\"0\","
      "\"layout\":\"me-->3886212441:nrkY-->\"}}"
      "},\"jsonrpc\":\"2.0\"}"};
};

struct I2PControlRouterManagerFixture : public I2PControlSessionFixture
{
  const std::string m_StatusUpdate{"update status"};
  // RouterManager Request
  std::string m_RouterManagerRequest{
      "{\"id\":123,\"method\":\"RouterManager\",\"params\":{"
      "\"Token\":\"some_token\","
      "\"FindUpdates\":null,"
      "\"Reseed\":null,"
      "\"Restart\":null,"
      "\"RestartGraceful\":null,"
      "\"Shutdown\":null,"
      "\"ShutdownGraceful\":null,"
      "\"Update\":null"
      "},\"jsonrpc\":\"2.0\"}"};

  // RouterManager Response
  std::string m_RouterManagerResponse{
      "{\"id\":123,\"result\":{"
      "\"FindUpdates\":false,"
      "\"Reseed\":null,"
      "\"Restart\":null,"
      "\"RestartGraceful\":null,"
      "\"Shutdown\":null,"
      "\"ShutdownGraceful\":null,"
      "\"Update\":\"update status\""
      "},\"jsonrpc\":\"2.0\"}"};
};

struct I2PControlNetworkSettingFixture : public I2PControlSessionFixture
{
  const std::string m_NTCPPort{"25250"};
  const std::string m_NTCPHostName{"ntcp hostname"};
  const std::string m_NTCPAutoIP{"ntcp auto ip"};
  const std::string m_SSUPort{"25251"};
  const std::string m_SSUHostName{"ssu hostname"};
  const std::string m_SSUAutoIP{"ssu auto ip"};
  const std::string m_UPnP{"upnp"};
  const std::string m_BWShare{"BW share"};
  const std::string m_BWIn{"10.10"};
  const std::string m_BWOut{"20.20"};
  const std::string m_LaptopMode{"laptop mode"};

  // NetworkSetting Request
  std::string m_NetworkSettingRequest{
      "{\"id\":123,\"method\":\"NetworkSetting\",\"params\":{"
      "\"Token\":\"some_token\","
      "\"i2p.router.net.ntcp.port\":\"25250\","
      "\"i2p.router.net.ntcp.hostname\":\"ntcp hostname\","
      "\"i2p.router.net.ntcp.autoip\":\"ntcp auto ip\","
      "\"i2p.router.net.ssu.port\":\"25251\","
      "\"i2p.router.net.ssu.hostname\":\"ssu hostname\","
      "\"i2p.router.net.ssu.autoip\":\"ssu auto ip\","
      "\"i2p.router.net.ssu.detectedip\":null,"
      "\"i2p.router.net.upnp\":\"upnp\","
      "\"i2p.router.net.bw.share\":\"BW share\","
      "\"i2p.router.net.bw.in\":\"10.10\","
      "\"i2p.router.net.bw.out\":\"20.20\","
      "\"i2p.router.net.laptopmode\":\"laptop mode\""
      "},\"jsonrpc\":\"2.0\"}"};

  // NetworkSetting Response
  std::string m_NetworkSettingResponse{
      "{\"id\":123,\"result\":{"
      "\"i2p.router.net.ntcp.port\":\"25250\","
      "\"i2p.router.net.ntcp.hostname\":\"ntcp hostname\","
      "\"i2p.router.net.ntcp.autoip\":\"ntcp auto ip\","
      "\"i2p.router.net.ssu.port\":\"25251\","
      "\"i2p.router.net.ssu.hostname\":\"ssu hostname\","
      "\"i2p.router.net.ssu.autoip\":\"ssu auto ip\","
      "\"i2p.router.net.ssu.detectedip\":\"172.18.0.10\","
      "\"i2p.router.net.upnp\":\"upnp\","
      "\"i2p.router.net.bw.share\":\"BW share\","
      "\"i2p.router.net.bw.in\":\"10.10\","
      "\"i2p.router.net.bw.out\":\"20.20\","
      "\"i2p.router.net.laptopmode\":\"laptop mode\","
      "\"SettingsSaved\":true,"
      "\"RestartNeeded\":false"
      "},\"jsonrpc\":\"2.0\"}"};
};

// Response with error
BOOST_FIXTURE_TEST_CASE(ReadResponseWithError, I2PControlSessionFixture)
{
  std::stringstream stream(m_ResponseWithError);
  Response response;
  // Parse
  BOOST_CHECK_NO_THROW(response.Parse(Method::Authenticate, stream));
  // Check params
  BOOST_CHECK(response.GetError() == Response::ErrorCode::ParseError);
}

BOOST_FIXTURE_TEST_SUITE(I2PControlAuthTest, I2PControlAuthFixture)
// Authenticate Request
BOOST_AUTO_TEST_CASE(WriteAuthenticateRequest)
{
  Request request;
  // Set common params
  request.SetID(m_ID);
  request.SetMethod(Method::Authenticate);
  // Set specific params
  request.SetParam(Auth::API, m_API);
  request.SetParam(Auth::Password, m_Password);
  // Check output
  BOOST_CHECK_EQUAL(request.ToJsonString(), m_AuthenticateRequest);
}

BOOST_AUTO_TEST_CASE(ReadAuthenticateRequest)
{
  Request request;
  std::stringstream stream(m_AuthenticateRequest);
  // Parse
  BOOST_CHECK_NO_THROW(request.Parse(stream));
  // Check params
  BOOST_CHECK_EQUAL(request.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(request.GetID()), m_ID);
  BOOST_CHECK_EQUAL(request.GetParam<std::size_t>(Auth::API), m_API);
  BOOST_CHECK_EQUAL(request.GetParam<std::string>(Auth::Password), m_Password);
}

// Authenticate Response
BOOST_AUTO_TEST_CASE(WriteAuthenticateResponse)
{
  client::I2PControlResponse response;
  response.SetMethod(Method::Authenticate);
  // Set common params
  response.SetID(m_ID);
  response.SetParam(Auth::API, m_API);
  response.SetParam(Auth::Token, m_Token);
  // Check output
  BOOST_CHECK_EQUAL(response.ToJsonString(), m_AuthenticateResponse);
}

BOOST_AUTO_TEST_CASE(ReadAuthenticateResponse)
{
  Response response;
  std::stringstream stream(m_AuthenticateResponse);
  // Parse
  BOOST_CHECK_NO_THROW(response.Parse(Method::Authenticate, stream));
  // Check params
  BOOST_CHECK_EQUAL(response.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(response.GetID()), m_ID);
  BOOST_CHECK_EQUAL(response.GetParam<std::size_t>(Auth::API), m_API);
  BOOST_CHECK_EQUAL(response.GetParam<std::string>(Auth::Token), m_Token);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(I2PControlEchoTest, I2PControlEchoFixture)
// Echo Request
BOOST_AUTO_TEST_CASE(WriteEchoRequest)
{
  Request request;
  // Set common params
  request.SetID(m_ID);
  request.SetMethod(Method::Echo);
  request.SetToken(m_Token);
  // Set specific params
  request.SetParam(Echo::Echo, m_EchoMessage);
  // Check output
  BOOST_CHECK_EQUAL(request.ToJsonString(), m_EchoRequest);
}

BOOST_AUTO_TEST_CASE(ReadEchoRequest)
{
  Request request;
  std::stringstream stream(m_EchoRequest);
  // Parse
  BOOST_CHECK_NO_THROW(request.Parse(stream));
  // Check params
  BOOST_CHECK_EQUAL(request.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(request.GetID()), m_ID);
  BOOST_CHECK_EQUAL(request.GetToken(), m_Token);
  BOOST_CHECK_EQUAL(request.GetParam<std::string>(Echo::Echo), m_EchoMessage);
}

// Echo Response
BOOST_AUTO_TEST_CASE(WriteEchoResponse)
{
  client::I2PControlResponse response;
  response.SetMethod(Method::Echo);
  // Set common params
  response.SetID(m_ID);
  // Set specific params
  response.SetParam(Echo::Result, m_EchoMessage);
  // Check output
  BOOST_CHECK_EQUAL(response.ToJsonString(), m_EchoResponse);
}

BOOST_AUTO_TEST_CASE(ReadEchoResponse)
{
  Response response;
  std::stringstream stream(m_EchoResponse);
  // Parse
  BOOST_CHECK_NO_THROW(response.Parse(Method::Echo, stream));
  // Check params
  BOOST_CHECK_EQUAL(response.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(response.GetID()), m_ID);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(Echo::Result), m_EchoMessage);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(I2PControlControlTest, I2PControlControlFixture)

// I2PControl Request
BOOST_AUTO_TEST_CASE(WriteI2PControlRequest)
{
  Request request;
  // Set common params
  request.SetID(m_ID);
  request.SetMethod(Method::I2PControl);
  request.SetToken(m_Token);
  // Set specific params
  request.SetParam(I2PControl::Address, m_Address);
  request.SetParam(I2PControl::Password, m_Password);
  request.SetParam(I2PControl::Port, m_Port);
  // Check output
  BOOST_CHECK_EQUAL(request.ToJsonString(), m_I2PControlRequest);
}

BOOST_AUTO_TEST_CASE(ReadI2PControlRequest)
{
  Request request;
  std::stringstream stream(m_I2PControlRequest);
  // Parse
  BOOST_CHECK_NO_THROW(request.Parse(stream));
  // Check params
  BOOST_CHECK_EQUAL(request.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(request.GetID()), m_ID);
  BOOST_CHECK_EQUAL(request.GetToken(), m_Token);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(I2PControl::Address), m_Address);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(I2PControl::Password), m_Password);
  BOOST_CHECK_EQUAL(request.GetParam<std::string>(I2PControl::Port), m_Port);
}

// I2PControl Response
BOOST_AUTO_TEST_CASE(WriteI2PControlResponse)
{
  client::I2PControlResponse response;
  response.SetID(m_ID);
  std::string empty;
  response.SetMethod(Method::I2PControl);
  // Set specific params
  response.SetParam(I2PControl::Address, empty);
  response.SetParam(I2PControl::Password, empty);
  response.SetParam(I2PControl::Port, empty);
  response.SetParam(I2PControl::SettingsSaved, true);
  response.SetParam(I2PControl::RestartNeeded, false);
  // Check Output
  BOOST_CHECK_EQUAL(response.ToJsonString(), m_I2PControlResponse);
}

BOOST_AUTO_TEST_CASE(ReadI2PControlResponse)
{
  Response response;
  std::stringstream stream(m_I2PControlResponse);
  // Parse
  BOOST_CHECK_NO_THROW(response.Parse(Method::I2PControl, stream));
  // Check params
  std::string empty;
  BOOST_CHECK_EQUAL(response.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(response.GetID()), m_ID);
  BOOST_CHECK_EQUAL(response.GetParam<std::string>(I2PControl::Address), empty);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(I2PControl::Password), empty);
  BOOST_CHECK_EQUAL(response.GetParam<std::string>(I2PControl::Port), empty);
  BOOST_CHECK_EQUAL(response.GetParam<bool>(I2PControl::SettingsSaved), true);
  BOOST_CHECK_EQUAL(response.GetParam<bool>(I2PControl::RestartNeeded), false);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(I2PControlRouterInfoTest, I2PControlRouterInfoFixture)

// RouterInfo Request
BOOST_AUTO_TEST_CASE(WriteRouterInfoRequest)
{
  Request request;
  // Set common params
  request.SetID(m_ID);
  request.SetMethod(Method::RouterInfo);
  request.SetToken(m_Token);
  // Set all specific params to null
  std::string empty;
  for (auto i(core::GetType(RouterInfo::Status));
       i <= core::GetType(RouterInfo::TunnelsOutList);
       i++)
    request.SetParam(i, empty);
  // Check output
  BOOST_CHECK_EQUAL(request.ToJsonString(), m_RouterInfoRequest);
}

BOOST_AUTO_TEST_CASE(ReadRouterInfoRequest)
{
  Request request;
  std::stringstream stream(m_RouterInfoRequest);
  // Parse
  BOOST_CHECK_NO_THROW(request.Parse(stream));
  // Check params
  BOOST_CHECK_EQUAL(request.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(request.GetID()), m_ID);
  BOOST_CHECK_EQUAL(request.GetToken(), m_Token);
  std::string empty;
  for (auto i(core::GetType(RouterInfo::Status));
       i <= core::GetType(RouterInfo::TunnelsOutList);
       i++)
    BOOST_CHECK_EQUAL(request.GetParam<std::string>(i), empty);
}

// RouterInfo Response
BOOST_AUTO_TEST_CASE(WriteRouterInfoResponse)
{
  client::I2PControlResponse response;
  response.SetID(m_ID);
  response.SetMethod(Method::RouterInfo);
  // Set specific params
  std::string empty;
  response.SetParam(RouterInfo::Status, m_Status);
  response.SetParam(RouterInfo::Uptime, m_Uptime);
  response.SetParam(RouterInfo::Version, m_KovriVersion);
  response.SetParam(RouterInfo::BWIn1S, m_BWIn1S);
  response.SetParam(RouterInfo::BWIn15S, m_BWIn15S);
  response.SetParam(RouterInfo::BWOut1S, m_BWOut1S);
  response.SetParam(RouterInfo::BWOut15S, m_BWOut15S);
  response.SetParam(RouterInfo::NetStatus, std::size_t(m_NetStatus));
  response.SetParam(RouterInfo::TunnelsParticipating, m_Participants);
  response.SetParam(RouterInfo::ActivePeers, m_ActivePeers);
  response.SetParam(RouterInfo::FastPeers, m_FastPeers);
  response.SetParam(RouterInfo::HighCapacityPeers, m_HighCapPeers);
  response.SetParam(RouterInfo::IsReseeding, false);
  response.SetParam(RouterInfo::KnownPeers, m_KnownPeers);
  response.SetParam(RouterInfo::DataPath, m_DataPath);
  response.SetParam(RouterInfo::Floodfills, m_Floodfills);
  response.SetParam(RouterInfo::LeaseSets, m_LeaseSets);
  response.SetParam(
      RouterInfo::TunnelsCreationSuccessRate, m_TunnelsCreationSuccessRate);
  response.SetParam(RouterInfo::TunnelsInList, client::JsonObject());
  response.SetParam(RouterInfo::TunnelsOutList, m_Json);
  // Check output
  BOOST_CHECK_EQUAL(response.ToJsonString(), m_RouterInfoResponse);
}

BOOST_AUTO_TEST_CASE(ReadRouterInfoResponse)
{
  Response response;
  std::stringstream stream(m_RouterInfoResponse);
  // Parse
  BOOST_CHECK_NO_THROW(response.Parse(Method::RouterInfo, stream));
  // Check common params
  std::string empty;
  BOOST_CHECK_EQUAL(response.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(response.GetID()), m_ID);
  // Check specific params
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(RouterInfo::Status), m_Status);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::size_t>(RouterInfo::Uptime), m_Uptime);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(RouterInfo::Version), m_KovriVersion);
  BOOST_CHECK_EQUAL(response.GetParam<double>(RouterInfo::BWIn1S), m_BWIn1S);
  BOOST_CHECK_EQUAL(response.GetParam<double>(RouterInfo::BWIn15S), m_BWIn15S);
  BOOST_CHECK_EQUAL(response.GetParam<double>(RouterInfo::BWOut1S), m_BWOut1S);
  BOOST_CHECK_EQUAL(
      response.GetParam<double>(RouterInfo::BWOut15S), m_BWOut15S);
  BOOST_CHECK(
      response.NetStatusFromLong(
          response.GetParam<std::size_t>(RouterInfo::NetStatus))
      == m_NetStatus);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::size_t>(RouterInfo::TunnelsParticipating),
      m_Participants);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::size_t>(RouterInfo::ActivePeers), m_ActivePeers);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::size_t>(RouterInfo::FastPeers), m_FastPeers);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::size_t>(RouterInfo::HighCapacityPeers),
      m_HighCapPeers);
  BOOST_CHECK_EQUAL(response.GetParam<bool>(RouterInfo::IsReseeding), false);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::size_t>(RouterInfo::KnownPeers), m_KnownPeers);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(RouterInfo::DataPath), m_DataPath);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::size_t>(RouterInfo::Floodfills), m_Floodfills);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::size_t>(RouterInfo::LeaseSets), m_LeaseSets);
  BOOST_CHECK_EQUAL(
      response.GetParam<double>(RouterInfo::TunnelsCreationSuccessRate),
      m_TunnelsCreationSuccessRate);
  BOOST_CHECK_EQUAL(
      response.GetParam<client::JsonObject>(RouterInfo::TunnelsInList),
      client::JsonObject());
  BOOST_CHECK_EQUAL(
      response.GetParam<client::JsonObject>(RouterInfo::TunnelsOutList),
      m_Json);
}
BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(
    I2PControlRouterManagerTest,
    I2PControlRouterManagerFixture)

// RouterManager Request
BOOST_AUTO_TEST_CASE(WriteRouterManagerRequest)
{
  Request request;
  // Set common params
  request.SetID(m_ID);
  request.SetMethod(Method::RouterManager);
  request.SetToken(m_Token);
  // Set specific params
  std::string empty;
  request.SetParam(RouterManager::FindUpdates, empty);
  request.SetParam(RouterManager::Reseed, empty);
  request.SetParam(RouterManager::Restart, empty);
  request.SetParam(RouterManager::RestartGraceful, empty);
  request.SetParam(RouterManager::Shutdown, empty);
  request.SetParam(RouterManager::ShutdownGraceful, empty);
  request.SetParam(RouterManager::Update, empty);
  // Check output
  BOOST_CHECK_EQUAL(request.ToJsonString(), m_RouterManagerRequest);
}

BOOST_AUTO_TEST_CASE(ReadRouterManagerRequest)
{
  Request request;
  std::stringstream stream(m_RouterManagerRequest);
  // Parse
  BOOST_CHECK_NO_THROW(request.Parse(stream));
  // Check params
  std::string empty;
  BOOST_CHECK_EQUAL(request.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(request.GetToken(), m_Token);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(RouterManager::Shutdown), empty);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(RouterManager::ShutdownGraceful), empty);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(RouterManager::Reseed), empty);
}

// RouterManager Response
BOOST_AUTO_TEST_CASE(WriteRouterManagerResponse)
{
  client::I2PControlResponse response;
  response.SetID(m_ID);
  std::string empty;
  response.SetMethod(Method::RouterManager);
  // Set specific params
  response.SetParam(RouterManager::FindUpdates, false);
  response.SetParam(RouterManager::Reseed, empty);
  response.SetParam(RouterManager::Restart, empty);
  response.SetParam(RouterManager::RestartGraceful, empty);
  response.SetParam(RouterManager::Shutdown, empty);
  response.SetParam(RouterManager::ShutdownGraceful, empty);
  response.SetParam(RouterManager::Update, m_StatusUpdate);
  // Check output
  BOOST_CHECK_EQUAL(response.ToJsonString(), m_RouterManagerResponse);
}

BOOST_AUTO_TEST_CASE(ReadRouterManagerResponse)
{
  Response response;
  std::stringstream stream(m_RouterManagerResponse);
  // Parse
  BOOST_CHECK_NO_THROW(response.Parse(Method::RouterManager, stream));
  // Check params
  std::string empty;
  BOOST_CHECK_EQUAL(response.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(response.GetID()), m_ID);
  BOOST_CHECK_EQUAL(response.GetParam<bool>(RouterManager::FindUpdates), false);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(RouterManager::Reseed), empty);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(RouterManager::Restart), empty);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(RouterManager::RestartGraceful), empty);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(RouterManager::Shutdown), empty);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(RouterManager::ShutdownGraceful), empty);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(RouterManager::Update), m_StatusUpdate);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_FIXTURE_TEST_SUITE(
    I2PControlNetworkSettingTest,
    I2PControlNetworkSettingFixture)

// NetworkSetting Request
BOOST_AUTO_TEST_CASE(WriteNetworkSettingRequest)
{
  Request request;
  // Set common params
  request.SetID(m_ID);
  request.SetMethod(Method::NetworkSetting);
  request.SetToken(m_Token);
  // Set specific params
  request.SetParam(NetworkSetting::NTCPPort, m_NTCPPort);
  request.SetParam(NetworkSetting::NTCPHostName, m_NTCPHostName);
  request.SetParam(NetworkSetting::NTCPAutoIP, m_NTCPAutoIP);
  request.SetParam(NetworkSetting::SSUPort, m_SSUPort);
  request.SetParam(NetworkSetting::SSUHostName, m_SSUHostName);
  request.SetParam(NetworkSetting::SSUAutoIP, m_SSUAutoIP);
  request.SetParam(NetworkSetting::SSUDetectedIP, std::string());
  request.SetParam(NetworkSetting::UPnP, m_UPnP);
  request.SetParam(NetworkSetting::BWShare, m_BWShare);
  request.SetParam(NetworkSetting::BWIn, m_BWIn);
  request.SetParam(NetworkSetting::BWOut, m_BWOut);
  request.SetParam(NetworkSetting::LaptopMode, m_LaptopMode);
  // Check output
  BOOST_CHECK_EQUAL(request.ToJsonString(), m_NetworkSettingRequest);
}

BOOST_AUTO_TEST_CASE(ReadNetworkSettingRequest)
{
  Request request;
  std::stringstream stream(m_NetworkSettingRequest);
  // Parse
  BOOST_CHECK_NO_THROW(request.Parse(stream));
  // Check common params
  std::string empty;
  BOOST_CHECK_EQUAL(request.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(request.GetID()), m_ID);
  BOOST_CHECK_EQUAL(request.GetToken(), m_Token);
  // Check Specific params
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::NTCPPort), m_NTCPPort);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::NTCPHostName),
      m_NTCPHostName);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::NTCPAutoIP), m_NTCPAutoIP);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::SSUPort), m_SSUPort);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::SSUHostName),
      m_SSUHostName);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::SSUAutoIP), m_SSUAutoIP);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::SSUDetectedIP),
      std::string());
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::UPnP), m_UPnP);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::BWShare), m_BWShare);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::BWIn), m_BWIn);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::BWOut), m_BWOut);
  BOOST_CHECK_EQUAL(
      request.GetParam<std::string>(NetworkSetting::LaptopMode), m_LaptopMode);
}

// NetworkSetting Response
BOOST_AUTO_TEST_CASE(WriteNetworkSettingResponse)
{
  client::I2PControlResponse response;
  response.SetID(m_ID);
  response.SetMethod(Method::NetworkSetting);
  // Set specific params
  response.SetParam(NetworkSetting::NTCPPort, m_NTCPPort);
  response.SetParam(NetworkSetting::NTCPHostName, m_NTCPHostName);
  response.SetParam(NetworkSetting::NTCPAutoIP, m_NTCPAutoIP);
  response.SetParam(NetworkSetting::SSUPort, m_SSUPort);
  response.SetParam(NetworkSetting::SSUHostName, m_SSUHostName);
  response.SetParam(NetworkSetting::SSUAutoIP, m_SSUAutoIP);
  response.SetParam(NetworkSetting::SSUDetectedIP, m_Address);
  response.SetParam(NetworkSetting::UPnP, m_UPnP);
  response.SetParam(NetworkSetting::BWShare, m_BWShare);
  response.SetParam(NetworkSetting::BWIn, m_BWIn);
  response.SetParam(NetworkSetting::BWOut, m_BWOut);
  response.SetParam(NetworkSetting::LaptopMode, m_LaptopMode);
  response.SetParam(NetworkSetting::SettingsSaved, true);
  response.SetParam(NetworkSetting::RestartNeeded, false);
  // Check output
  BOOST_CHECK_EQUAL(response.ToJsonString(), m_NetworkSettingResponse);
}

BOOST_AUTO_TEST_CASE(ReadNetworkSettingResponse)
{
  Response response;
  std::stringstream stream(m_NetworkSettingResponse);
  // Parse
  BOOST_CHECK_NO_THROW(response.Parse(Method::NetworkSetting, stream));
  // Check common params
  BOOST_CHECK_EQUAL(response.GetVersion(), m_Version);
  BOOST_CHECK_EQUAL(boost::get<decltype(m_ID)>(response.GetID()), m_ID);
  // Check specific params
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::NTCPPort), m_NTCPPort);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::NTCPHostName),
      m_NTCPHostName);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::NTCPAutoIP), m_NTCPAutoIP);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::SSUPort), m_SSUPort);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::SSUHostName),
      m_SSUHostName);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::SSUAutoIP), m_SSUAutoIP);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::SSUDetectedIP), m_Address);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::UPnP), m_UPnP);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::BWShare), m_BWShare);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::BWIn), m_BWIn);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::BWOut), m_BWOut);
  BOOST_CHECK_EQUAL(
      response.GetParam<std::string>(NetworkSetting::LaptopMode), m_LaptopMode);
  BOOST_CHECK_EQUAL(
      response.GetParam<bool>(NetworkSetting::SettingsSaved), true);
  BOOST_CHECK_EQUAL(
      response.GetParam<bool>(NetworkSetting::RestartNeeded), false);
}

BOOST_AUTO_TEST_SUITE_END()
