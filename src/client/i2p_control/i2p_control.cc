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

#include "i2p_control.h"

#include <boost/property_tree/json_parser.hpp>

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <iomanip>
#include <sstream>
#include <string>

#include "client/client_context.h"
#include "core/net_db.h"
#include "core/router_context.h"
#include "core/version.h"
#include "crypto/rand.h"
#include "transport/transports.h"
#include "tunnel/tunnel.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace client {
namespace i2pcontrol {

JsonObject::JsonObject(
    const std::string& value)
    : m_Children(),
      m_Value("\"" + value + "\"") {}

JsonObject::JsonObject(
    int value)
    : m_Children(),
      m_Value(std::to_string(value)) {}

JsonObject::JsonObject(
    double v)
    : m_Children(),
      m_Value() {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << v;
        m_Value = oss.str();
}

JsonObject& JsonObject::operator[](
    const std::string& key) {
  return m_Children[key];
}

std::string JsonObject::ToString() const {
  if (m_Children.empty())
    return m_Value;
  std::ostringstream oss;
  oss << '{';
  for (auto it = m_Children.begin(); it != m_Children.end(); ++it) {
    if (it != m_Children.begin())
      oss << ',';
    oss << '"' << it->first << "\":" << it->second.ToString();
  }
  oss << '}';
  return oss.str();
}

JsonObject TunnelToJsonObject(
    i2p::tunnel::Tunnel* tunnel) {
  JsonObject obj;
  std::stringstream ss;
  tunnel->GetTunnelConfig()->Print(ss);  // TODO(unassigned): use a JsonObject
  obj["layout"] = JsonObject(ss.str());
  const auto state = tunnel->GetState();
  if (state == i2p::tunnel::e_TunnelStateFailed)
     obj["state"] = JsonObject("failed");
  else if (state == i2p::tunnel::e_TunnelStateExpiring)
     obj["state"] = JsonObject("expiring");
  return obj;
}

I2PControlSession::Response::Response(
    const std::string& version)
    : m_ID(),
      m_Version(version),
      m_Error(ErrorCode::e_None),
      m_Params() {}

std::string I2PControlSession::Response::ToJsonString() const {
  std::ostringstream oss;
  oss << "{\"id\":" << m_ID << ",\"result\":{";
  for (auto it = m_Params.begin(); it != m_Params.end(); ++it) {
    if (it != m_Params.begin())
      oss << ',';
    oss << '"' << it->first << "\":" << it->second;
  }
  oss << "},\"jsonrpc\":\"" << m_Version << '"';
  if (m_Error != ErrorCode::e_None)
    oss << ",\"error\":{\"code\":" << -static_cast<int>(m_Error)
      << ",\"message\":\"" << GetErrorMsg() << "\"" << "}";
  oss << "}";
  return oss.str();
}

std::string I2PControlSession::Response::GetErrorMsg() const {
  switch (m_Error) {
    case ErrorCode::e_MethodNotFound:
      return "Method not found.";
    case ErrorCode::e_InvalidParameters:
      return "Invalid parameters.";
    case ErrorCode::e_InvalidRequest:
      return "Invalid request.";
    case ErrorCode::e_ParseError:
      return "Json parse error.";
    case ErrorCode::e_InvalidPassword:
      return "Invalid password.";
    case ErrorCode::e_NoToken:
      return "No authentication token given.";
    case ErrorCode::e_NonexistentToken:
      return "Nonexistent authentication token given.";
    case ErrorCode::e_ExpiredToken:
      return "Expired authentication token given.";
    case ErrorCode::e_UnspecifiedVersion:
      return "Version not specified.";
    case ErrorCode::e_UnsupportedVersion:
      return "Version not supported.";
    default:
      return "";
  }
}

void I2PControlSession::Response::SetParam(
    const std::string& param,
    const std::string& value) {
  m_Params[param] = value.empty() ?
    "null" :
    "\"" + value + "\"";
}

void I2PControlSession::Response::SetParam(
    const std::string& param,
    int value) {
  m_Params[param] = std::to_string(value);
}

void I2PControlSession::Response::SetParam(
    const std::string& param,
    double value) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(2) << value;
  m_Params[param] = oss.str();
}

void I2PControlSession::Response::SetParam(
    const std::string& param,
    const JsonObject& value) {
  m_Params[param] = value.ToString();
}

void I2PControlSession::Response::SetError(
    ErrorCode code) {
  m_Error = code;
}

void I2PControlSession::Response::SetID(
    const std::string& id) {
  m_ID = id;
}

I2PControlSession::I2PControlSession(
  boost::asio::io_service& ios,
  const std::string& pass)
    : m_Password(pass),
      m_Tokens(),
      m_TokensMutex(),
      m_Service(ios),
      m_ShutdownTimer(ios),
      m_ExpireTokensTimer(ios) {

  namespace constants = i2p::client::i2pcontrol::constants;

  // Method handlers
  m_MethodHandlers[constants::METHOD_AUTHENTICATE] =
    &I2PControlSession::HandleAuthenticate;

  m_MethodHandlers[constants::METHOD_ECHO] =
    &I2PControlSession::HandleEcho;

  m_MethodHandlers[constants::METHOD_I2PCONTROL] =
    &I2PControlSession::HandleI2PControl;

  m_MethodHandlers[constants::METHOD_ROUTER_INFO] =
    &I2PControlSession::HandleRouterInfo;

  m_MethodHandlers[constants::METHOD_ROUTER_MANAGER] =
    &I2PControlSession::HandleRouterManager;

  m_MethodHandlers[constants::METHOD_NETWORK_SETTING] =
    &I2PControlSession::HandleNetworkSetting;

  // RouterInfo handlers
  m_RouterInfoHandlers[constants::ROUTER_INFO_UPTIME] =
    &I2PControlSession::HandleUptime;

  m_RouterInfoHandlers[constants::ROUTER_INFO_VERSION] =
    &I2PControlSession::HandleVersion;

  m_RouterInfoHandlers[constants::ROUTER_INFO_STATUS] =
    &I2PControlSession::HandleStatus;

  m_RouterInfoHandlers[constants::ROUTER_INFO_DATAPATH] =
    &I2PControlSession::HandleDatapath;

  m_RouterInfoHandlers[constants::ROUTER_INFO_NETDB_KNOWNPEERS] =
    &I2PControlSession::HandleNetDbKnownPeers;

  m_RouterInfoHandlers[constants::ROUTER_INFO_NETDB_ACTIVEPEERS] =
    &I2PControlSession::HandleNetDbActivePeers;

  m_RouterInfoHandlers[constants::ROUTER_INFO_NETDB_LEASESETS] =
    &I2PControlSession::HandleNetDbLeaseSets;

  m_RouterInfoHandlers[constants::ROUTER_INFO_NETDB_FLOODFILLS] =
    &I2PControlSession::HandleNetDbFloodfills;

  m_RouterInfoHandlers[constants::ROUTER_INFO_NET_STATUS] =
    &I2PControlSession::HandleNetStatus;

  m_RouterInfoHandlers[constants::ROUTER_INFO_TUNNELS_PARTICIPATING] =
    &I2PControlSession::HandleTunnelsParticipating;

  m_RouterInfoHandlers[constants::ROUTER_INFO_TUNNELS_CREATION_SUCCESS] =
    &I2PControlSession::HandleTunnelsCreationSuccess;

  m_RouterInfoHandlers[constants::ROUTER_INFO_TUNNELS_IN_LIST] =
    &I2PControlSession::HandleTunnelsInList;

  m_RouterInfoHandlers[constants::ROUTER_INFO_TUNNELS_OUT_LIST] =
    &I2PControlSession::HandleTunnelsOutList;

  m_RouterInfoHandlers[constants::ROUTER_INFO_BW_IB_1S] =
    &I2PControlSession::HandleInBandwidth1S;

  m_RouterInfoHandlers[constants::ROUTER_INFO_BW_OB_1S] =
    &I2PControlSession::HandleOutBandwidth1S;

  // RouterManager handlers
  m_RouterManagerHandlers[constants::ROUTER_MANAGER_SHUTDOWN] =
    &I2PControlSession::HandleShutdown;

  m_RouterManagerHandlers[constants::ROUTER_MANAGER_SHUTDOWN_GRACEFUL] =
    &I2PControlSession::HandleShutdownGraceful;

  m_RouterManagerHandlers[constants::ROUTER_MANAGER_RESEED] =
    &I2PControlSession::HandleReseed;
}

void I2PControlSession::Start() {
  StartExpireTokensJob();
}

void I2PControlSession::Stop() {
  boost::system::error_code e;  // Make sure this doesn't throw
  m_ShutdownTimer.cancel(e);
  m_ExpireTokensTimer.cancel(e);
}

I2PControlSession::Response I2PControlSession::HandleRequest(
    std::stringstream& request) {
  boost::property_tree::ptree pt;
  boost::property_tree::read_json(request, pt);
  Response response;
  try {
    response.SetID(pt.get<std::string>(constants::PROPERTY_ID));
    std::string method = pt.get<std::string>(constants::PROPERTY_METHOD);
    auto it = m_MethodHandlers.find(method);
    if (it == m_MethodHandlers.end()) {  // Not found
      LogPrint(eLogWarn,
          "I2PControlSession: unknown I2PControl method ", method);
      response.SetError(ErrorCode::e_MethodNotFound);
      return response;
    }
    ptree params = pt.get_child(constants::PROPERTY_PARAMS);
    if (method != constants::METHOD_AUTHENTICATE &&
        !Authenticate(params, response)) {
      LogPrint(eLogWarn,
          "I2PControlSession: invalid token presented");
      return response;
    }
    // Call the appropriate handler
    (this->*(it->second))(params, response);
  } catch (const boost::property_tree::ptree_error&) {
    response.SetError(ErrorCode::e_ParseError);
  } catch (...) {
    response.SetError(ErrorCode::e_InternalError);
  }
  return response;
}

bool I2PControlSession::Authenticate(
    const ptree& pt,
    Response& response) {
  try {
    std::string token = pt.get<std::string>(constants::PARAM_TOKEN);
    std::lock_guard<std::mutex> lock(m_TokensMutex);
    auto it = m_Tokens.find(token);
    if (it == m_Tokens.end()) {
      response.SetError(ErrorCode::e_NonexistentToken);
      return false;
    } else if (util::GetSecondsSinceEpoch() - it->second >
        constants::TOKEN_LIFETIME) {
      response.SetError(ErrorCode::e_ExpiredToken);
      return false;
    }
  } catch (const boost::property_tree::ptree_error&) {
    response.SetError(ErrorCode::e_NoToken);
    return false;
  }
  return true;
}

std::string I2PControlSession::GenerateToken() const {
  // Generate random data for token
  std::array<std::uint8_t, constants::TOKEN_SIZE> rand = {};
  i2p::crypto::RandBytes(rand.data(), constants::TOKEN_SIZE);
  // Create base16 token from random data
  std::stringstream token;
  for (std::size_t i(0); i < rand.size(); i++)
    token << std::hex << std::setfill('0') << std::setw(2)
    << std::uppercase << static_cast<std::size_t>(rand.at(i));
  // Return string
  return token.str();
}

void I2PControlSession::HandleAuthenticate(
    const ptree& pt,
    Response& response) {
  const int api = pt.get<int>(
      constants::PARAM_API);
  const std::string given_pass = pt.get<std::string>(
      constants::PARAM_PASSWORD);
  LogPrint(eLogDebug,
      "I2PControlSession: Authenticate API = ", api,
      " Password = ", given_pass);
  if (given_pass != m_Password) {
    LogPrint(eLogError,
        "I2PControlSession: invalid password ",
        given_pass, ", expected ", m_Password);
    response.SetError(ErrorCode::e_InvalidPassword);
    return;
  }
  const std::string token = GenerateToken();
  response.SetParam(constants::PARAM_API, api);
  response.SetParam(constants::PARAM_TOKEN, token);
  std::lock_guard<std::mutex> lock(m_TokensMutex);
  m_Tokens.insert(
      std::make_pair(
        token,
        util::GetSecondsSinceEpoch()));
}

void I2PControlSession::HandleEcho(
    const ptree& pt,
    Response& response) {
  const std::string echo = pt.get<std::string>(constants::PARAM_ECHO);
  LogPrint(eLogDebug, "I2PControlSession: Echo = ", echo);
  response.SetParam(constants::PARAM_RESULT, echo);
}

void I2PControlSession::HandleI2PControl(
    const ptree&,
    Response&) {
  // TODO(unassigned): implement
  LogPrint(eLogDebug, "I2PControlSession: I2PControl");
}

void I2PControlSession::HandleRouterInfo(
    const ptree& pt,
    Response& response) {
  LogPrint(eLogDebug, "I2PControlSession: HandleRouterInfo()");
  for (const auto& pair : pt) {
    if (pair.first == constants::PARAM_TOKEN)
      continue;
    LogPrint(eLogDebug, "I2PControlSession: ", pair.first);
    auto it = m_RouterInfoHandlers.find(pair.first);
    if (it != m_RouterInfoHandlers.end()) {
      (this->*(it->second))(response);
    } else {
      LogPrint(eLogError,
          "I2PControlSession: HandleRouterInfo() unknown request ",
          pair.first);
      response.SetError(ErrorCode::e_InvalidRequest);
    }
  }
}

void I2PControlSession::HandleRouterManager(
    const ptree& pt,
    Response& response) {
  LogPrint(eLogDebug, "I2PControlSession: HandleRouterManager()");
  for (const auto& pair : pt) {
    if (pair.first == constants::PARAM_TOKEN)
      continue;
    LogPrint(eLogDebug, pair.first);
    auto it = m_RouterManagerHandlers.find(pair.first);
    if (it != m_RouterManagerHandlers.end()) {
      (this->*(it->second))(response);
    } else {
      LogPrint(eLogError,
          "I2PControlSession: HandleRouterManager() unknown request ",
          pair.first);
      response.SetError(ErrorCode::e_InvalidRequest);
    }
  }
}

void I2PControlSession::HandleNetworkSetting(
    const ptree&,
    Response&) {
  // TODO(unassigned): implement
}

void I2PControlSession::HandleUptime(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_UPTIME,
      static_cast<int>(i2p::context.GetUptime())*1000);
}

void I2PControlSession::HandleVersion(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_VERSION,
      KOVRI_VERSION);
}

void I2PControlSession::HandleStatus(
    Response& response) {
  // TODO(unassigned): implement
  response.SetParam(
      constants::ROUTER_INFO_STATUS,
      "???");
}

void I2PControlSession::HandleDatapath(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_DATAPATH,
      i2p::context.GetDataPath().string());
}

void I2PControlSession::HandleNetDbKnownPeers(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_NETDB_KNOWNPEERS,
      i2p::data::netdb.GetNumRouters());
}

void I2PControlSession::HandleNetDbActivePeers(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_NETDB_ACTIVEPEERS,
      static_cast<int>(i2p::transport::transports.GetPeers().size()));
}

void I2PControlSession::HandleNetDbFloodfills(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_NETDB_FLOODFILLS,
      static_cast<int>(i2p::data::netdb.GetNumFloodfills()));
}

void I2PControlSession::HandleNetDbLeaseSets(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_NETDB_LEASESETS,
      static_cast<int>(i2p::data::netdb.GetNumLeaseSets()));
}

void I2PControlSession::HandleNetStatus(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_NET_STATUS,
      static_cast<int>(i2p::context.GetStatus()));
}

void I2PControlSession::HandleTunnelsParticipating(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_TUNNELS_PARTICIPATING,
      static_cast<int>(i2p::tunnel::tunnels.GetTransitTunnels().size()));
}

void I2PControlSession::HandleTunnelsCreationSuccess(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_TUNNELS_CREATION_SUCCESS,
      i2p::tunnel::tunnels.GetTunnelCreationSuccessRate());
}

void I2PControlSession::HandleTunnelsInList(
    Response& response) {
  JsonObject list;
  for (auto pair : i2p::tunnel::tunnels.GetInboundTunnels()) {
    const std::string id = std::to_string(pair.first);
    list[id] = TunnelToJsonObject(pair.second.get());
    list[id]["bytes"] = JsonObject(
      static_cast<int>(pair.second->GetNumReceivedBytes()));
  }
  response.SetParam(
      constants::ROUTER_INFO_TUNNELS_IN_LIST,
      list);
}

void I2PControlSession::HandleTunnelsOutList(
    Response& response) {
  JsonObject list;
  for (auto tunnel : i2p::tunnel::tunnels.GetOutboundTunnels()) {
    const std::string id = std::to_string(
        tunnel->GetTunnelID());
    list[id] = TunnelToJsonObject(tunnel.get());
    list[id]["bytes"] = JsonObject(
        static_cast<int>(tunnel->GetNumSentBytes()));
  }
  response.SetParam(
      constants::ROUTER_INFO_TUNNELS_OUT_LIST,
      list);
}

void I2PControlSession::HandleInBandwidth1S(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_BW_IB_1S,
      static_cast<double>(i2p::transport::transports.GetInBandwidth()));
}

void I2PControlSession::HandleOutBandwidth1S(
    Response& response) {
  response.SetParam(
      constants::ROUTER_INFO_BW_OB_1S,
      static_cast<double>(i2p::transport::transports.GetOutBandwidth()));
}

void I2PControlSession::HandleShutdown(
    Response& response) {
  LogPrint(eLogInfo, "I2PControlSession: shutdown requested");
  response.SetParam(constants::ROUTER_MANAGER_SHUTDOWN, "");
  // 1 second to make sure response has been sent
  m_ShutdownTimer.expires_from_now(
      boost::posix_time::seconds(1));
  m_ShutdownTimer.async_wait(
      [this](
        const boost::system::error_code&) {
      std::lock_guard<std::mutex> lock(m_ShutdownMutex);
      i2p::client::context.RequestShutdown();
      });
}

void I2PControlSession::HandleShutdownGraceful(
    Response& response) {
  // Stop accepting tunnels
  i2p::context.SetAcceptsTunnels(false);
  // Get tunnel expiry time
  int timeout = i2p::tunnel::tunnels.GetTransitTunnelsExpirationTimeout();
  LogPrint(eLogInfo,
      "I2PControlSession: graceful shutdown requested."
      "Will shutdown after ", timeout, " seconds");
  // Initiate graceful shutdown
  response.SetParam(
      constants::ROUTER_MANAGER_SHUTDOWN_GRACEFUL,
      "");
  m_ShutdownTimer.expires_from_now(
      boost::posix_time::seconds(
        timeout + 1));
  m_ShutdownTimer.async_wait(
      [this](
        const boost::system::error_code&) {
      std::lock_guard<std::mutex> lock(m_ShutdownMutex);
      i2p::client::context.RequestShutdown();
      });
}

void I2PControlSession::HandleReseed(
    Response& response) {
  LogPrint(eLogInfo, "I2PControlSession: reseed requested");
  response.SetParam(
      constants::ROUTER_MANAGER_SHUTDOWN,
      "");
  i2p::data::netdb.Reseed();
}

void I2PControlSession::ExpireTokens(
    const boost::system::error_code& error) {
  if (error == boost::asio::error::operation_aborted)
    return;  // Do not restart timer, shutting down
  StartExpireTokensJob();
  LogPrint(eLogDebug, "I2PControlSession: expiring tokens");
  const uint64_t now = util::GetSecondsSinceEpoch();
  std::lock_guard<std::mutex> lock(m_TokensMutex);
  for (auto it = m_Tokens.begin(); it != m_Tokens.end(); ) {
    if (now - it->second > constants::TOKEN_LIFETIME)
      it = m_Tokens.erase(it);
    else
      ++it;
  }
}

void I2PControlSession::StartExpireTokensJob() {
  m_ExpireTokensTimer.expires_from_now(
      boost::posix_time::seconds(
        constants::TOKEN_LIFETIME));
  m_ExpireTokensTimer.async_wait(
      std::bind(
        &I2PControlSession::ExpireTokens,
        shared_from_this(),
        std::placeholders::_1));
}

}  // namespace i2pcontrol
}  // namespace client
}  // namespace i2p
