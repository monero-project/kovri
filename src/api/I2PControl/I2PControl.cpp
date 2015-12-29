/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

#include <boost/property_tree/json_parser.hpp>

#include <iomanip>
#include <sstream>
#include <string>

#include "I2PControl.h"
#include "NetworkDatabase.h"
#include "client/Daemon.h"
#include "core/Version.h"
#include "transport/Transports.h"
#include "tunnel/Tunnel.h"
#include "util/Log.h"
#include "util/Timestamp.h"

namespace i2p {
namespace client {
namespace i2pcontrol {

JsonObject::JsonObject(const std::string& value)
    : children(),
      value("\"" + value + "\"") {}

JsonObject::JsonObject(int value)
    : children(),
      value(std::to_string(value)) {}

JsonObject::JsonObject(double v)
    : children(),
      value() {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(2) << v;
        value = oss.str();
}

JsonObject& JsonObject::operator[](const std::string& key) {
  return children[key];
}

std::string JsonObject::toString() const {
  if (children.empty())
    return value;
  std::ostringstream oss;
  oss << '{';
  for (auto it = children.begin(); it != children.end(); ++it) {
    if (it != children.begin())
      oss << ',';
    oss << '"' << it->first << "\":" << it->second.toString();
  }
  oss << '}';
  return oss.str();
}

JsonObject tunnelToJsonObject(
    i2p::tunnel::Tunnel* tunnel) {
  JsonObject obj;
  std::stringstream ss;
  tunnel->GetTunnelConfig()->Print(ss);  // TODO(unassigned): use a JsonObject
  obj["layout"] = JsonObject(ss.str());
  const auto state = tunnel->GetState();
  if (state == i2p::tunnel::eTunnelStateFailed)
     obj["state"] = JsonObject("failed");
  else if (state == i2p::tunnel::eTunnelStateExpiring)
     obj["state"] = JsonObject("expiring");
  return obj;
}

I2PControlSession::Response::Response(
    const std::string& version)
    : id(),
      version(version),
      error(ErrorCode::None),
      parameters() {}

std::string I2PControlSession::Response::toJsonString() const {
  std::ostringstream oss;
  oss << "{\"id\":" << id << ",\"result\":{";
  for (auto it = parameters.begin(); it != parameters.end(); ++it) {
    if (it != parameters.begin())
      oss << ',';
    oss << '"' << it->first << "\":" << it->second;
  }
  oss << "},\"jsonrpc\":\"" << version << '"';
  if (error != ErrorCode::None)
    oss << ",\"error\":{\"code\":" << -static_cast<int>(error)
      << ",\"message\":\"" << getErrorMsg() << "\"" << "}";
  oss << "}";
  return oss.str();
}

std::string I2PControlSession::Response::getErrorMsg() const {
  switch (error) {
    case ErrorCode::MethodNotFound:
      return "Method not found.";
    case ErrorCode::InvalidParameters:
      return "Invalid parameters.";
    case ErrorCode::InvalidRequest:
      return "Invalid request.";
    case ErrorCode::ParseError:
      return "Json parse error.";
    case ErrorCode::InvalidPassword:
      return "Invalid password.";
    case ErrorCode::NoToken:
      return "No authentication token given.";
    case ErrorCode::NonexistentToken:
      return "Nonexistent authentication token given.";
    case ErrorCode::ExpiredToken:
      return "Expired authentication token given.";
    case ErrorCode::UnspecifiedVersion:
      return "Version not specified.";
    case ErrorCode::UnsupportedVersion:
      return "Version not supported.";
    default:
      return "";
  }
}

void I2PControlSession::Response::setParam(
  const std::string& param,
  const std::string& value) {
  parameters[param] = value.empty() ? "null" : "\"" + value + "\"";
}

void I2PControlSession::Response::setParam(
  const std::string& param,
  int value) {
  parameters[param] = std::to_string(value);
}

void I2PControlSession::Response::setParam(
  const std::string& param,
  double value) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(2) << value;
  parameters[param] = oss.str();
}

void I2PControlSession::Response::setParam(
  const std::string& param,
  const JsonObject& value) {
  parameters[param] = value.toString();
}

void I2PControlSession::Response::setError(ErrorCode code) {
  error = code;
}

void I2PControlSession::Response::setId(const std::string& identifier) {
  id = identifier;
}

I2PControlSession::I2PControlSession(
  boost::asio::io_service& ios,
  const std::string& pass)
    : password(pass),
      tokens(),
      tokensMutex(),
      service(ios),
      shutdownTimer(ios),
      expireTokensTimer(ios) {

  namespace constants = i2p::client::i2pcontrol::constants;

  // Method handlers
  methodHandlers[constants::METHOD_AUTHENTICATE] =
    &I2PControlSession::handleAuthenticate;

  methodHandlers[constants::METHOD_ECHO] =
    &I2PControlSession::handleEcho;

  methodHandlers[constants::METHOD_I2PCONTROL] =
    &I2PControlSession::handleI2PControl;

  methodHandlers[constants::METHOD_ROUTER_INFO] =
    &I2PControlSession::handleRouterInfo;

  methodHandlers[constants::METHOD_ROUTER_MANAGER] =
    &I2PControlSession::handleRouterManager;

  methodHandlers[constants::METHOD_NETWORK_SETTING] =
    &I2PControlSession::handleNetworkSetting;

  // RouterInfo handlers
  routerInfoHandlers[constants::ROUTER_INFO_UPTIME] =
    &I2PControlSession::handleUptime;

  routerInfoHandlers[constants::ROUTER_INFO_VERSION] =
    &I2PControlSession::handleVersion;

  routerInfoHandlers[constants::ROUTER_INFO_STATUS] =
    &I2PControlSession::handleStatus;

  routerInfoHandlers[constants::ROUTER_INFO_DATAPATH] =
    &I2PControlSession::handleDatapath;

  routerInfoHandlers[constants::ROUTER_INFO_NETDB_KNOWNPEERS] =
    &I2PControlSession::handleNetDbKnownPeers;

  routerInfoHandlers[constants::ROUTER_INFO_NETDB_ACTIVEPEERS] =
    &I2PControlSession::handleNetDbActivePeers;

  routerInfoHandlers[constants::ROUTER_INFO_NETDB_LEASESETS] =
    &I2PControlSession::handleNetDbLeaseSets;

  routerInfoHandlers[constants::ROUTER_INFO_NETDB_FLOODFILLS] =
    &I2PControlSession::handleNetDbFloodfills;

  routerInfoHandlers[constants::ROUTER_INFO_NET_STATUS] =
    &I2PControlSession::handleNetStatus;

  routerInfoHandlers[constants::ROUTER_INFO_TUNNELS_PARTICIPATING] =
    &I2PControlSession::handleTunnelsParticipating;

  routerInfoHandlers[constants::ROUTER_INFO_TUNNELS_CREATION_SUCCESS] =
    &I2PControlSession::handleTunnelsCreationSuccess;

  routerInfoHandlers[constants::ROUTER_INFO_TUNNELS_IN_LIST] =
    &I2PControlSession::handleTunnelsInList;

  routerInfoHandlers[constants::ROUTER_INFO_TUNNELS_OUT_LIST] =
    &I2PControlSession::handleTunnelsOutList;

  routerInfoHandlers[constants::ROUTER_INFO_BW_IB_1S] =
    &I2PControlSession::handleInBandwidth1S;

  routerInfoHandlers[constants::ROUTER_INFO_BW_OB_1S] =
    &I2PControlSession::handleOutBandwidth1S;

  // RouterManager handlers
  routerManagerHandlers[constants::ROUTER_MANAGER_SHUTDOWN] =
    &I2PControlSession::handleShutdown;

  routerManagerHandlers[constants::ROUTER_MANAGER_SHUTDOWN_GRACEFUL] =
    &I2PControlSession::handleShutdownGraceful;

  routerManagerHandlers[constants::ROUTER_MANAGER_RESEED] =
    &I2PControlSession::handleReseed;
}

void I2PControlSession::start() {
  startExpireTokensJob();
}

void I2PControlSession::stop() {
  boost::system::error_code e;  // Make sure this doesn't throw
  shutdownTimer.cancel(e);
  expireTokensTimer.cancel(e);
}

I2PControlSession::Response I2PControlSession::handleRequest(
    std::stringstream& request) {
  boost::property_tree::ptree pt;
  boost::property_tree::read_json(request, pt);
  Response response;
  try {
    response.setId(pt.get<std::string>(constants::PROPERTY_ID));
    std::string method = pt.get<std::string>(constants::PROPERTY_METHOD);
    auto it = methodHandlers.find(method);
    if (it == methodHandlers.end()) {  // Not found
      LogPrint(eLogWarning, "Unknown I2PControl method ", method);
      response.setError(ErrorCode::MethodNotFound);
      return response;
    }
    PropertyTree params = pt.get_child(constants::PROPERTY_PARAMS);
    if (method != constants::METHOD_AUTHENTICATE &&
        !authenticate(params, response)) {
      LogPrint(eLogWarning, "I2PControl invalid token presented");
      return response;
    }
    // Call the appropriate handler
    (this->*(it->second))(params, response);
  } catch (const boost::property_tree::ptree_error& error) {
    response.setError(ErrorCode::ParseError);
  } catch (...) {
    response.setError(ErrorCode::InternalError);
  }

  return response;
}

bool I2PControlSession::authenticate(
    const PropertyTree& pt, Response& response) {
  try {
    std::string token = pt.get<std::string>(constants::PARAM_TOKEN);
    std::lock_guard<std::mutex> lock(tokensMutex);
    auto it = tokens.find(token);
    if (it == tokens.end()) {
      response.setError(ErrorCode::NonexistentToken);
      return false;
    } else if (util::GetSecondsSinceEpoch() - it->second >
        constants::TOKEN_LIFETIME) {
      response.setError(ErrorCode::ExpiredToken);
      return false;
    }
  } catch (const boost::property_tree::ptree_error& error) {
    response.setError(ErrorCode::NoToken);
    return false;
  }
  return true;
}

std::string I2PControlSession::generateToken() const {
  byte random_data[constants::TOKEN_SIZE] = {};
  CryptoPP::AutoSeededRandomPool rng;
  rng.GenerateBlock(random_data, constants::TOKEN_SIZE);
  std::string token;
  CryptoPP::StringSource ss(
      random_data,
      constants::TOKEN_SIZE,
      true,
      new CryptoPP::HexEncoder(
        new CryptoPP::StringSink(
          token)));
  return token;
}

void I2PControlSession::handleAuthenticate(
    const PropertyTree& pt,
    Response& response) {
  const int api = pt.get<int>(constants::PARAM_API);
  const std::string given_pass =
    pt.get<std::string>(constants::PARAM_PASSWORD);
  LogPrint(eLogDebug,
      "I2PControl Authenticate API = ", api,
      " Password = ", given_pass);
  if (given_pass != password) {
    LogPrint(eLogError, "I2PControl Authenticate Invalid password ",
      given_pass, " expected ", password);
    response.setError(ErrorCode::InvalidPassword);
    return;
  }
  const std::string token = generateToken();
  response.setParam(constants::PARAM_API, api);
  response.setParam(constants::PARAM_TOKEN, token);
  std::lock_guard<std::mutex> lock(tokensMutex);
  tokens.insert(
      std::make_pair(
        token,
        util::GetSecondsSinceEpoch()));
}

void I2PControlSession::handleEcho(
    const PropertyTree& pt,
    Response& response) {
  const std::string echo = pt.get<std::string>(constants::PARAM_ECHO);
  LogPrint(eLogDebug, "I2PControl Echo Echo = ", echo);
  response.setParam(constants::PARAM_RESULT, echo);
}

void I2PControlSession::handleI2PControl(
    const PropertyTree&,
    Response&) {
  LogPrint(eLogDebug, "I2PControl I2PControl");
  // TODO(anonimal): implement
}

void I2PControlSession::handleRouterInfo(
    const PropertyTree& pt,
    Response& response) {
  LogPrint(eLogDebug, "I2PControl RouterInfo");
  for (const auto& pair : pt) {
    if (pair.first == constants::PARAM_TOKEN)
      continue;
    LogPrint(eLogDebug, pair.first);
    auto it = routerInfoHandlers.find(pair.first);
    if (it != routerInfoHandlers.end()) {
      (this->*(it->second))(response);
    } else {
      LogPrint(eLogError, "I2PControl RouterInfo unknown request ", pair.first);
      response.setError(ErrorCode::InvalidRequest);
    }
  }
}

void I2PControlSession::handleRouterManager(
    const PropertyTree& pt,
    Response& response) {
  LogPrint(eLogDebug, "I2PControl RouterManager");
  for (const auto& pair : pt) {
    if (pair.first == constants::PARAM_TOKEN)
      continue;
    LogPrint(eLogDebug, pair.first);
    auto it = routerManagerHandlers.find(pair.first);
    if (it != routerManagerHandlers.end()) {
      (this->*(it->second))(response);
    } else {
      LogPrint(eLogError,
          "I2PControl RouterManager unknown request ", pair.first);
      response.setError(ErrorCode::InvalidRequest);
    }
  }
}

void I2PControlSession::handleNetworkSetting(
    const PropertyTree&,
    Response&) {
  // TODO(anonimal): implement
}

void I2PControlSession::handleUptime(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_UPTIME,
      static_cast<int>(i2p::context.GetUptime())*1000);
}

void I2PControlSession::handleVersion(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_VERSION,
      KOVRI_VERSION);
}

void I2PControlSession::handleStatus(
    Response& response) {
  // TODO(anonimal): implement
  response.setParam(
      constants::ROUTER_INFO_STATUS,
      "???");
}

void I2PControlSession::handleDatapath(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_DATAPATH,
      i2p::util::filesystem::GetDefaultDataPath().string());
}

void I2PControlSession::handleNetDbKnownPeers(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_NETDB_KNOWNPEERS,
      i2p::data::netdb.GetNumRouters());
}

void I2PControlSession::handleNetDbActivePeers(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_NETDB_ACTIVEPEERS,
      static_cast<int>(i2p::transport::transports.GetPeers().size()));
}

void I2PControlSession::handleNetDbFloodfills(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_NETDB_FLOODFILLS,
      static_cast<int>(i2p::data::netdb.GetNumFloodfills()));
}

void I2PControlSession::handleNetDbLeaseSets(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_NETDB_LEASESETS,
      static_cast<int>(i2p::data::netdb.GetNumLeaseSets()));
}

void I2PControlSession::handleNetStatus(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_NET_STATUS,
      static_cast<int>(i2p::context.GetStatus()));
}

void I2PControlSession::handleTunnelsParticipating(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_TUNNELS_PARTICIPATING,
      static_cast<int>(i2p::tunnel::tunnels.GetTransitTunnels().size()));
}

void I2PControlSession::handleTunnelsCreationSuccess(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_TUNNELS_CREATION_SUCCESS,
      i2p::tunnel::tunnels.GetTunnelCreationSuccessRate());
}

void I2PControlSession::handleTunnelsInList(
    Response& response) {
  JsonObject list;
  for (auto pair : i2p::tunnel::tunnels.GetInboundTunnels()) {
    const std::string id = std::to_string(pair.first);
    list[id] = tunnelToJsonObject(pair.second.get());
    list[id]["bytes"] = JsonObject(
      static_cast<int>(pair.second->GetNumReceivedBytes()));
  }
  response.setParam(
      constants::ROUTER_INFO_TUNNELS_IN_LIST,
      list);
}

void I2PControlSession::handleTunnelsOutList(
    Response& response) {
  JsonObject list;
  for (auto tunnel : i2p::tunnel::tunnels.GetOutboundTunnels()) {
    const std::string id = std::to_string(
        tunnel->GetTunnelID());
    list[id] = tunnelToJsonObject(tunnel.get());
    list[id]["bytes"] = JsonObject(
        static_cast<int>(tunnel->GetNumSentBytes()));
  }
  response.setParam(
      constants::ROUTER_INFO_TUNNELS_OUT_LIST,
      list);
}

void I2PControlSession::handleInBandwidth1S(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_BW_IB_1S,
      static_cast<double>(i2p::transport::transports.GetInBandwidth()));
}

void I2PControlSession::handleOutBandwidth1S(
    Response& response) {
  response.setParam(
      constants::ROUTER_INFO_BW_OB_1S,
      static_cast<double>(i2p::transport::transports.GetOutBandwidth()));
}

void I2PControlSession::handleShutdown(
    Response& response) {
  LogPrint(eLogInfo, "Shutdown requested");
  response.setParam(constants::ROUTER_MANAGER_SHUTDOWN, "");
  // 1 second to make sure response has been sent
  shutdownTimer.expires_from_now(
      boost::posix_time::seconds(1));
  shutdownTimer.async_wait([](
        const boost::system::error_code&) {
      Daemon.m_isRunning = 0;});
}

void I2PControlSession::handleShutdownGraceful(
    Response& response) {
  i2p::context.SetAcceptsTunnels(false);
  int timeout = i2p::tunnel::tunnels.GetTransitTunnelsExpirationTimeout();
  LogPrint(eLogInfo, "Graceful shutdown requested. Will shutdown after ",
      timeout, " seconds");
  response.setParam(
      constants::ROUTER_MANAGER_SHUTDOWN_GRACEFUL,
      "");
  shutdownTimer.expires_from_now(
      boost::posix_time::seconds(
        timeout + 1));
  shutdownTimer.async_wait([](
        const boost::system::error_code&) {
      Daemon.m_isRunning = 0;});
}

void I2PControlSession::handleReseed(
    Response& response) {
  LogPrint(eLogInfo, "Reseed requested");
  response.setParam(
      constants::ROUTER_MANAGER_SHUTDOWN,
      "");
  i2p::data::netdb.Reseed();
}

void I2PControlSession::expireTokens(
    const boost::system::error_code& error) {
  if (error == boost::asio::error::operation_aborted)
    return;  // Do not restart timer, shutting down
  startExpireTokensJob();
  LogPrint(eLogDebug, "I2PControl is expiring tokens.");
  const uint64_t now = util::GetSecondsSinceEpoch();
  std::lock_guard<std::mutex> lock(tokensMutex);
  for (auto it = tokens.begin(); it != tokens.end(); ) {
    if (now - it->second > constants::TOKEN_LIFETIME)
      it = tokens.erase(it);
    else
      ++it;
  }
}

void I2PControlSession::startExpireTokensJob() {
  expireTokensTimer.expires_from_now(
      boost::posix_time::seconds(
        constants::TOKEN_LIFETIME));
  expireTokensTimer.async_wait(
      std::bind(
        &I2PControlSession::expireTokens,
        shared_from_this(),
        std::placeholders::_1));
}

}  // namespace i2pcontrol
}  // namespace client
}  // namespace i2p
