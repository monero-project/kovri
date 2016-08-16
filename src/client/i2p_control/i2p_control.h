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

#ifndef SRC_CLIENT_I2P_CONTROL_I2P_CONTROL_H_
#define SRC_CLIENT_I2P_CONTROL_I2P_CONTROL_H_

#include <boost/asio.hpp>
#include <boost/property_tree/ptree.hpp>

#include <functional>
#include <map>
#include <mutex>
#include <string>

#include "core/tunnel/tunnel.h"

namespace i2p {
namespace client {
namespace i2pcontrol {

namespace constants {

const char DEFAULT_PASSWORD[] = "itoopie";
const uint64_t TOKEN_LIFETIME = 600;  // Token lifetime in seconds
const std::size_t TOKEN_SIZE = 8;  // Token size in bytes

const char PROPERTY_ID[] = "id";
const char PROPERTY_METHOD[] = "method";
const char PROPERTY_PARAMS[] = "params";
const char PROPERTY_RESULT[] = "result";

// methods
const char METHOD_AUTHENTICATE[] = "Authenticate";
const char METHOD_ECHO[] = "Echo";
const char METHOD_I2PCONTROL[] = "I2PControl";
const char METHOD_ROUTER_INFO[] = "RouterInfo";
const char METHOD_ROUTER_MANAGER[] = "RouterManager";
const char METHOD_NETWORK_SETTING[] = "NetworkSetting";

// params
const char PARAM_API[] = "API";
const char PARAM_PASSWORD[] = "Password";
const char PARAM_TOKEN[] = "Token";
const char PARAM_ECHO[] = "Echo";
const char PARAM_RESULT[] = "Result";

// I2PControl
const char I2PCONTROL_ADDRESS[] = "i2pcontrol.address";
const char I2PCONTROL_PASSWORD[] = "i2pcontrol.password";
const char I2PCONTROL_PORT[] = "i2pcontrol.port";

// RouterInfo requests
const char ROUTER_INFO_UPTIME[] =
  "i2p.router.uptime";

const char ROUTER_INFO_VERSION[] =
  "i2p.router.version";

const char ROUTER_INFO_STATUS[] =
  "i2p.router.status";

const char ROUTER_INFO_DATAPATH[] =
  "i2p.router.datapath";

const char ROUTER_INFO_NETDB_KNOWNPEERS[] =
  "i2p.router.netdb.knownpeers";

const char ROUTER_INFO_NETDB_ACTIVEPEERS[] =
  "i2p.router.netdb.activepeers";

const char ROUTER_INFO_NETDB_FLOODFILLS[] =
  "i2p.router.netdb.floodfills";

const char ROUTER_INFO_NETDB_LEASESETS[] =
  "i2p.router.netdb.leasesets";

const char ROUTER_INFO_NET_STATUS[] =
  "i2p.router.net.status";

const char ROUTER_INFO_TUNNELS_PARTICIPATING[] =
  "i2p.router.net.tunnels.participating";

// TODO(unassigned): Probably better to use the standard GetRate instead
const char ROUTER_INFO_TUNNELS_CREATION_SUCCESS[] =
  "i2p.router.net.tunnels.creationsuccessrate";

const char ROUTER_INFO_TUNNELS_IN_LIST[] =
  "i2p.router.net.tunnels.inbound.list";

const char ROUTER_INFO_TUNNELS_OUT_LIST[] =
  "i2p.router.net.tunnels.outbound.list";

const char ROUTER_INFO_BW_IB_1S[] =
  "i2p.router.net.bw.inbound.1s";

const char ROUTER_INFO_BW_OB_1S[] =
  "i2p.router.net.bw.outbound.1s";

// RouterManager requests
const char ROUTER_MANAGER_SHUTDOWN[] = "Shutdown";
const char ROUTER_MANAGER_SHUTDOWN_GRACEFUL[] = "ShutdownGraceful";
const char ROUTER_MANAGER_RESEED[] = "Reseed";

}  // namespace constants

/**
 * @class JsonObject
 * @brief Represents a Json object, provides functionality to convert to string.
 */
class JsonObject {
 public:
  JsonObject() = default;

  explicit JsonObject(
      const std::string& value);

  explicit JsonObject(
      int value);

  explicit JsonObject(
      double value);

  JsonObject& operator[](
      const std::string& key);

  std::string ToString() const;

 private:
  std::map<std::string, JsonObject> m_Children;
  std::string m_Value;
};

JsonObject TunnelToJsonObject(
    i2p::tunnel::Tunnel* tunnel);

/**
 * @class I2PControlSession
 * @brief "Null" I2P control implementation, does not do actual networking.
 * @note authentication tokens are per-session
 * @note I2PControlSession must always be used as a std::shared_ptr
 * @warning an I2PControlSession must be destroyed before its io_service
 */
class I2PControlSession
    : public std::enable_shared_from_this<I2PControlSession> {
 public:
  enum class ErrorCode {
    e_None = 0,
    // JSON-RPC2
    e_MethodNotFound = 32601,
    e_InvalidParameters = 32602,
    e_InvalidRequest = 32600,
    e_InternalError = 32603,
    e_ParseError = 32700,
    // I2PControl specific
    e_InvalidPassword = 32001,
    e_NoToken = 32002,
    e_NonexistentToken = 32003,
    e_ExpiredToken = 32004,
    e_UnspecifiedVersion = 32005,
    e_UnsupportedVersion = 32006
  };

  class Response {
   public:
    explicit Response(
        const std::string& version = "2.0");

    // Returns response params in JSON form
    std::string ToJsonString() const;

    // Set an output parameter to a specified string.
    // @todo escape quotes
    void SetParam(
        const std::string& param,
        const std::string& value);

    // Set an output parameter to a specified integer.
    void SetParam(
        const std::string& param,
        int value);

    // Set an output parameter to a specified double.
    void SetParam(
        const std::string& param,
        double value);

    // Set an output parameter to a specified Json object.
    void SetParam(
        const std::string& param,
        const JsonObject& value);

    void SetError(
        ErrorCode code);

    void SetID(
        const std::string& id);

    std::string GetErrorMsg() const;

   private:
    std::string m_ID;
    std::string m_Version;
    ErrorCode m_Error;
    std::map<std::string, std::string> m_Params;
  };  // class Response

  // Sets up the appropriate handlers.
  // @param ios the parent io_service object, must remain valid throughout
  // the lifetime of this I2PControlSession.
  // @param pass the password required to authenticate (i.e. obtains a token)
  I2PControlSession(
      boost::asio::io_service& ios,
      const std::string& pass = constants::DEFAULT_PASSWORD);

  // Starts the I2PControlSession.
  // In essence, this starts the expireTokensTimer.
  // @note should always be called after construction
  void Start();

  // Cancels all operations that are waiting.
  // @note it's a good idea to call this before destruction (shared_ptr reset)
  void Stop();

  // Handle a json string with I2PControl instructions.
  Response HandleRequest(
      std::stringstream& request);

 private:
  // For convenience
  typedef boost::property_tree::ptree ptree;

  // Handler types
  typedef void (I2PControlSession::*MethodHandler)(
      const ptree& pt,
      Response& results);
  typedef void (I2PControlSession::*RequestHandler)(
      Response& results);

  // Tries to authenticate by checking whether the given token is valid.
  // Sets the appropriate error code in the given response.
  bool Authenticate(
      const ptree& pt,
      Response& response);

  // Generate a random authentication token.
  // @return 8 random bytes as a hexadecimal string
  std::string GenerateToken() const;

  // Expire tokens that are too old.
  void StartExpireTokensJob();
  void ExpireTokens(const boost::system::error_code& error);

  // Method handlers
  void HandleAuthenticate(const ptree& pt, Response& response);
  void HandleEcho(const ptree& pt, Response& response);
  void HandleI2PControl(const ptree& pt, Response& response);
  void HandleRouterInfo(const ptree& pt, Response& response);
  void HandleRouterManager(const ptree& pt, Response& response);
  void HandleNetworkSetting(const ptree& pt, Response& response);

  // RouterInfo handlers
  void HandleUptime(Response& response);
  void HandleVersion(Response& response);
  void HandleStatus(Response& response);
  void HandleDatapath(Response& response);
  void HandleNetDbKnownPeers(Response& response);
  void HandleNetDbActivePeers(Response& response);
  void HandleNetDbFloodfills(Response& response);
  void HandleNetDbLeaseSets(Response& response);
  void HandleNetStatus(Response& response);

  void HandleTunnelsParticipating(Response& response);
  void HandleTunnelsCreationSuccess(Response& response);
  void HandleTunnelsInList(Response& response);
  void HandleTunnelsOutList(Response& response);

  void HandleInBandwidth1S(Response& response);
  void HandleOutBandwidth1S(Response& response);

  // RouterManager handlers
  void HandleShutdown(Response& response);
  void HandleShutdownGraceful(Response& response);
  void HandleReseed(Response& response);

  std::string m_Password;
  std::map<std::string, uint64_t> m_Tokens;
  std::mutex m_TokensMutex,
             m_ShutdownMutex;

  std::map<std::string, MethodHandler> m_MethodHandlers;
  std::map<std::string, RequestHandler> m_RouterInfoHandlers,
                                        m_RouterManagerHandlers,
                                        m_NetworkSettingHandlers;

  /// @todo Unused private field. Why?
  boost::asio::io_service& m_Service;
  boost::asio::deadline_timer m_ShutdownTimer,
                              m_ExpireTokensTimer;
};

}  // namespace i2pcontrol
}  // namespace client
}  // namespace i2p

#endif  // SRC_CLIENT_I2P_CONTROL_I2P_CONTROL_H_
