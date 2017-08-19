/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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

#ifndef SRC_CLIENT_API_I2P_CONTROL_SESSION_H_
#define SRC_CLIENT_API_I2P_CONTROL_SESSION_H_

#include <boost/asio.hpp>

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "client/api/i2p_control/data.h"
#include "core/router/tunnel/impl.h"

namespace kovri {
namespace client {

const char DEFAULT_PASSWORD[] = "itoopie";
const std::uint64_t TOKEN_LIFETIME = 600;  // Token lifetime in seconds
const std::size_t TOKEN_SIZE = 8;  // Token size in bytes

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
  // For convenience
  typedef I2PControlResponse Response;
  typedef I2PControlRequest Request;
  typedef I2PControlData::Method Method;
  typedef I2PControlData::MethodRouterManager RouterManager;
  typedef I2PControlData::ErrorCode ErrorCode;

  // Sets up the appropriate handlers.
  // @param ios the parent io_service object, must remain valid throughout
  // the lifetime of this I2PControlSession.
  // @param pass the password required to authenticate (i.e. obtains a token)
  I2PControlSession(
      boost::asio::io_service& ios,
      const std::string& pass = DEFAULT_PASSWORD);

  // Starts the I2PControlSession.
  // In essence, this starts the expireTokensTimer.
  // @note should always be called after construction
  void Start();

  // Cancels all operations that are waiting.
  // @note it's a good idea to call this before destruction (shared_ptr reset)
  void Stop();

  // Handle a json string with I2PControl instructions.
  std::unique_ptr<Response> HandleRequest(std::stringstream& request);

 private:
  // Handler types
  typedef void (
      I2PControlSession::*MethodHandler)(const Request& pt, Response* results);
  typedef void (I2PControlSession::*RequestHandler)(Response* results);

  // Tries to authenticate by checking whether the given token is valid.
  // Sets the appropriate error code in the given response.
  bool Authenticate(const Request& request, Response* response);

  // Generate a random authentication token.
  // @return 8 random bytes as a hexadecimal string
  std::string GenerateToken() const;

  // Expire tokens that are too old.
  void StartExpireTokensJob();
  void ExpireTokens(const boost::system::error_code& error);

  // Method handlers
  void HandleAuthenticate(const Request& request, Response* response);
  void HandleEcho(const Request& request, Response* response);
  void HandleI2PControl(const Request& request, Response* response);
  void HandleRouterInfo(const Request& request, Response* response);
  void HandleRouterManager(const Request& request, Response* response);

  // RouterInfo handlers
  void HandleTunnelsInList(Response* response);
  void HandleTunnelsOutList(Response* response);

  // RouterManager handlers
  void HandleShutdown(Response* response);
  void HandleShutdownGraceful(Response* response);
  void HandleReseed(Response* response);

  std::string m_Password;
  std::map<std::string, std::uint64_t> m_Tokens;
  std::mutex m_TokensMutex,
             m_ShutdownMutex;

  std::map<I2PControlData::Method, MethodHandler> m_MethodHandlers;
  std::map<std::uint8_t, RequestHandler> m_RouterManagerHandlers;

  boost::asio::deadline_timer m_ShutdownTimer,
                              m_ExpireTokensTimer;
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_API_I2P_CONTROL_SESSION_H_
