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

#include "client/api/i2p_control/session.h"

#include <boost/property_tree/json_parser.hpp>
#include <memory>

#include "client/context.h"

#include "core/crypto/rand.h"

#include "core/router/context.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/impl.h"

#include "core/util/filesystem.h"
#include "core/util/log.h"
#include "core/util/timestamp.h"

#include "version.h"

namespace kovri {
namespace client {
JsonObject TunnelToJsonObject(
    kovri::core::Tunnel* tunnel) {
  JsonObject obj;
  std::stringstream ss;
  tunnel->GetTunnelConfig()->Print(ss);  // TODO(unassigned): use a JsonObject
  obj["layout"] = JsonObject(ss.str());
  const auto state = tunnel->GetState();
  if (state == kovri::core::e_TunnelStateFailed)
     obj["state"] = JsonObject("failed");
  else if (state == kovri::core::e_TunnelStateExpiring)
     obj["state"] = JsonObject("expiring");
  return obj;
}

I2PControlSession::I2PControlSession(
  boost::asio::io_service& ios,
  const std::string& pass)
    : m_Password(pass),
      m_Tokens(),
      m_TokensMutex(),
      m_ShutdownTimer(ios),
      m_ExpireTokensTimer(ios) {

  // Method handlers
  m_MethodHandlers[Method::Authenticate] =
      &I2PControlSession::HandleAuthenticate;

  m_MethodHandlers[Method::Echo] = &I2PControlSession::HandleEcho;

  // TODO(unassigned): method GetRate

  m_MethodHandlers[Method::I2PControl] = &I2PControlSession::HandleI2PControl;

  m_MethodHandlers[Method::RouterInfo] = &I2PControlSession::HandleRouterInfo;

  m_MethodHandlers[Method::RouterManager] =
      &I2PControlSession::HandleRouterManager;

  // RouterManager handlers
  m_RouterManagerHandlers[RouterManager::Shutdown] =
      &I2PControlSession::HandleShutdown;

  m_RouterManagerHandlers[RouterManager::ShutdownGraceful] =
      &I2PControlSession::HandleShutdownGraceful;

  m_RouterManagerHandlers[RouterManager::Reseed] =
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

std::unique_ptr<I2PControlResponse> I2PControlSession::HandleRequest(
    std::stringstream& stream)
{
  LOG(debug) << "I2PControlSession: reading json request";
  auto response = std::make_unique<I2PControlResponse>();
  try {
    // Parse request
    I2PControlRequest request;
    request.Parse(stream);
    // Build response
    response->SetID(request.GetID());
    auto method = request.GetMethod();
    auto it = m_MethodHandlers.find(method);
    if (it == m_MethodHandlers.end()) {  // Not found
        LOG(error) << "I2PControlSession: unknown or unimplemented method "
                     << core::GetType(method);
        response->SetError(ErrorCode::MethodNotFound);
        return response;
    }
    response->SetMethod(method);

    if (method != Method::Authenticate
        && !Authenticate(request, response.get()))
      {
        LOG(warning) << "I2PControlSession: invalid token presented";
        return response;
      }
    LOG(debug) << "I2PControlSession: calling handler";
    (this->*(it->second))(request, response.get());
  } catch (const boost::property_tree::ptree_error&) {
      response->SetError(ErrorCode::ParseError);
  } catch (const std::logic_error&) {
      response->SetError(ErrorCode::ParseError);
  } catch (const boost::bad_get&) {
      response->SetError(ErrorCode::ParseError);
  } catch (...) {
      response->SetError(ErrorCode::InternalError);
  }
  return response;
}

bool I2PControlSession::Authenticate(
    const I2PControlRequest& request,
    I2PControlResponse* response)
{
  std::lock_guard<std::mutex> lock(m_TokensMutex);
  auto token = request.GetToken();
  if (token.empty())
    {
      response->SetError(ErrorCode::NoToken);
      return false;
    }
  auto it = m_Tokens.find(token);
  if (it == m_Tokens.end())
    {
      response->SetError(ErrorCode::NonexistentToken);
      return false;
    }
  else if (kovri::core::GetSecondsSinceEpoch() - it->second > TOKEN_LIFETIME)
    {
      response->SetError(ErrorCode::ExpiredToken);
      return false;
    }
  return true;
}

std::string I2PControlSession::GenerateToken() const {
  // Generate random data for token
  std::array<std::uint8_t, TOKEN_SIZE> rand {{}};
  kovri::core::RandBytes(rand.data(), TOKEN_SIZE);
  // Create base16 token from random data
  std::stringstream token;
  for (std::size_t i(0); i < rand.size(); i++)
    token << std::hex << std::setfill('0') << std::setw(2)
    << std::uppercase << static_cast<std::size_t>(rand.at(i));
  // Return string
  return token.str();
}

void I2PControlSession::HandleAuthenticate(
    const Request& request,
    Response* response)
{
  typedef I2PControlData::MethodAuthenticate Auth;

  const auto api = request.GetParam<std::size_t>(Auth::API);
  const auto given_pass = request.GetParam<std::string>(Auth::Password);
  LOG(debug)
    << "I2PControlSession: Authenticate API = " << api
    << " Password = " << given_pass;
  if (given_pass != m_Password) {
    LOG(error)
      << "I2PControlSession: invalid password "
      << given_pass << " expected " << m_Password;
    response->SetError(ErrorCode::InvalidPassword);
    return;
  }
  const std::string token = GenerateToken();
  response->SetParam(Auth::API, api);
  response->SetParam(Auth::Token, token);
  std::lock_guard<std::mutex> lock(m_TokensMutex);
  m_Tokens.insert(
      std::make_pair(
        token,
        kovri::core::GetSecondsSinceEpoch()));
}

void I2PControlSession::HandleEcho(const Request& request, Response* response)
{
  typedef I2PControlData::MethodEcho Keys;
  const std::string echo = request.GetParam<std::string>(Keys::Echo);
  LOG(debug) << "I2PControlSession: Echo = " << echo;
  response->SetParam(Keys::Result, echo);
}

void I2PControlSession::HandleI2PControl(const Request&, Response*)
{
  // TODO(unassigned): implement method I2PControl
  LOG(debug) << "I2PControlSession: I2PControl";
}

void I2PControlSession::HandleRouterInfo(
    const Request& request,
    Response* response)
{
  typedef I2PControlData::MethodRouterInfo RouterInfo;
  LOG(debug) << "I2PControlSession: HandleRouterInfo()";
  for (const auto& pair : request.GetParams())
    {
      switch (pair.first)
        {
          case RouterInfo::Status:
            response->SetParam(
                pair.first, core::context.GetState(core::context.GetState()));
            break;

          case RouterInfo::Uptime:
            response->SetParam(
                pair.first,
                // TODO(unassigned): do not downcast from uint64_t! Requires interface work.
                static_cast<std::size_t>(core::context.GetUptime()) * 1000);  // TODO(unassigned): multiplying will not bode well for the distant future...
            break;

          case RouterInfo::Version:
            response->SetParam(
                pair.first,
                std::string(KOVRI_VERSION) + "-" + KOVRI_GIT_REVISION + "-"
                    + KOVRI_CODENAME);
            break;

          case RouterInfo::BWIn1S:
            response->SetParam(
                pair.first,
                static_cast<double>(kovri::core::transports.GetInBandwidth()));
            break;

          case RouterInfo::BWOut1S:
            response->SetParam(
                pair.first,
                static_cast<double>(kovri::core::transports.GetOutBandwidth()));
            break;

          case RouterInfo::NetStatus:
            response->SetParam(
                pair.first,
                static_cast<std::size_t>(core::context.GetState()));
            break;

          case RouterInfo::TunnelsParticipating:
            response->SetParam(
                pair.first, core::tunnels.GetTransitTunnels().size());
            break;

          case RouterInfo::ActivePeers:
            response->SetParam(pair.first, core::transports.GetPeers().size());
            break;

          case RouterInfo::KnownPeers:
            response->SetParam(pair.first, core::netdb.GetNumRouters());
            break;

          // Extra pair.firsts
          case RouterInfo::DataPath:
            response->SetParam(pair.first, core::GetPath(core::Path::Core).string());
            break;

          case RouterInfo::Floodfills:
            response->SetParam(pair.first, core::netdb.GetNumFloodfills());
            break;

          case RouterInfo::LeaseSets:
            response->SetParam(pair.first, core::netdb.GetNumLeaseSets());
            break;

          case RouterInfo::TunnelsCreationSuccessRate:
            response->SetParam(
                pair.first,
                static_cast<std::size_t>(
                    core::tunnels.GetTunnelCreationSuccessRate()));
            break;

          case RouterInfo::TunnelsInList:
            HandleTunnelsInList(response);
            break;

          case RouterInfo::TunnelsOutList:
            HandleTunnelsOutList(response);
            break;

          case RouterInfo::BWIn15S:
          case RouterInfo::BWOut15S:
          case RouterInfo::FastPeers:
          case RouterInfo::HighCapacityPeers:
          case RouterInfo::IsReseeding:
          // TODO(unassigned): implement these indicators
          default:
            throw std::runtime_error("Indicator not implemented");
        }
    }
}

void I2PControlSession::HandleRouterManager(
    const Request& request,
    Response* response)
{
  LOG(debug) << "I2PControlSession: " << __func__;
  for (const auto& pair : request.GetParams())
    {
      auto it = m_RouterManagerHandlers.find(pair.first);
      if (it != m_RouterManagerHandlers.end())
        {
          (this->*(it->second))(response);
        }
      else
        {
          LOG(error) << "I2PControlSession: " << __func__
                     << ": unknown request " << std::to_string(pair.first);
          response->SetError(ErrorCode::InvalidRequest);
        }
    }
}

void I2PControlSession::HandleTunnelsInList(Response* response)
{
  JsonObject list;
  for (auto pair : kovri::core::tunnels.GetInboundTunnels()) {
    const std::string id = std::to_string(pair.first);
    list[id] = TunnelToJsonObject(pair.second.get());
    list[id]["bytes"] = JsonObject(
      static_cast<int>(pair.second->GetNumReceivedBytes()));
  }
  response->SetParam(I2PControlData::MethodRouterInfo::TunnelsInList, list);
}

void I2PControlSession::HandleTunnelsOutList(Response* response)
{
  JsonObject list;
  for (auto tunnel : kovri::core::tunnels.GetOutboundTunnels()) {
    const std::string id = std::to_string(
        tunnel->GetTunnelID());
    list[id] = TunnelToJsonObject(tunnel.get());
    list[id]["bytes"] = JsonObject(
        static_cast<int>(tunnel->GetNumSentBytes()));
  }
  response->SetParam(I2PControlData::MethodRouterInfo::TunnelsOutList, list);
}

void I2PControlSession::HandleShutdown(Response* response)
{
  LOG(info) << "I2PControlSession: shutdown requested";
  response->SetParam(RouterManager::Shutdown, "");
  // 1 second to make sure response has been sent
  m_ShutdownTimer.expires_from_now(
      boost::posix_time::seconds(1));
  m_ShutdownTimer.async_wait(
      [this](
        const boost::system::error_code&) {
      std::lock_guard<std::mutex> lock(m_ShutdownMutex);
      kovri::client::context.RequestShutdown();
      });
}

void I2PControlSession::HandleShutdownGraceful(Response* response)
{
  // Stop accepting tunnels
  core::context.SetAcceptsTunnels(false);
  // Get tunnel expiry time
  std::uint64_t timeout = kovri::core::tunnels.GetTransitTunnelsExpirationTimeout();
  LOG(info)
    << "I2PControlSession: graceful shutdown requested."
    << "Will shutdown after " << timeout << " seconds";
  // Initiate graceful shutdown
  response->SetParam(RouterManager::ShutdownGraceful, "");
  m_ShutdownTimer.expires_from_now(
      boost::posix_time::seconds(
        timeout + 1));
  m_ShutdownTimer.async_wait(
      [this](
        const boost::system::error_code&) {
      std::lock_guard<std::mutex> lock(m_ShutdownMutex);
      kovri::client::context.RequestShutdown();
      });
}

void I2PControlSession::HandleReseed(Response* response)
{
  LOG(info) << "I2PControlSession: reseed requested";
  response->SetParam(RouterManager::Reseed, "");
  Reseed reseed;
  if (!reseed.Start())
    LOG(error) << "I2PControlSession: reseed failed";
}

void I2PControlSession::ExpireTokens(
    const boost::system::error_code& error) {
  if (error == boost::asio::error::operation_aborted)
    return;  // Do not restart timer, shutting down
  StartExpireTokensJob();
  LOG(debug) << "I2PControlSession: expiring tokens";
  const std::uint64_t now = kovri::core::GetSecondsSinceEpoch();
  std::lock_guard<std::mutex> lock(m_TokensMutex);
  for (auto it = m_Tokens.begin(); it != m_Tokens.end(); ) {
    if (now - it->second > TOKEN_LIFETIME)
      it = m_Tokens.erase(it);
    else
      ++it;
  }
}

void I2PControlSession::StartExpireTokensJob() {
  m_ExpireTokensTimer.expires_from_now(
      boost::posix_time::seconds(
        TOKEN_LIFETIME));
  m_ExpireTokensTimer.async_wait(
      std::bind(
        &I2PControlSession::ExpireTokens,
        shared_from_this(),
        std::placeholders::_1));
}

}  // namespace client
}  // namespace kovri
