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

#ifndef SRC_CORE_ROUTER_CONTEXT_H_
#define SRC_CORE_ROUTER_CONTEXT_H_

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "core/router/garlic.h"
#include "core/router/identity.h"
#include "core/router/info.h"

namespace kovri
{
namespace core
{

enum struct RouterState : std::uint8_t
{
  /// @brief Context is fully port forwarded
  OK,

  /// @brief Context is testing connectivity
  Testing,

  /// @brief Context detects being firewalled
  Firewalled,
};

class RouterContext : public RouterInfoTraits, public GarlicDestination {
 public:
  RouterContext();

  /// @brief Initializes the router context, must be called before further context use
  /// @param map Variable map used to initialize context options
  void Initialize(const boost::program_options::variables_map& map);

  // @return This RouterContext's RouterInfo
  kovri::core::RouterInfo& GetRouterInfo() {
    return m_RouterInfo;
  }

  // @return This RouterContext's RouterInfo wrapped in a smart pointer
  std::shared_ptr<const kovri::core::RouterInfo> GetSharedRouterInfo() const  {
    return std::shared_ptr<const kovri::core::RouterInfo>(
        &m_RouterInfo,
        [](const kovri::core::RouterInfo *) {});
  }

  // @return How long this RouterContext has been online in seconds since epoch
  std::uint64_t GetUptime() const;

  // @return Time that this RouterContext started in seconds since epoch
  std::uint32_t GetStartupTime() const {
    return m_StartupTime;
  }

  // @return Time this RouterContext last updated its RouterInfo
  std::uint64_t GetLastUpdateTime() const {
    return m_LastUpdateTime;
  }

  /// @return Router state
  RouterState GetState() const noexcept
  {
    return m_State;
  }

  /// @return Router state
  std::string GetState(RouterState state) const noexcept
  {
    switch (state)
      {
        case RouterState::OK:
          return "OK";
        case RouterState::Testing:
          return "Testing";
        case RouterState::Firewalled:
          return "Firewalled";
        default:
          return "Unknown";
      }
  }

  /// @brief Set context state
  // @param status the new state this context will have
  void SetState(RouterState state) noexcept
  {
    m_State = state;
  }

  /// @brief Updates our external IP Address
  /// @param host Our IP address
  /// @param host_size Our IP address size in bytes
  /// @param port Our port number
  /// @notes Default port paramter set for UPnP
  /// @notes Rebuilds RouterInfo
  void UpdateAddress(
      const std::uint8_t* host,
      const std::uint8_t host_size,
      const std::uint16_t port = 0);

  // Add an SSU introducer to our RouterInfo.
  // Rebuild RouterInfo.
  // @param routerInfo the RouterInfo to use in the Introducer
  // @param tag
  bool AddIntroducer(
      const kovri::core::RouterInfo& routerInfo,
      std::uint32_t tag);

  // Remove and SSU introducer given its endpoint.
  // Rebuilds RouterInfo.
  // @param e the SSU introducer's endpoint
  void RemoveIntroducer(
      const boost::asio::ip::udp::endpoint& e);

  // @return true if other routers cannot reach us otherwise false
  bool IsUnreachable() const;

  // Set that other routers cannot reach us
  void SetUnreachable();

  // Set that other routers *can* reach us
  void SetReachable();

  // @return true if we are a floodfill router otherwise false
  bool IsFloodfill() const
  {
    return m_Opts["enable-floodfill"].as<bool>();
  }

  // @return true if we are going to accept tunnels right now.
  bool AcceptsTunnels() const {
    return m_AcceptsTunnels;
  }

  // Set explicitly if we want to accept tunnels right now.
  // @param acceptTunnels true if we want to accept tunnels otherwise false
  void SetAcceptsTunnels(
      bool acceptsTunnels) {
    m_AcceptsTunnels = acceptsTunnels;
  }

  // @return true if we support IPv6 connectivity otherwise false
  bool SupportsV6() const {
    return m_RouterInfo.HasV6();
  }

  // Called From NTCPSession.
  // Update our NTCP IPv6 address.
  // Rebuilds RouterInfo.
  // @param host Our reachable IPv6 address for NTCP
  void UpdateNTCPV6Address(
      const boost::asio::ip::address& host);

  // Update Stats in Router Info when floodfill.
  // Rebuilds RouterInfo.
  void UpdateStats();

  // implements LocalDestination
  const kovri::core::PrivateKeys& GetPrivateKeys() const {
    return m_Keys;
  }

  const std::uint8_t* GetEncryptionPrivateKey() const {
    return m_Keys.GetPrivateKey();
  }

  const std::uint8_t* GetEncryptionPublicKey() const {
    return GetIdentity().GetStandardIdentity().public_key;
  }

  void SetLeaseSetUpdated() {}

  // implements GarlicDestination
  std::shared_ptr<const kovri::core::LeaseSet> GetLeaseSet() {
    return nullptr;
  }

  std::shared_ptr<kovri::core::TunnelPool> GetTunnelPool() const;

  void HandleI2NPMessage(
      const std::uint8_t* buf,
      std::size_t len,
      std::shared_ptr<kovri::core::InboundTunnel> from);

  // override GarlicDestination
  void ProcessGarlicMessage(
      std::shared_ptr<kovri::core::I2NPMessage> msg);

  void ProcessDeliveryStatusMessage(
      std::shared_ptr<kovri::core::I2NPMessage> msg);

  /// @brief Core router traits/options
  const boost::program_options::variables_map& GetOpts() const
  {
    return m_Opts;
  }

  /// @return root directory path
  const std::string& GetCustomDataDir() const
  {
    return m_CustomDataDir;
  }

  /// @brief Sets root directory path : Should not be called after Init
  void SetCustomDataDir(const std::string& dir)
  {
    m_CustomDataDir = dir;
  }

 private:
  void UpdateRouterInfo();
  void RemoveTransport(core::RouterInfo::Transport transport);

 private:
  kovri::core::RouterInfo m_RouterInfo;
  kovri::core::PrivateKeys m_Keys;
  std::uint64_t m_LastUpdateTime;
  bool m_AcceptsTunnels;
  std::uint64_t m_StartupTime;  // in seconds since epoch
  RouterState m_State;
  std::mutex m_GarlicMutex;
  std::string m_CustomDataDir;
  boost::program_options::variables_map m_Opts;
};

extern RouterContext context;

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_CONTEXT_H_
