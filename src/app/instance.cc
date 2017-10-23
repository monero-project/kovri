/**                                                                                           //
 * Copyright (c) 2015-2017, The Kovri I2P Router Project                                      //
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

#include "app/instance.h"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

#include <cstdint>
#include <stdexcept>
#include <memory>

#include "client/context.h"

#include "core/crypto/aes.h"  // For AES-NI detection/initialization

#include "core/router/context.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/impl.h"
#include "core/router/tunnel/impl.h"

#include "core/util/log.h"

#include "version.h"

namespace kovri {
namespace app {

Instance::Instance(const std::vector<std::string>& args) try
    : m_Config(args),
      m_IsReloading(false),
      m_Exception(__func__)
  {
    Configure();
  }
catch (...)
  {
    m_Exception.Dispatch("could not construct");
  }

Instance::~Instance() {}

void Instance::Configure() {
  // TODO(anonimal): instance configuration should probably be moved to libcore
  m_Config.ParseKovriConfig();
  // TODO(anonimal): Initializing of sources/streams/sinks must come after we've properly configured the logger.
  //   we do this here so we can catch debug logging before instance "initialization". This is not ideal
  core::SetupLogging(m_Config.GetParsedKovriConfig());
  // Log the banner
  LOG(info) << "The Kovri I2P Router Project";
  LOG(info) << KOVRI_VERSION << "-" << KOVRI_GIT_REVISION << " \"" << KOVRI_CODENAME << "\"";
  // Continue with configuration/setup
  m_Config.SetupAESNI();
  m_Config.ParseTunnelsConfig();
}

// Note: we'd love Instance RAII but singleton needs to be daemonized (if applicable) before initialization
void Instance::Initialize() {
  // TODO(anonimal): what use-case to unhook contexts from an instance? Alternate client/core implementations?
  InitClientContext();
  InitRouterContext();
}

// TODO(unassigned): see TODO's for router/client context and singleton
void Instance::InitRouterContext() {
  LOG(debug) << "Instance: initializing router context";
  auto map = m_Config.GetParsedKovriConfig();
  auto host = map["host"].as<std::string>();
  // Random generated port if none is supplied via CLI or config
  // See: i2p.i2p/router/java/src/net/i2p/router/transport/udp/UDPEndpoint.java
  auto port = map["port"].defaulted()
                  ? kovri::core::RandInRange32(
                        core::RouterInfo::MinPort, core::RouterInfo::MaxPort)
                  : map["port"].as<int>();
  // TODO(unassigned): context should be in core namespace (see TODO in router context)
  context.Init(host, port);
  context.UpdatePort(port);
  LOG(info) << "Instance: listening on port " << map["port"].as<int>();
  context.UpdateAddress(boost::asio::ip::address::from_string(host));
  context.SetSupportsV6(map["v6"].as<bool>());
  context.SetFloodfill(map["floodfill"].as<bool>());
  auto bandwidth = map["bandwidth"].as<std::string>();
  if (!bandwidth.empty()) {
    if (bandwidth[0] > 'L')
      context.SetHighBandwidth();
    else
      context.SetLowBandwidth();
  }
  // Set reseed options
  context.SetOptionReseedFrom(map["reseed-from"].as<std::string>());
  context.SetOptionDisableSU3Verification(
      map["disable-su3-verification"].as<bool>());
  // Set transport options
  context.SetSupportsNTCP(map["enable-ntcp"].as<bool>());
  context.SetSupportsSSU(map["enable-ssu"].as<bool>());
  // Set SSL option
  context.SetOptionEnableSSL(map["enable-ssl"].as<bool>());
}

// TODO(unassigned): see TODO's for router/client context and singleton
void Instance::InitClientContext() {
  LOG(debug) << "Instance: initializing client context";
  // TODO(unassigned): a useful shutdown handler but needs to callback to daemon
  // singleton's member. It's only used for I2PControl (and currently doesn't work)
  // so we'll have to figure out another way to *not* rely on the singleton to
  // tell the contexts to shutdown. Note: previous to refactor work, the shutdown handler
  // (or related) was not fully functional (for possible threading reasons), so
  // commenting out this function does not provide any loss in functionality.
  /*kovri::client::context.RegisterShutdownHandler(
    [this]() { m_IsRunning = false; });*/
  // Initialize proxies
  std::shared_ptr<kovri::client::ClientDestination> local_destination;
  auto map = m_Config.GetParsedKovriConfig();
  auto proxy_keys = map["proxykeys"].as<std::string>();
  if (!proxy_keys.empty())
    local_destination =
      kovri::client::context.LoadLocalDestination(proxy_keys, false);
  kovri::client::context.SetHTTPProxy(
      std::make_unique<kovri::client::HTTPProxy>(
          "HTTP Proxy",  // TODO(unassigned): what if we want to change the name?
          map["httpproxyaddress"].as<std::string>(),
          map["httpproxyport"].as<int>(),
          local_destination));
  kovri::client::context.SetSOCKSProxy(
      std::make_unique<kovri::client::SOCKSProxy>(
          map["socksproxyaddress"].as<std::string>(),
          map["socksproxyport"].as<int>(),
          local_destination));
  // Initialize I2PControl
  auto i2pcontrol_port = map["i2pcontrolport"].as<int>();
  if (i2pcontrol_port) {
    kovri::client::context.SetI2PControlService(
        std::make_unique<kovri::client::I2PControlService>(
            kovri::client::context.GetIoService(),
            map["i2pcontroladdress"].as<std::string>(),
            i2pcontrol_port,
            map["i2pcontrolpassword"].as<std::string>()));
  }
  // Setup client and server tunnels
  SetupTunnels();
}

void Instance::SetupTunnels() {
  // List of tunnels that exist after update
  std::vector<std::string> updated_client_tunnels, updated_server_tunnels;
  // Count number of tunnels
  std::size_t client_count = 0, server_count = 0;
  // Iterate through each section in tunnels config
  for (auto const& tunnel : m_Config.GetParsedTunnelsConfig()) {
    try {
      // Test which type of tunnel (client or server)
      if (tunnel.type == m_Config.GetAttribute(Key::Client)
          ||tunnel.type == m_Config.GetAttribute(Key::IRC)) {  // TODO(unassigned): see #9
        if (m_IsReloading) {
          auto client_tunnel = kovri::client::context.GetClientTunnel(tunnel.port);
          if (client_tunnel && client_tunnel->GetName() != tunnel.name)
            {
              // Check for conflicting port done in ParseTunnelsConfig
              // early deletion of client_tunnel to avoid temp duplicate port bind
              std::string name = client_tunnel->GetName();
              LOG(debug) << "ClientContext: Premature delete tunnel " << name;
              kovri::client::context.RemoveClientTunnels(
                  [&name](kovri::client::I2PClientTunnel* old_tunnel) {
                    return name == old_tunnel->GetName();
                  });
            }
          kovri::client::context.UpdateClientTunnel(tunnel);
          updated_client_tunnels.push_back(tunnel.name);
          ++client_count;
          continue;
        }
        // Create client tunnel
        if (kovri::client::context.AddClientTunnel(tunnel))
          ++client_count;
        else
          LOG(error) << "Instance: client tunnel with port " << tunnel.port
                     << " already exists";
      } else {  // TODO(unassigned): currently, anything that's not client
        bool is_http = (tunnel.type == m_Config.GetAttribute(Key::HTTP));
        if (m_IsReloading) {
          kovri::client::context.UpdateServerTunnel(tunnel, is_http);
          updated_server_tunnels.push_back(tunnel.name);
          ++server_count;
          continue;
        }
        if (kovri::client::context.AddServerTunnel(tunnel, is_http))
          ++server_count;
        else
          LOG(error) << "Instance: Failed to add server tunnel";
      }
    }
    catch (...)
      {
        kovri::core::Exception ex;
        ex.Dispatch(__func__);
        return;
      }
  }  // end of iteration block
  if (m_IsReloading) {
    LOG(info) << "Instance: " << client_count << " client tunnels updated";
    LOG(info) << "Instance: " << server_count << " server tunnels updated";
    RemoveOldTunnels(updated_client_tunnels, updated_server_tunnels);
    return;
  }
  LOG(info) << "Instance: " << client_count << " client tunnels created";
  LOG(info) << "Instance: " << server_count << " server tunnels created";
}

void Instance::RemoveOldTunnels(
    const std::vector<std::string>& updated_client_tunnels,
    const std::vector<std::string>& updated_server_tunnels)
{
  kovri::client::context.RemoveServerTunnels(
      [&updated_server_tunnels](kovri::client::I2PServerTunnel* tunnel) {
        return std::find(
                   updated_server_tunnels.begin(),
                   updated_server_tunnels.end(),
                   tunnel->GetTunnelAttributes().name)
               == updated_server_tunnels.end();
      });
  kovri::client::context.RemoveClientTunnels(
      [&updated_client_tunnels](kovri::client::I2PClientTunnel* tunnel) {
        return std::find(
                   updated_client_tunnels.begin(),
                   updated_client_tunnels.end(),
                   tunnel->GetTunnelAttributes().name)
               == updated_client_tunnels.end();
      });
}

void Instance::Start()
{
  try
    {
      LOG(debug) << "Instance: starting NetDb";

      // NetDb
      if (!kovri::core::netdb.Start())
        throw std::runtime_error("Instance: NetDb failed to start");

      // Reseed
      if (core::netdb.GetNumRouters() < core::NetDb::Size::MinRequiredRouters)
        {
          LOG(debug) << "Instance: reseeding NetDb";
          kovri::client::Reseed reseed;
          if (!reseed.Start())
            throw std::runtime_error("Instance: reseed failed");
        }

      LOG(debug) << "Instance: starting transports";
      kovri::core::transports.Start();

      LOG(debug) << "Instance: starting tunnels";
      kovri::core::tunnels.Start();

      LOG(debug) << "Instance: starting client";
      kovri::client::context.Start();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }

  LOG(info) << "Instance: successfully started";
}

void Instance::Stop()
{
  try
    {
      LOG(debug) << "Instance: stopping client";
      kovri::client::context.Stop();

      LOG(debug) << "Instance: stopping tunnels";
      kovri::core::tunnels.Stop();

      LOG(debug) << "Instance: stopping transports";
      kovri::core::transports.Stop();

      LOG(debug) << "Instance: stopping NetDb";
      kovri::core::netdb.Stop();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }

  LOG(info) << "Instance: successfully stopped";
}

void Instance::Reload() {
  LOG(info) << "Instance: reloading";
  // TODO(unassigned): reload kovri.conf
  // TODO(unassigned): locking etc.
  // TODO(unassigned): client/router contexts
  m_IsReloading = true;
  m_Config.ParseTunnelsConfig();
  SetupTunnels();
  m_IsReloading = false;
}

}  // namespace app
}  // namespace kovri
