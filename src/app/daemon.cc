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

#include "app/daemon.h"

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "app/util/config.h"

#include "client/api/streaming.h"
#include "client/context.h"
#include "client/destination.h"

#include "core/router/context.h"
#include "core/router/garlic.h"
#include "core/router/info.h"
#include "core/router/net_db/impl.h"
#include "core/router/transports/ntcp/session.h"
#include "core/router/transports/impl.h"
#include "core/router/tunnel/impl.h"

#include "core/util/log.h"

#include "core/version.h"

namespace kovri {
namespace app {

Daemon_Singleton::Daemon_Singleton()
    : m_IsDaemon(kovri::app::var_map["daemon"].as<bool>()),
      m_IsRunning(true) {}

Daemon_Singleton::~Daemon_Singleton() {}

bool Daemon_Singleton::Init() {
  // We must initialize contexts here (in child process, if in daemon mode)
  try {
    LogPrint(eLogDebug, "Daemon_Singleton: initializing router context");
    InitRouterContext();
    LogPrint(eLogDebug, "Daemon_Singleton: initializing client context");
    InitClientContext();
  } catch (const std::exception& ex) {
    LogPrint(eLogError,
        "Daemon_Singleton: exception during initialization: ", ex.what());
    return false;
  } catch (...) {
    LogPrint(eLogError,
        "Daemon_Singleton: unknown exception during initialization");
    return false;
  }
  return true;
}

// TODO(anonimal): layout logic and style

bool Daemon_Singleton::Start() {
  try {
    LogPrint(eLogInfo, "Daemon_Singleton: starting NetDb");
    if (!kovri::core::netdb.Start()) {
      LogPrint(eLogError, "Daemon_Singleton: NetDb failed to start");
      return false;
    }
    if (kovri::core::netdb.GetNumRouters() < kovri::core::netdb.MIN_REQUIRED_ROUTERS) {
      LogPrint(eLogInfo, "Daemon_Singleton: reseeding NetDb");
      kovri::client::Reseed reseed;
      if (!reseed.Start()) {
        LogPrint(eLogError, "Daemon_Singleton: reseed failed");
        return false;
      }
    }
    LogPrint(eLogInfo, "Daemon_Singleton: starting transports");
    kovri::core::transports.Start();
    LogPrint(eLogInfo, "Daemon_Singleton: starting tunnels");
    kovri::core::tunnels.Start();
    LogPrint(eLogInfo, "Daemon_Singleton: starting client");
    kovri::client::context.Start();
  } catch (std::runtime_error& e) {
    LogPrint(eLogError, "Daemon_Singleton: runtime start exception: ", e.what());
    return false;
  }  // TODO(anonimal): catch all
  return true;
}

bool Daemon_Singleton::Stop() {
  try {
    LogPrint(eLogInfo, "Daemon_Singleton: stopping client");
    kovri::client::context.Stop();
    LogPrint(eLogInfo, "Daemon_Singleton: stopping tunnels");
    kovri::core::tunnels.Stop();
    LogPrint(eLogInfo, "Daemon_Singleton: stopping transports");
    kovri::core::transports.Stop();
    LogPrint(eLogInfo, "Daemon_Singleton: stopping NetDb");
    kovri::core::netdb.Stop();
    LogPrint(eLogInfo, "Goodbye!");
  } catch (std::runtime_error& e) {
    LogPrint(eLogError, "Daemon_Singleton: runtime stop exception: ", e.what());
    return false;
  }
  return true;
}

void Daemon_Singleton::Reload() {
  // TODO(unassigned): do we want to add locking?
  LogPrint(eLogInfo, "Daemon_Singleton: reloading configuration");
  // reload tunnels.conf
  ReloadTunnels();
  // TODO(unassigned): reload kovri.conf
}
// TODO(anonimal): cleanup initialization style
void Daemon_Singleton::InitRouterContext() {
  kovri::context.Init(
      kovri::app::var_map["host"].as<std::string>(),
      kovri::app::var_map["port"].as<int>());
  auto port = kovri::app::var_map["port"].as<int>();
  kovri::context.UpdatePort(port);
  LogPrint(eLogInfo,
      "Daemon_Singleton: listening on port ",
      kovri::app::var_map["port"].as<int>());
  kovri::context.UpdateAddress(
      boost::asio::ip::address::from_string(
          kovri::app::var_map["host"].as<std::string>()));
  kovri::context.SetSupportsV6(
      kovri::app::var_map["v6"].as<bool>());
  kovri::context.SetFloodfill(
      kovri::app::var_map["floodfill"].as<bool>());
  auto bandwidth = kovri::app::var_map["bandwidth"].as<std::string>();
  if (bandwidth.length() > 0) {
    if (bandwidth[0] > 'L')
      kovri::context.SetHighBandwidth();
    else
      kovri::context.SetLowBandwidth();
  }
  // Set reseed options
  kovri::context.SetOptionReseedFrom(
      kovri::app::var_map["reseed-from"].as<std::string>());
  kovri::context.SetOptionReseedSkipSSLCheck(
      kovri::app::var_map["reseed-skip-ssl-check"].as<bool>());
  // Set transport options
  kovri::context.SetSupportsNTCP(
      kovri::app::var_map["enable-ntcp"].as<bool>());
  kovri::context.SetSupportsSSU(
      kovri::app::var_map["enable-ssu"].as<bool>());
}

// TODO(anonimal): cleanup initialization style
void Daemon_Singleton::InitClientContext() {
  kovri::client::context.RegisterShutdownHandler(
      [this]() { m_IsRunning = false; });
  std::shared_ptr<kovri::client::ClientDestination> local_destination;
  // Setup proxies and services
  auto proxy_keys =
    kovri::app::var_map["proxykeys"].as<std::string>();
  if (proxy_keys.length() > 0)
    local_destination = kovri::client::context.LoadLocalDestination(
        proxy_keys,
        false);
  kovri::client::context.SetHTTPProxy(std::make_unique<kovri::client::HTTPProxy>(
      "HTTP Proxy",  // TODO(unassigned): what if we want to change the name?
      kovri::app::var_map["httpproxyaddress"].as<std::string>(),
      kovri::app::var_map["httpproxyport"].as<int>(),
      local_destination));
  kovri::client::context.SetSOCKSProxy(std::make_unique<kovri::client::SOCKSProxy>(
      kovri::app::var_map["socksproxyaddress"].as<std::string>(),
      kovri::app::var_map["socksproxyport"].as<int>(),
      local_destination));
  auto i2pcontrol_port = kovri::app::var_map["i2pcontrolport"].as<int>();
  if (i2pcontrol_port) {
    kovri::client::context.SetI2PControlService(
        std::make_unique<kovri::client::I2PControlService>(
            kovri::client::context.GetIoService(),
            kovri::app::var_map["i2pcontroladdress"].as<std::string>(),
            i2pcontrol_port,
            kovri::app::var_map["i2pcontrolpassword"].as<std::string>()));
  }
  // Setup client and server tunnels
  SetupTunnels();
}

void Daemon_Singleton::SetupTunnels() {
  boost::property_tree::ptree pt;
  auto path_tunnels_config_file =
    kovri::app::GetTunnelsConfigFile().string();
  try {
    boost::property_tree::read_ini(path_tunnels_config_file, pt);
  } catch(const std::exception& ex) {
    LogPrint(eLogWarn,
        "Daemon_Singleton: can't read ",
        path_tunnels_config_file, ": ", ex.what());
    return;
  }
  int num_client_tunnels = 0, num_server_tunnels = 0;
  for (auto& section : pt) {
    const auto name = section.first;
    const auto& value = section.second;
    try {
      auto type = value.get<std::string>(I2P_TUNNELS_SECTION_TYPE);
      // Test which type of tunnel (client or server)
      if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT) {
        // Mandatory parameters
        auto dest = value.get<std::string>(I2P_CLIENT_TUNNEL_DESTINATION);
        auto port = value.get<int>(I2P_CLIENT_TUNNEL_PORT);
        // Optional parameters
        auto address = value.get(I2P_CLIENT_TUNNEL_ADDRESS, "127.0.0.1");
        auto keys = value.get(I2P_CLIENT_TUNNEL_KEYS, "");
        auto destination_port = value.get(I2P_CLIENT_TUNNEL_DESTINATION_PORT, 0);
        // Get local destination
        std::shared_ptr<kovri::client::ClientDestination> local_destination;
        if (keys.length() > 0)
          local_destination =
            kovri::client::context.LoadLocalDestination(keys, false);
        // Insert client tunnel
        bool result =
          kovri::client::context.InsertClientTunnel(
              port,
              std::make_unique<kovri::client::I2PClientTunnel>(
                  name,
                  dest,
                  address,
                  port,
                  local_destination,
                  destination_port));
        if (result)
          ++num_client_tunnels;
        else
          LogPrint(eLogError,
              "Daemon_Singleton: I2P client tunnel with port ",
              port, " already exists");
      } else if (type == I2P_TUNNELS_SECTION_TYPE_SERVER ||
          type == I2P_TUNNELS_SECTION_TYPE_HTTP) {
        // Mandatory parameters
        auto host = value.get<std::string>(I2P_SERVER_TUNNEL_HOST);
        auto port = value.get<int>(I2P_SERVER_TUNNEL_PORT);
        auto keys = value.get<std::string>(I2P_SERVER_TUNNEL_KEYS);
        // Optional parameters
        auto in_port = value.get(I2P_SERVER_TUNNEL_INPORT, 0);
        auto accessList = value.get(I2P_SERVER_TUNNEL_ACCESS_LIST, "");
        auto local_destination =
          kovri::client::context.LoadLocalDestination(keys, true);
        auto server_tunnel =
          (type == I2P_TUNNELS_SECTION_TYPE_HTTP) ?
            std::make_unique<kovri::client::I2PServerTunnelHTTP>(
                name,
                host,
                port,
                local_destination,
                in_port) :
            std::make_unique<kovri::client::I2PServerTunnel>(
                name,
                host,
                port,
                local_destination,
                in_port);
        server_tunnel->SetAccessListString(accessList);
        // Insert server tunnel
        bool result = kovri::client::context.InsertServerTunnel(
            local_destination->GetIdentHash(),
            std::move(server_tunnel));
        if (result)
          ++num_server_tunnels;
        else
          LogPrint(eLogError,
              "Daemon_Singleton: I2P server tunnel for destination ",
              kovri::client::context.GetAddressBook().GetB32AddressFromIdentHash(
                  local_destination->GetIdentHash()),
              " already exists");
      } else {
        LogPrint(eLogWarn,
            "Daemon_Singleton: unknown section type=",
            type, " of ", name, " in ", path_tunnels_config_file);
      }
    } catch (const std::exception& ex) {
      LogPrint(eLogError,
          "Daemon_Singleton: can't read tunnel ", name, " params: ", ex.what());
    }
  }
  LogPrint(eLogInfo,
      "Daemon_Singleton: ", num_client_tunnels, " I2P client tunnels created");
  LogPrint(eLogInfo,
      "Daemon_Singleton: ", num_server_tunnels, " I2P server tunnels created");
}

void Daemon_Singleton::ReloadTunnels() {
  boost::property_tree::ptree pt;
  auto tunnels_config_file =
    kovri::app::GetTunnelsConfigFile().string();
  try {
    boost::property_tree::read_ini(tunnels_config_file, pt);
  } catch (const std::exception& ex) {
    LogPrint(eLogWarn,
        "Daemon_Singleton: can't read ",
        tunnels_config_file, ": ", ex.what());
    return;
  }
  // List of tunnels that still exist after config update
  // Make sure the default IRC and eepsite tunnels do not get removed
  std::vector<std::string> updated_tunnels;
  // Iterate over tunnels' ident hashes for what's in tunnels.conf now
  for (auto& section : pt) {
    // TODO(unassigned): what if we switch a server from client to tunnel
    // or vice versa?
    const auto tunnel_name = section.first;
    const auto value = section.second;
    const auto type = value.get<std::string>(I2P_TUNNELS_SECTION_TYPE, "");
    if (type == I2P_TUNNELS_SECTION_TYPE_SERVER ||
        type == I2P_TUNNELS_SECTION_TYPE_HTTP) {
      // Obtain server options
      auto key_file = value.get<std::string>(I2P_SERVER_TUNNEL_KEYS, "");
      auto host_str = value.get<std::string>(I2P_SERVER_TUNNEL_HOST, "");
      auto port = value.get<int>(I2P_SERVER_TUNNEL_PORT, 0);
      auto in_port = value.get(I2P_SERVER_TUNNEL_INPORT, 0);
      auto access_list = value.get(I2P_SERVER_TUNNEL_ACCESS_LIST, "");
      kovri::client::context.UpdateServerTunnel(
          tunnel_name,
          key_file,
          host_str,
          access_list,
          port,
          in_port,
          (type == I2P_TUNNELS_SECTION_TYPE_HTTP));
    } else if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT) {
      // Get client tunnel parameters
      auto key_file = value.get(I2P_CLIENT_TUNNEL_KEYS, "");
      auto destination = value.get<std::string>(I2P_CLIENT_TUNNEL_DESTINATION, "");
      auto host_str = value.get(I2P_CLIENT_TUNNEL_ADDRESS, "127.0.0.1");
      auto port = value.get<int>(I2P_CLIENT_TUNNEL_PORT, 0);
      auto dest_port = value.get(I2P_CLIENT_TUNNEL_DESTINATION_PORT, 0);
      auto tunnel = kovri::client::context.GetClientTunnel(port);
      if (tunnel && tunnel->GetName() != tunnel_name) {
        // Conflicting port
        // TODO(unassigned): what if we interchange two client tunnels' ports?
        // TODO(EinMByte): the addresses could differ
        LogPrint(eLogError,
            "Daemon_Singleton: ",
            tunnel_name, " will not be updated, conflicting port");
        continue;
      }
      kovri::client::context.UpdateClientTunnel(
          tunnel_name,
          key_file,
          destination,
          host_str,
          port,
          dest_port);
    }
  }
  kovri::client::context.RemoveServerTunnels(
      [&updated_tunnels](kovri::client::I2PServerTunnel* tunnel) {
        return std::find(
            updated_tunnels.begin(),
            updated_tunnels.end(),
            tunnel->GetName()) == updated_tunnels.end();
      });
  kovri::client::context.RemoveClientTunnels(
      [&updated_tunnels](kovri::client::I2PClientTunnel* tunnel) {
        return std::find(
            updated_tunnels.begin(),
            updated_tunnels.end(),
            tunnel->GetName()) == updated_tunnels.end();
      });
}

}  // namespace app
}  // namespace kovri
