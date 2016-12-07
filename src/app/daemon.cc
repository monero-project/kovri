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

DaemonSingleton::DaemonSingleton()
    : m_IsDaemon(VarMap["daemon"].as<bool>()),
      m_IsRunning(true) {}

DaemonSingleton::~DaemonSingleton() {}

bool DaemonSingleton::Init() {
  // We must initialize contexts here (in child process, if in daemon mode)
  try {
    LogPrint(eLogDebug, "DaemonSingleton: initializing router context");
    InitRouterContext();
    LogPrint(eLogDebug, "DaemonSingleton: initializing client context");
    InitClientContext();
  } catch (const std::exception& ex) {
    LogPrint(eLogError,
        "DaemonSingleton: exception during initialization: ", ex.what());
    return false;
  } catch (...) {
    LogPrint(eLogError,
        "DaemonSingleton: unknown exception during initialization");
    return false;
  }
  return true;
}

void DaemonSingleton::InitRouterContext() {
  auto host = VarMap["host"].as<std::string>();
  auto port = VarMap["port"].as<int>();
  // TODO(unassigned): context should be in core namespace (see TODO in router context)
  context.Init(host, port);
  context.UpdatePort(port);
  LogPrint(eLogInfo,
      "DaemonSingleton: listening on port ", VarMap["port"].as<int>());
  context.UpdateAddress(boost::asio::ip::address::from_string(host));
  context.SetSupportsV6(VarMap["v6"].as<bool>());
  context.SetFloodfill(VarMap["floodfill"].as<bool>());
  auto bandwidth = VarMap["bandwidth"].as<std::string>();
  if (bandwidth.length() > 0) {
    if (bandwidth[0] > 'L')
      context.SetHighBandwidth();
    else
      context.SetLowBandwidth();
  }
  // Set reseed options
  context.SetOptionReseedFrom(VarMap["reseed-from"].as<std::string>());
  context.SetOptionReseedSkipSSLCheck(VarMap["reseed-skip-ssl-check"].as<bool>());
  // Set transport options
  context.SetSupportsNTCP(VarMap["enable-ntcp"].as<bool>());
  context.SetSupportsSSU(VarMap["enable-ssu"].as<bool>());
}

void DaemonSingleton::InitClientContext() {
  kovri::client::context.RegisterShutdownHandler(
      [this]() { m_IsRunning = false; });
  std::shared_ptr<kovri::client::ClientDestination> local_destination;
  // Setup proxies and services
  auto proxy_keys = VarMap["proxykeys"].as<std::string>();
  if (proxy_keys.length() > 0)
    local_destination = kovri::client::context.LoadLocalDestination(
        proxy_keys,
        false);
  kovri::client::context.SetHTTPProxy(std::make_unique<kovri::client::HTTPProxy>(
      "HTTP Proxy",  // TODO(unassigned): what if we want to change the name?
      VarMap["httpproxyaddress"].as<std::string>(),
      VarMap["httpproxyport"].as<int>(),
      local_destination));
  kovri::client::context.SetSOCKSProxy(std::make_unique<kovri::client::SOCKSProxy>(
      VarMap["socksproxyaddress"].as<std::string>(),
      VarMap["socksproxyport"].as<int>(),
      local_destination));
  auto i2pcontrol_port = VarMap["i2pcontrolport"].as<int>();
  if (i2pcontrol_port) {
    kovri::client::context.SetI2PControlService(
        std::make_unique<kovri::client::I2PControlService>(
            kovri::client::context.GetIoService(),
            VarMap["i2pcontroladdress"].as<std::string>(),
            i2pcontrol_port,
            VarMap["i2pcontrolpassword"].as<std::string>()));
  }
  // Setup client and server tunnels
  SetupTunnels();
}

void DaemonSingleton::SetupTunnels() {
  boost::property_tree::ptree pt;
  auto path_tunnels_config_file =
    kovri::app::GetTunnelsConfigFile().string();
  try {
    boost::property_tree::read_ini(path_tunnels_config_file, pt);
  } catch(const std::exception& ex) {
    LogPrint(eLogWarn,
        "DaemonSingleton: can't read ",
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
              "DaemonSingleton: I2P client tunnel with port ",
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
              "DaemonSingleton: I2P server tunnel for destination ",
              kovri::client::context.GetAddressBook().GetB32AddressFromIdentHash(
                  local_destination->GetIdentHash()),
              " already exists");
      } else {
        LogPrint(eLogWarn,
            "DaemonSingleton: unknown section type=",
            type, " of ", name, " in ", path_tunnels_config_file);
      }
    } catch (const std::exception& ex) {
      LogPrint(eLogError,
          "DaemonSingleton: can't read tunnel ", name, " params: ", ex.what());
    }
  }
  LogPrint(eLogInfo,
      "DaemonSingleton: ", num_client_tunnels, " I2P client tunnels created");
  LogPrint(eLogInfo,
      "DaemonSingleton: ", num_server_tunnels, " I2P server tunnels created");
}

bool DaemonSingleton::Start() {
  try {
    LogPrint(eLogInfo, "DaemonSingleton: starting NetDb");
    if (!kovri::core::netdb.Start()) {
      LogPrint(eLogError, "DaemonSingleton: NetDb failed to start");
      return false;
    }
    if (kovri::core::netdb.GetNumRouters() < kovri::core::netdb.MIN_REQUIRED_ROUTERS) {
      LogPrint(eLogInfo, "DaemonSingleton: reseeding NetDb");
      kovri::client::Reseed reseed;
      if (!reseed.Start()) {
        LogPrint(eLogError, "DaemonSingleton: reseed failed");
        return false;
      }
    }
    LogPrint(eLogInfo, "DaemonSingleton: starting transports");
    kovri::core::transports.Start();
    LogPrint(eLogInfo, "DaemonSingleton: starting tunnels");
    kovri::core::tunnels.Start();
    LogPrint(eLogInfo, "DaemonSingleton: starting client");
    kovri::client::context.Start();
  } catch (std::runtime_error& e) {
    LogPrint(eLogError, "DaemonSingleton: runtime start exception: ", e.what());
    return false;
  }  catch (...) {
    LogPrint(eLogError, "DaemonSingleton: unknown exception when starting");
    return false;
  }
  return true;
}

void DaemonSingleton::ReloadTunnels() {
  boost::property_tree::ptree pt;
  auto tunnels_config_file =
    kovri::app::GetTunnelsConfigFile().string();
  try {
    boost::property_tree::read_ini(tunnels_config_file, pt);
  } catch (const std::exception& ex) {
    LogPrint(eLogWarn,
        "DaemonSingleton: can't read ",
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
            "DaemonSingleton: ",
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

void DaemonSingleton::Reload() {
  // TODO(unassigned): do we want to add locking?
  LogPrint(eLogInfo, "DaemonSingleton: reloading configuration");
  // reload tunnels.conf
  ReloadTunnels();
  // TODO(unassigned): reload kovri.conf
}

bool DaemonSingleton::Stop() {
  try {
    LogPrint(eLogInfo, "DaemonSingleton: stopping client");
    kovri::client::context.Stop();
    LogPrint(eLogInfo, "DaemonSingleton: stopping tunnels");
    kovri::core::tunnels.Stop();
    LogPrint(eLogInfo, "DaemonSingleton: stopping transports");
    kovri::core::transports.Stop();
    LogPrint(eLogInfo, "DaemonSingleton: stopping NetDb");
    kovri::core::netdb.Stop();
    LogPrint(eLogInfo, "Goodbye!");
  } catch (std::runtime_error& e) {
    LogPrint(eLogError, "DaemonSingleton: runtime stop exception: ", e.what());
    return false;
  }  catch (...) {
    LogPrint(eLogError, "DaemonSingleton: unknown exception when stopping");
    return false;
  }
  return true;
}

}  // namespace app
}  // namespace kovri
