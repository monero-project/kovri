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

#include "daemon.h"

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "client/client_context.h"
#include "destination.h"
#include "garlic.h"
#include "net_db.h"
#include "router_context.h"
#include "router_info.h"
#include "version.h"
#include "streaming.h"
#include "core/util/log.h"
#include "transport/ntcp_session.h"
#include "transport/transports.h"
#include "tunnel/tunnel.h"
#include "util/config.h"

namespace i2p {
namespace util {

Daemon_Singleton::Daemon_Singleton()
    : m_IsDaemon(false),
      m_IsRunning(true) {}

Daemon_Singleton::~Daemon_Singleton() {}

// TODO(anonimal): find a better way to initialize
bool Daemon_Singleton::Init() {
  LogPrint(eLogInfo, "Daemon_Singleton: initializing");
  i2p::context.Init(
      i2p::util::config::var_map["host"].as<std::string>(),
      i2p::util::config::var_map["port"].as<int>(),
      i2p::util::filesystem::GetDataPath());
  m_IsDaemon = i2p::util::config::var_map["daemon"].as<bool>();
  auto port = i2p::util::config::var_map["port"].as<int>();
  i2p::context.UpdatePort(port);
  i2p::context.UpdateAddress(
      boost::asio::ip::address::from_string(
          i2p::util::config::var_map["host"].as<std::string>()));
  i2p::context.SetSupportsV6(
      i2p::util::config::var_map["v6"].as<bool>());
  i2p::context.SetFloodfill(
      i2p::util::config::var_map["floodfill"].as<bool>());
  auto bandwidth = i2p::util::config::var_map["bandwidth"].as<std::string>();
  if (bandwidth.length() > 0) {
    if (bandwidth[0] > 'L')
      i2p::context.SetHighBandwidth();
    else
      i2p::context.SetLowBandwidth();
  }
  // Set reseed options
  // TODO(anonimal): rename as SetOption*
  i2p::context.ReseedFrom(
      i2p::util::config::var_map["reseed-from"].as<std::string>());
  i2p::context.ReseedSkipSSLCheck(
      i2p::util::config::var_map["reseed-skip-ssl-check"].as<bool>());
  // Initialize the ClientContext
  InitClientContext();
  return true;
}

bool Daemon_Singleton::Start() {
  LogPrint(eLogInfo,
      "Daemon_Singleton: listening on port ",
      i2p::util::config::var_map["port"].as<int>());
  try {
    LogPrint(eLogInfo, "Daemon_Singleton: starting NetDb");
    if (!i2p::data::netdb.Start()) {
      LogPrint(eLogError, "Daemon_Singleton: NetDb failed to start");
      return false;
    }
    LogPrint(eLogInfo, "Daemon_Singleton: starting transports");
    i2p::transport::transports.Start();
    LogPrint(eLogInfo, "Daemon_Singleton: starting tunnels");
    i2p::tunnel::tunnels.Start();
    LogPrint(eLogInfo, "Daemon_Singleton: starting client");
    i2p::client::context.Start();
  } catch (std::runtime_error& e) {
    LogPrint(eLogError, "Daemon_Singleton: exception: ", e.what());
    return false;
  }
  return true;
}

bool Daemon_Singleton::Stop() {
  LogPrint(eLogInfo, "Daemon_Singleton: stopping client");
  i2p::client::context.Stop();
  LogPrint(eLogInfo, "Daemon_Singleton: stopping tunnels");
  i2p::tunnel::tunnels.Stop();
  LogPrint(eLogInfo, "Daemon_Singleton: stopping transports");
  i2p::transport::transports.Stop();
  LogPrint(eLogInfo, "Daemon_Singleton: stopping NetDb");
  i2p::data::netdb.Stop();
  LogPrint(eLogInfo, "Goodbye!");
  return true;
}

void Daemon_Singleton::Reload() {
  // TODO(unassigned): do we want to add locking?
  LogPrint(eLogInfo, "Daemon_Singleton: reloading configuration");
  // reload tunnels.conf
  ReloadTunnels();
  // TODO(unassigned): reload kovri.conf
}

void Daemon_Singleton::InitClientContext() {
  i2p::client::context.RegisterShutdownHandler(
      [this]() { m_IsRunning = false; });
  std::shared_ptr<i2p::client::ClientDestination> local_destination;
  // Setup proxies and services
  auto proxy_keys =
    i2p::util::config::var_map["proxykeys"].as<std::string>();
  if (proxy_keys.length() > 0)
    local_destination = i2p::client::context.LoadLocalDestination(
        proxy_keys,
        false);
  i2p::client::context.SetHTTPProxy(std::make_unique<i2p::proxy::HTTPProxy>(
      "HTTP Proxy",  // TODO(unassigned): what if we want to change the name?
      i2p::util::config::var_map["httpproxyaddress"].as<std::string>(),
      i2p::util::config::var_map["httpproxyport"].as<int>(),
      local_destination));
  i2p::client::context.SetSOCKSProxy(std::make_unique<i2p::proxy::SOCKSProxy>(
      i2p::util::config::var_map["socksproxyaddress"].as<std::string>(),
      i2p::util::config::var_map["socksproxyport"].as<int>(),
      local_destination));
  auto i2pcontrol_port = i2p::util::config::var_map["i2pcontrolport"].as<int>();
  if (i2pcontrol_port) {
    i2p::client::context.SetI2PControlService(
        std::make_unique<i2p::client::i2pcontrol::I2PControlService>(
            i2p::client::context.GetIoService(),
            i2p::util::config::var_map["i2pcontroladdress"].as<std::string>(),
            i2pcontrol_port,
            i2p::util::config::var_map["i2pcontrolpassword"].as<std::string>()));
  }
  // Setup client and server tunnels
  SetupTunnels();
}

void Daemon_Singleton::SetupTunnels() {
  boost::property_tree::ptree pt;
  auto path_tunnels_config_file =
    i2p::util::filesystem::GetTunnelsConfigFile().string();
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
        std::shared_ptr<i2p::client::ClientDestination> local_destination;
        if (keys.length() > 0)
          local_destination =
            i2p::client::context.LoadLocalDestination(keys, false);
        // Insert client tunnel
        bool result =
          i2p::client::context.InsertClientTunnel(
              port,
              std::make_unique<i2p::client::I2PClientTunnel>(
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
          i2p::client::context.LoadLocalDestination(keys, true);
        auto server_tunnel =
          (type == I2P_TUNNELS_SECTION_TYPE_HTTP) ?
            std::make_unique<i2p::client::I2PServerTunnelHTTP>(
                name,
                host,
                port,
                local_destination,
                in_port) :
            std::make_unique<i2p::client::I2PServerTunnel>(
                name,
                host,
                port,
                local_destination,
                in_port);
        server_tunnel->SetAccessListString(accessList);
        // Insert server tunnel
        bool result = i2p::client::context.InsertServerTunnel(
            local_destination->GetIdentHash(),
            std::move(server_tunnel));
        if (result)
          ++num_server_tunnels;
        else
          LogPrint(eLogError,
              "Daemon_Singleton: I2P server tunnel for destination ",
              i2p::client::context.GetAddressBook().ToAddress(
                  local_destination->GetIdentHash()),
              " already exists");
      } else {
        LogPrint(eLogWarn,
            "Daemon_Singleton: unknown section type=",
            type, " of ", name, " in ", path_tunnels_config_file);
      }
    } catch(const std::exception& ex) {
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
    i2p::util::filesystem::GetTunnelsConfigFile().string();
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
      auto accessList = value.get(I2P_SERVER_TUNNEL_ACCESS_LIST, "");
      i2p::client::context.UpdateServerTunnel(
          tunnel_name,
          key_file,
          host_str,
          accessList,
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
      auto tunnel = i2p::client::context.GetClientTunnel(port);
      if (tunnel && tunnel->GetName() != tunnel_name) {
        // Conflicting port
        // TODO(unassigned): what if we interchange two client tunnels' ports?
        // TODO(EinMByte): the addresses could differ
        LogPrint(eLogError,
            "Daemon_Singleton: ",
            tunnel_name, " will not be updated, conflicting port");
        continue;
      }
      i2p::client::context.UpdateClientTunnel(
          tunnel_name,
          key_file,
          destination,
          host_str,
          port,
          dest_port);
    }
  }
  i2p::client::context.RemoveServerTunnels(
      [&updated_tunnels](i2p::client::I2PServerTunnel* tunnel) {
        return std::find(
            updated_tunnels.begin(),
            updated_tunnels.end(),
            tunnel->GetName()) == updated_tunnels.end();
      });
  i2p::client::context.RemoveClientTunnels(
      [&updated_tunnels](i2p::client::I2PClientTunnel* tunnel) {
        return std::find(
            updated_tunnels.begin(),
            updated_tunnels.end(),
            tunnel->GetName()) == updated_tunnels.end();
      });
}

}  // namespace util
}  // namespace i2p
