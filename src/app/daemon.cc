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
    : m_IsDaemon(false),
      m_IsRunning(true),
      m_IsReloading(false),
      m_Config(std::make_unique<Configuration>()) {}

DaemonSingleton::~DaemonSingleton() {}

bool DaemonSingleton::Config(int argc, const char* argv[]) {
  try {
    // Get all kovri configuration data, cli args first then config file second
    if (!m_Config->ParseKovriConfig(argc, argv)) {
      // User simply wanted help option
      return false;
    }
    // Set daemon mode (if applicable)
    m_IsDaemon = m_Config->GetParsedKovriConfig().at("daemon").as<bool>();
    // Get all tunnels configuration data
    m_Config->ParseTunnelsConfig();
  } catch (const std::exception& ex) {
    LogPrint(eLogError, "DaemonSingleton: ", ex.what(), "\nHave you tried --help?");
    return false;
  } catch (...) {
    LogPrint(eLogError, "DaemonSingleton: unknown exception when parsing args");
    return false;
  }
  return true;
}

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

// TODO(anonimal): consider unhooking from singleton
void DaemonSingleton::InitRouterContext() {
  auto map = m_Config->GetParsedKovriConfig();
  auto host = map["host"].as<std::string>();
  auto port = map["port"].as<int>();
  // TODO(unassigned): context should be in core namespace (see TODO in router context)
  context.Init(host, port);
  context.UpdatePort(port);
  LogPrint(eLogInfo,
      "DaemonSingleton: listening on port ", map["port"].as<int>());
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
  context.SetOptionReseedSkipSSLCheck(map["reseed-skip-ssl-check"].as<bool>());
  // Set transport options
  context.SetSupportsNTCP(map["enable-ntcp"].as<bool>());
  context.SetSupportsSSU(map["enable-ssu"].as<bool>());
}

// TODO(anonimal): consider unhooking from singleton
void DaemonSingleton::InitClientContext() {
  kovri::client::context.RegisterShutdownHandler(
      [this]() { m_IsRunning = false; });
  std::shared_ptr<kovri::client::ClientDestination> local_destination;
  // Setup proxies and services
  auto map = m_Config->GetParsedKovriConfig();
  auto proxy_keys = map["proxykeys"].as<std::string>();
  if (!proxy_keys.empty())
    local_destination = kovri::client::context.LoadLocalDestination(
        proxy_keys,
        false);
  kovri::client::context.SetHTTPProxy(std::make_unique<kovri::client::HTTPProxy>(
      "HTTP Proxy",  // TODO(unassigned): what if we want to change the name?
      map["httpproxyaddress"].as<std::string>(),
      map["httpproxyport"].as<int>(),
      local_destination));
  kovri::client::context.SetSOCKSProxy(std::make_unique<kovri::client::SOCKSProxy>(
      map["socksproxyaddress"].as<std::string>(),
      map["socksproxyport"].as<int>(),
      local_destination));
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

// TODO(anonimal): consider unhooking from singleton
void DaemonSingleton::SetupTunnels() {
  // List of tunnels that exist after update
  // TODO(unassigned): ensure that default IRC and eepsite tunnels aren't removed?
  std::vector<std::string> updated_tunnels;  // TODO(unassigned): this was never fully implemented
  // Count number of tunnels
  std::size_t client_count = 0, server_count = 0;
  // Iterate through each section in tunnels config
  for (auto const& tunnel : m_Config->GetParsedTunnelsConfig()) {
    try {
      // Test which type of tunnel (client or server)
      if (tunnel.type == TunnelsMap.at(TunnelsKey::Client)) {
        if (m_IsReloading) {
          auto client_tunnel = kovri::client::context.GetClientTunnel(tunnel.port);
          if (client_tunnel && client_tunnel->GetName() != tunnel.name) {
            // Conflicting port
            // TODO(unassigned): what if we interchange two client tunnels' ports?
            // TODO(unassigned): the addresses could differ
            LogPrint(eLogError,
                "DaemonSingleton: ",
                tunnel.name, " will not be updated, conflicting port");
            continue;
          }
          // TODO(unassigned): this should be passing a structure
          kovri::client::context.UpdateClientTunnel(
              tunnel.name,
              tunnel.keys,
              tunnel.dest,
              tunnel.host,
              tunnel.port,
              tunnel.dest_port);
	  ++client_count;
	  continue;
        }
        // Get local destination
        std::shared_ptr<kovri::client::ClientDestination> local_destination;
        if (!tunnel.keys.empty())
          local_destination =
            kovri::client::context.LoadLocalDestination(tunnel.keys, false);
        // Insert client tunnel
        bool result =
          kovri::client::context.InsertClientTunnel(
              tunnel.port,
              // TODO(unassigned): this should be passing a structure
              std::make_unique<kovri::client::I2PClientTunnel>(
                  tunnel.name,
                  tunnel.dest,
                  tunnel.address,
                  tunnel.port,
                  local_destination,
                  tunnel.dest_port));
        if (result)
          ++client_count;
        else
          LogPrint(eLogError,
              "DaemonSingleton: client tunnel with port ",
              tunnel.port, " already exists");
      } else {  // TODO(unassigned): currently anything that's not client is server
	if (m_IsReloading) {
          // TODO(unassigned): this should be passing a structure
          kovri::client::context.UpdateServerTunnel(
              tunnel.name,
              tunnel.keys,
              tunnel.host,
              tunnel.access_list,
              tunnel.port,
              tunnel.in_port,
              (tunnel.type == TunnelsMap.at(TunnelsKey::HTTP)));
	  ++server_count;
	  continue;
        }
        auto local_destination =
          kovri::client::context.LoadLocalDestination(tunnel.keys, true);
        auto server_tunnel = (tunnel.type == TunnelsMap.at(TunnelsKey::HTTP))
            // TODO(unassigned): these should be passing a structure
          ? std::make_unique<kovri::client::I2PServerTunnelHTTP>(
                tunnel.name,
                tunnel.host,
                tunnel.port,
                local_destination,
                tunnel.in_port)
          : std::make_unique<kovri::client::I2PServerTunnel>(
                tunnel.name,
                tunnel.host,
                tunnel.port,
                local_destination,
                tunnel.in_port);
        server_tunnel->SetAccessListString(tunnel.access_list);
        // Insert server tunnel
        bool result = kovri::client::context.InsertServerTunnel(
            local_destination->GetIdentHash(),
            std::move(server_tunnel));
        if (result) {
          ++server_count;
        } else {
          LogPrint(eLogError,
              "DaemonSingleton: server tunnel for destination ",
              kovri::client::context.GetAddressBook().GetB32AddressFromIdentHash(
                  local_destination->GetIdentHash()),
              " already exists");
	}
      }
    } catch (const std::exception& ex) {
      LogPrint(eLogError,
          "DaemonSingleton: exception during tunnel setup: ", ex.what());
      return;
    } catch (...) {
      LogPrint(eLogError,
          "DaemonSingleton: unknown exception during tunnel setup");
      return;
    }
  }  // end of iteration block
  if (m_IsReloading) {
    LogPrint(eLogInfo,
        "DaemonSingleton: ", client_count, " client tunnels updated");
    LogPrint(eLogInfo,
        "DaemonSingleton: ", server_count, " server tunnels updated");
    // TODO(unassigned): this was never fully implemented
    RemoveOldTunnels(updated_tunnels);
    return;
  }
  LogPrint(eLogInfo,
      "DaemonSingleton: ", client_count, " client tunnels created");
  LogPrint(eLogInfo,
      "DaemonSingleton: ", server_count, " server tunnels created");
}

// TODO(anonimal): consider unhooking from singleton
void DaemonSingleton::RemoveOldTunnels(
    std::vector<std::string>& updated_tunnels) {
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

void DaemonSingleton::Reload() {
  // TODO(unassigned): do we want to add locking?
  LogPrint(eLogInfo, "DaemonSingleton: reloading configuration");
  // Reload tunnels configuration
  m_IsReloading = true;
  // TODO(anonimal): consider unhooking from singleton
  SetupTunnels();
  m_IsReloading = false;
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
