/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
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
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#include "Daemon.h"

#include <string>
#include <vector>
#include <thread>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "client/ClientContext.h"
#include "Destination.h"
#include "Garlic.h"
#include "NetworkDatabase.h"
#include "RouterContext.h"
#include "RouterInfo.h"
#include "Version.h"
#include "Streaming.h"
#include "core/util/Log.h"
#include "transport/NTCPSession.h"
#include "transport/Transports.h"
#include "tunnel/Tunnel.h"
#include "util/Config.h"

namespace i2p {
namespace util {

Daemon_Singleton::Daemon_Singleton()
    : m_IsRunning(true),
      m_log(i2p::util::log::Log::Get()) {}
Daemon_Singleton::~Daemon_Singleton() {}

bool Daemon_Singleton::IsService() const {
#ifndef _WIN32
  return i2p::util::config::var_map["service"].as<bool>();
#else
  return false;
#endif
}

// TODO(anonimal): find a better way to initialize
bool Daemon_Singleton::Init() {
  i2p::context.Init(
      i2p::util::config::var_map["host"].as<std::string>(),
      i2p::util::config::var_map["port"].as<int>(),
      i2p::util::filesystem::GetDataPath());
  m_IsDaemon = i2p::util::config::var_map["daemon"].as<bool>();
  m_IsLogging = i2p::util::config::var_map["log"].as<bool>();
  int port = i2p::util::config::var_map["port"].as<int>();
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
  i2p::context.ReseedFrom(
      i2p::util::config::var_map["reseed-from"].as<std::string>());
  i2p::context.ReseedSkipSSLCheck(
    i2p::util::config::var_map["reseed-skip-ssl-check"].as<bool>());
  // Initialize the ClientContext
  InitClientContext();
  return true;
}

bool Daemon_Singleton::Start() {
  LogPrint("The Kovri I2P Router Project");
  LogPrint("Version ", KOVRI_VERSION);
  LogPrint("Listening on port ", i2p::util::config::var_map["port"].as<int>());
  if (m_IsLogging) {
    if (m_IsDaemon) {
      std::string logfile_path = IsService() ? "/var/log" :
      i2p::util::filesystem::GetDataPath().string();
#ifndef _WIN32
      logfile_path.append("/kovri.log");
#else
      logfile_path.append("\\kovri.log");
#endif
      StartLog(logfile_path);
    } else {
      StartLog("");  // write to stdout
    }
  } else {
    m_log->Stop();
  }
  try {
    LogPrint("Starting NetDB...");
    if (i2p::data::netdb.Start()) {
      LogPrint("NetDB started");
    } else {
      LogPrint("NetDB failed to start");
      return false;
    }
    LogPrint("Starting transports...");
    i2p::transport::transports.Start();
    LogPrint("Transports started");

    LogPrint("Starting tunnels...");
    i2p::tunnel::tunnels.Start();
    LogPrint("Tunnels started");

    LogPrint("Starting client...");
    i2p::client::context.Start();
    LogPrint("Client started");
  } catch (std::runtime_error& e) {
    LogPrint(eLogError, e.what());
    return false;
  }
  return true;
}

bool Daemon_Singleton::Stop() {
  LogPrint("Stopping client...");
  i2p::client::context.Stop();
  LogPrint("Client stopped");

  LogPrint("Stopping tunnels...");
  i2p::tunnel::tunnels.Stop();
  LogPrint("Tunnels stopped");

  LogPrint("Stopping transports...");
  i2p::transport::transports.Stop();
  LogPrint("Transports stopped");

  LogPrint("Stopping NetDB...");
  i2p::data::netdb.Stop();
  LogPrint("NetDB stopped");

  LogPrint("Goodbye!");
  StopLog();
  return true;
}

void Daemon_Singleton::Reload() {
  // TODO(unassigned): do we want to add locking?
  LogPrint("Reloading configuration");
  // reload tunnels.conf
  ReloadTunnels();
  // TODO(anonimal): reload kovri.conf
}

void Daemon_Singleton::InitClientContext() {
  i2p::client::context.RegisterShutdownHandler([this]() {
        m_IsRunning = false;
      });

  std::shared_ptr<i2p::client::ClientDestination> localDestination;
  // Setup proxies and services
  std::string proxyKeys =
    i2p::util::config::var_map["proxykeys"].as<std::string>();
  if (proxyKeys.length() > 0)
    localDestination = i2p::client::context.LoadLocalDestination(
        proxyKeys, false);
  i2p::client::context.SetHTTPProxy(new i2p::proxy::HTTPProxy(
      "HTTP Proxy",  // TODO(unassigned): what if we want to change the name?
      i2p::util::config::var_map["httpproxyaddress"].as<std::string>(),
      i2p::util::config::var_map["httpproxyport"].as<int>(),
      localDestination));

  i2p::client::context.SetSOCKSProxy(new i2p::proxy::SOCKSProxy(
      i2p::util::config::var_map["socksproxyaddress"].as<std::string>(),
      i2p::util::config::var_map["socksproxyport"].as<int>(),
      localDestination));

  int i2pcontrolPort = i2p::util::config::var_map["i2pcontrolport"].as<int>();
  if (i2pcontrolPort) {
    i2p::client::context.SetI2PControlService(
        new i2p::client::i2pcontrol::I2PControlService(
          i2p::client::context.GetIoService(),
          i2p::util::config::var_map["i2pcontroladdress"].as<std::string>(),
          i2pcontrolPort,
          i2p::util::config::var_map["i2pcontrolpassword"].as<std::string>()));
  }

  // Setup client and server tunnels
  SetupTunnels();
}

void Daemon_Singleton::SetupTunnels() {
  boost::property_tree::ptree pt;
  std::string pathTunnelsConfigFile =
    i2p::util::filesystem::GetTunnelsConfigFile().string();
  try {
    boost::property_tree::read_ini(pathTunnelsConfigFile, pt);
  } catch(const std::exception& ex) {
    LogPrint(eLogWarning, "Can't read ",
        pathTunnelsConfigFile, ": ", ex.what());
    return;
  }

  int numClientTunnels = 0, numServerTunnels = 0;
  for (auto& section : pt) {
    const std::string name = section.first;
    const auto& value = section.second;
    try {
      std::string type = value.get<std::string>(I2P_TUNNELS_SECTION_TYPE);
      if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT) {
        // Mandatory parameters
        std::string dest = value.get<std::string>(
            I2P_CLIENT_TUNNEL_DESTINATION);
        int port = value.get<int>(I2P_CLIENT_TUNNEL_PORT);
        // Optional parameters
        std::string address = value.get(I2P_CLIENT_TUNNEL_ADDRESS, "127.0.0.1");
        std::string keys = value.get(I2P_CLIENT_TUNNEL_KEYS, "");
        int destinationPort = value.get(I2P_CLIENT_TUNNEL_DESTINATION_PORT, 0);

        std::shared_ptr<i2p::client::ClientDestination> localDestination;
        if (keys.length() > 0)
          localDestination = i2p::client::context.LoadLocalDestination(
              keys, false);

        bool result = i2p::client::context.InsertClientTunnel(port,
            new i2p::client::I2PClientTunnel(
              name,
              dest,
              address,
              port,
              localDestination,
              destinationPort));

        if (result)
          ++numClientTunnels;
        else
          LogPrint(eLogError, "I2P client tunnel with port ",
              port, " already exists");

      } else if (type == I2P_TUNNELS_SECTION_TYPE_SERVER ||
          type == I2P_TUNNELS_SECTION_TYPE_HTTP) {
        // Mandatory parameters
        std::string host = value.get<std::string>(I2P_SERVER_TUNNEL_HOST);
        int port = value.get<int>(I2P_SERVER_TUNNEL_PORT);
        std::string keys = value.get<std::string>(I2P_SERVER_TUNNEL_KEYS);
        // Optional parameters
        int inPort = value.get(I2P_SERVER_TUNNEL_INPORT, 0);
        std::string accessList = value.get(I2P_SERVER_TUNNEL_ACCESS_LIST, "");
        auto localDestination = i2p::client::context.LoadLocalDestination(
            keys, true);
        i2p::client::I2PServerTunnel* serverTunnel =
          (type == I2P_TUNNELS_SECTION_TYPE_HTTP) ?
          new i2p::client::I2PServerTunnelHTTP(
              name, host, port, localDestination, inPort) :
          new i2p::client::I2PServerTunnel(
              name, host, port, localDestination, inPort);
        serverTunnel->SetAccessListString(accessList);

        bool result = i2p::client::context.InsertServerTunnel(
            localDestination->GetIdentHash(), serverTunnel);

        if (result)
          ++numServerTunnels;
        else
          LogPrint(eLogError, "I2P server tunnel for destination ",
              i2p::client::context.GetAddressBook().ToAddress(
                localDestination->GetIdentHash()), " already exists");
      } else {
        LogPrint(eLogWarning, "Unknown section type=", type,
            " of ", name, " in ", pathTunnelsConfigFile);
      }
    } catch(const std::exception& ex) {
      LogPrint(eLogError, "Can't read tunnel ", name, " params: ", ex.what());
    }
  }
  LogPrint(eLogInfo, numClientTunnels, " I2P client tunnels created");
  LogPrint(eLogInfo, numServerTunnels, " I2P server tunnels created");
}

void Daemon_Singleton::ReloadTunnels() {
  boost::property_tree::ptree pt;
  std::string tunnelsConfigFile =
    i2p::util::filesystem::GetTunnelsConfigFile().string();
  try {
    boost::property_tree::read_ini(tunnelsConfigFile, pt);
  } catch (const std::exception& ex) {
    LogPrint(eLogWarning, "Can't read ", tunnelsConfigFile,
             ": ", ex.what());
    return;
  }

  // List of tunnels that still exist after config update
  // Make sure the default IRC and eepsite tunnels do not get removed
  std::vector<std::string> updatedTunnels;

  // Iterate over tunnels' ident hashes for what's in tunnels.conf now
  for (auto& section : pt) {
    // TODO(unassigned): what if we switch a server from client to tunnel
    // or vice versa?
    const std::string tunnelName = section.first;
    const auto value = section.second;

    const std::string type = value.get<std::string>(
        I2P_TUNNELS_SECTION_TYPE, "");

    if (type == I2P_TUNNELS_SECTION_TYPE_SERVER ||
        type == I2P_TUNNELS_SECTION_TYPE_HTTP) {
      // Obtain server options
      std::string keyfile = value.get<std::string>(I2P_SERVER_TUNNEL_KEYS, "");
      std::string hostStr = value.get<std::string>(I2P_SERVER_TUNNEL_HOST, "");
      int port = value.get<int>(I2P_SERVER_TUNNEL_PORT, 0);
      int inPort = value.get(I2P_SERVER_TUNNEL_INPORT, 0);
      std::string accessList = value.get(I2P_SERVER_TUNNEL_ACCESS_LIST, "");

      i2p::client::context.UpdateServerTunnel(
          tunnelName, keyfile, hostStr, accessList, port, inPort,
          (type == I2P_TUNNELS_SECTION_TYPE_HTTP));

    } else if (type == I2P_TUNNELS_SECTION_TYPE_CLIENT) {
      // Get client tunnel parameters
      std::string keyfile = value.get(I2P_CLIENT_TUNNEL_KEYS, "");
      std::string destination = value.get<std::string>(
          I2P_CLIENT_TUNNEL_DESTINATION, "");
      std::string hostStr = value.get(I2P_CLIENT_TUNNEL_ADDRESS, "127.0.0.1");
      int port = value.get<int>(I2P_CLIENT_TUNNEL_PORT, 0);
      int destPort = value.get(I2P_CLIENT_TUNNEL_DESTINATION_PORT, 0);

      i2p::client::I2PClientTunnel* tunnel =
          i2p::client::context.GetClientTunnel(port);

      if (tunnel && tunnel->GetName() != tunnelName) {
        // Conflicting port
        // TODO(unassigned): what if we interchange two client tunnels' ports?
        // TODO(EinMByte): the addresses could differ
        LogPrint(eLogError,
            tunnelName, " will not be updated, Conflicting Port");
        continue;
      }

      i2p::client::context.UpdateClientTunnel(
          tunnelName, keyfile, destination, hostStr, port, destPort);
    }
  }

  i2p::client::context.RemoveServerTunnels(
      [&updatedTunnels](i2p::client::I2PServerTunnel* tunnel) {
        return std::find(
            updatedTunnels.begin(),
            updatedTunnels.end(),
            tunnel->GetName())
          == updatedTunnels.end();
      });
  i2p::client::context.RemoveClientTunnels(
      [&updatedTunnels](i2p::client::I2PClientTunnel* tunnel) {
        return std::find(
            updatedTunnels.begin(),
            updatedTunnels.end(),
            tunnel->GetName())
          == updatedTunnels.end();
      });
}



}  // namespace util
}  // namespace i2p
