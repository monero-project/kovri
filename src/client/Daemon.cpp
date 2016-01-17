/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
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
 */

#include <string>
#include <thread>

#include "ClientContext.h"
#include "Daemon.h"
#include "Destination.h"
#include "Garlic.h"
#include "NetworkDatabase.h"
#include "RouterContext.h"
#include "RouterInfo.h"
#include "Version.h"
#include "api/Streaming.h"
#include "transport/NTCPSession.h"
#include "transport/Transports.h"
#include "tunnel/Tunnel.h"

namespace i2p {
namespace util {

Daemon_Singleton::Daemon_Singleton()
    : m_IsRunning(1),
      m_log(kovri::log::Log::Get()) {}
Daemon_Singleton::~Daemon_Singleton() {}

bool Daemon_Singleton::IsService() const {
#ifndef _WIN32
  return i2p::util::config::varMap["service"].as<bool>();
#else
  return false;
#endif
}

// TODO(anonimal): find a better way to initialize
bool Daemon_Singleton::Init() {
  i2p::context.Init();
  m_IsDaemon = i2p::util::config::varMap["daemon"].as<bool>();
  m_IsLogging = i2p::util::config::varMap["log"].as<bool>();
  int port = i2p::util::config::varMap["port"].as<int>();
  i2p::context.UpdatePort(port);
  i2p::context.UpdateAddress(
      boost::asio::ip::address::from_string(
        i2p::util::config::varMap["host"].as<std::string>()));
  i2p::context.SetSupportsV6(
      i2p::util::config::varMap["v6"].as<bool>());
  i2p::context.SetFloodfill(
      i2p::util::config::varMap["floodfill"].as<bool>());
  auto bandwidth = i2p::util::config::varMap["bandwidth"].as<std::string>();
  if (bandwidth.length() > 0) {
    if (bandwidth[0] > 'L')
      i2p::context.SetHighBandwidth();
    else
      i2p::context.SetLowBandwidth();
  }
  return true;
}

bool Daemon_Singleton::Start() {
  LogPrint("The Kovri I2P Router Project");
  LogPrint("Version ", KOVRI_VERSION);
  LogPrint("Listening on port ", i2p::util::config::varMap["port"].as<int>());
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
    // TODO(psi) do we want to add locking?
    LogPrint("Reloading configuration");
    // reload tunnels.cfg
    i2p::client::context.ReloadTunnels();
    // TODO(psi) reload i2p.conf
  }
  
}  // namespace util
}  // namespace i2p
