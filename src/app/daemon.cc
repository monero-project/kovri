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

#include "app/daemon.h"

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include <thread>
#include <vector>

#include "client/context.h"

#include "core/router/net_db/impl.h"
#include "core/router/transports/impl.h"
#include "core/router/tunnel/impl.h"

namespace kovri {
namespace app {

DaemonSingleton::DaemonSingleton()
    : m_IsDaemon(false),
      m_IsRunning(true),
      m_Instance(nullptr) {}

DaemonSingleton::~DaemonSingleton() {}

bool DaemonSingleton::Config(
    const std::vector<std::string>& args) {
  // TODO(unassigned): ideally, all instance configuration, etc., happens outside of singleton
  m_Instance = std::make_unique<Instance>(args);
  try {
    m_Instance->Configure();
  } catch (const std::exception& ex) {
    LOG(error) << "DaemonSingleton: " << ex.what();
    return false;
  } catch (...) {
    LOG(error) << "DaemonSingleton: unknown exception when configuring";
    return false;
  }
  // Set daemon mode (if applicable)
  m_IsDaemon = m_Instance->GetConfig().GetParsedKovriConfig().at("daemon").as<bool>();
#ifdef _WIN32
  m_Service = m_Instance->GetConfig().GetParsedKovriConfig().at("service").as<std::string>();
#endif
  return true;
}

bool DaemonSingleton::Init() {
  // We must initialize contexts here (in child process, if in daemon mode)
  try {
    m_Instance->Initialize();
  } catch (const std::exception& ex) {
    LOG(error) << "DaemonSingleton: exception during initialization: " << ex.what();
    return false;
  } catch (...) {
    LOG(error) << "DaemonSingleton: unknown exception during initialization";
    return false;
  }
  return true;
}

// TODO(anonimal): when refactoring TODO's for singleton, have instance Start
bool DaemonSingleton::Start() {
  try {
    LOG(debug) << "DaemonSingleton: starting NetDb";
    if (!kovri::core::netdb.Start()) {
      LOG(error) << "DaemonSingleton: NetDb failed to start";
      return false;
    }
    if (kovri::core::netdb.GetNumRouters() < kovri::core::netdb.MIN_REQUIRED_ROUTERS) {
      LOG(debug) << "DaemonSingleton: reseeding NetDb";
      kovri::client::Reseed reseed;
      if (!reseed.Start()) {
        LOG(error) << "DaemonSingleton: reseed failed";
        return false;
      }
    }
    LOG(debug) << "DaemonSingleton: starting transports";
    kovri::core::transports.Start();
    LOG(debug) << "DaemonSingleton: starting tunnels";
    kovri::core::tunnels.Start();
    LOG(debug) << "DaemonSingleton: starting client";
    kovri::client::context.Start();
  } catch (const std::exception& ex) {
    LOG(error) << "DaemonSingleton: start exception: " << ex.what();
    return false;
  }  catch (...) {
    LOG(error) << "DaemonSingleton: unknown exception when starting";
    return false;
  }
  LOG(info) << "DaemonSingleton: successfully started";
  return true;
}

void DaemonSingleton::Reload() {
  // TODO(unassigned): do we want to add locking?
  LOG(info) << "DaemonSingleton: reloading configuration";
  // Reload tunnels configuration
  m_Instance->Reload();
}

// TODO(anonimal): when refactoring TODO's for singleton, have instance Stop
bool DaemonSingleton::Stop() {
  try {
    LOG(debug) << "DaemonSingleton: stopping client";
    kovri::client::context.Stop();
    LOG(debug) << "DaemonSingleton: stopping tunnels";
    kovri::core::tunnels.Stop();
    LOG(debug) << "DaemonSingleton: stopping transports";
    kovri::core::transports.Stop();
    LOG(debug) << "DaemonSingleton: stopping NetDb";
    kovri::core::netdb.Stop();
  } catch (const std::exception& ex) {
    LOG(error) << "DaemonSingleton: stop exception: " << ex.what();
    return false;
  }  catch (...) {
    LOG(error) << "DaemonSingleton: unknown exception when stopping";
    return false;
  }
  LOG(info) << "DaemonSingleton: successfully stopped";
  LOG(info) << "Goodbye!";
  return true;
}

}  // namespace app
}  // namespace kovri
