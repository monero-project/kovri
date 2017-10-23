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

#include <memory>
#include <vector>
#include <exception>

#include "app/instance.h"

namespace kovri {
namespace app {

DaemonSingleton::DaemonSingleton()
    : m_IsDaemon(false),
      m_IsRunning(true),
      m_Instance(nullptr),
      m_Exception(__func__) {}

DaemonSingleton::~DaemonSingleton() {}

// TODO(anonimal): Instance and RAII refactoring

bool DaemonSingleton::Config(const std::vector<std::string>& args)
{
  // TODO(unassigned): ideally, all instance configuration, etc., happens outside of singleton
  m_Instance = std::make_unique<Instance>(args);

  try
    {
      m_Instance->Configure();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      return false;
    }

  // Set daemon mode (if applicable)
  m_IsDaemon =
      m_Instance->GetConfig().GetParsedKovriConfig().at("daemon").as<bool>();
#ifdef _WIN32
  m_Service = m_Instance->GetConfig()
                  .GetParsedKovriConfig()
                  .at("service")
                  .as<std::string>();
#endif
  return true;
}

bool DaemonSingleton::Init()
{
  // We must initialize contexts here (in child process, if in daemon mode)
  try
    {
      m_Instance->Initialize();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      Stop();
      return false;
    }

  LOG(info) << "DaemonSingleton: initialized";
  return true;
}

bool DaemonSingleton::Start()
{
  try
    {
      m_Instance->Start();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
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

bool DaemonSingleton::Stop()
{
  try
    {
      m_Instance->Stop();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      return false;
    }

  LOG(info) << "DaemonSingleton: successfully stopped";
  LOG(info) << "Goodbye!";
  return true;
}

}  // namespace app
}  // namespace kovri
