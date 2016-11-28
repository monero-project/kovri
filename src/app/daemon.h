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

#ifndef SRC_APP_DAEMON_H_
#define SRC_APP_DAEMON_H_

#include <string>
#include <memory>

#ifdef _WIN32
#define Daemon kovri::app::DaemonWin32::Instance()
#else
#define Daemon kovri::app::DaemonLinux::Instance()
#endif

#include "app/util/config.h"

#include "core/util/log.h"
#include "core/util/filesystem.h"

namespace kovri {
namespace app {

class DaemonSingleton {
 public:
  /// @brief Get/Set configuration options before initialization/forking
  /// @param argc Classic arg count from command line
  /// @param argv Classic arg vector from command line
  virtual bool Config(int argc, const char* argv[]);

  /// @brief Forks process if daemon mode is set, initializes contexts
  /// @warning Child *must* fork *before* contexts are initialized
  virtual bool Init();

  /// @brief Start client/router
  virtual bool Start();

  /// @brief Stop client/router
  virtual bool Stop();

  /// @brief Reload tunnels
  virtual void Reload();

  bool m_IsDaemon, m_IsRunning;

  /// TODO(anonimal): consider unhooking from singleton
  /// @var m_IsReloading
  /// @brief Are tunnels configuration in the process of reloading?
  bool m_IsReloading;

  /// @var m_Config
  /// @brief Pointer to configuration object for configuration implementation
  std::unique_ptr<Configuration> m_Config;

 private:
  /// @brief Initializes router context / core settings
  void InitRouterContext();

  /// @brief Initializes the router's client context object
  /// @details Creates tunnels, proxies and I2PControl service
  void InitClientContext();

  /// TODO(anonimal): consider unhooking from singleton
  /// @brief Sets up client/server tunnels
  /// @warning Configuration files must be parsed prior to setup
  void SetupTunnels();

  /// TODO(anonimal): consider unhooking from singleton
  /// @brief Should remove old tunnels after tunnels config is updated
  /// TODO(unassigned): not fully implemented
  void RemoveOldTunnels(
      std::vector<std::string>& updated_tunnels);

 protected:
  DaemonSingleton();
  virtual ~DaemonSingleton();
  std::shared_ptr<kovri::core::Log> m_Log;
};

#ifdef _WIN32
class DaemonWin32 : public DaemonSingleton {
 public:
  static DaemonWin32& Instance() {
    static DaemonWin32 instance;
    return instance;
  }
  virtual bool Config(int argc, const char* argv[]);
  virtual bool Init();
  virtual bool Start();
  virtual bool Stop();
};
#else
class DaemonLinux : public DaemonSingleton {
 public:
  DaemonLinux()
    : m_PIDPath(kovri::core::GetDataPath().string()),
      m_PIDFile((kovri::core::GetDataPath() / "kovri.pid").string()),
      m_PIDFileHandle() {}
  static DaemonLinux& Instance() {
    static DaemonLinux instance;
    return instance;
  }
  virtual bool Config(int argc, const char* argv[]);
  virtual bool Init();
  virtual bool Start();
  virtual bool Stop();
  void Reload();
 private:
  std::string m_PIDPath, m_PIDFile;
  int m_PIDFileHandle;
};
#endif

}  // namespace app
}  // namespace kovri

#endif  // SRC_APP_DAEMON_H_
