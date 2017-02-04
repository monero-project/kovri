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

#ifndef SRC_APP_DAEMON_H_
#define SRC_APP_DAEMON_H_

#include <string>
#include <memory>

#ifdef _WIN32
#define Daemon kovri::app::DaemonWin32::Instance()
#else
#define Daemon kovri::app::DaemonLinux::Instance()
#endif

#include "app/instance.h"

#include "core/util/log.h"
#include "core/util/filesystem.h"

namespace kovri {
namespace app {

class DaemonSingleton {
 public:
  /// @brief Get/Set configuration options before initialization/forking
  /// @param args Reference to string vector of command line args
  virtual bool Config(
      std::vector<std::string>& args);

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

#ifdef _WIN32
  std::string m_Service;
#endif

  /// @var m_Instance
  /// @brief Unique pointer to instance object (client/router)
  std::unique_ptr<Instance> m_Instance;

 protected:
  DaemonSingleton();
  virtual ~DaemonSingleton();
};

#ifdef _WIN32
class DaemonWin32 : public DaemonSingleton {
 public:
  static DaemonWin32& Instance() {
    static DaemonWin32 instance;
    return instance;
  }
  virtual bool Config(
      std::vector<std::string>& args);

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
  virtual bool Config(
      std::vector<std::string>& args);

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
