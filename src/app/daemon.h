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

#ifdef _WIN32
#define Daemon i2p::util::DaemonWin32::Instance()
#else
#define Daemon i2p::util::DaemonLinux::Instance()
#endif

#include "core/util/log.h"

namespace i2p {
namespace util {

class Daemon_Singleton {
 public:
  virtual bool Init();
  virtual bool Start();
  virtual bool Stop();
  virtual void Reload();
  bool m_IsDaemon, m_IsRunning;

 private:
  /// Initializes the router's client context object
  /// Creates tunnels, proxies and I2PControl service
  void InitClientContext();
  void SetupTunnels();
  void ReloadTunnels();

 protected:
  Daemon_Singleton();
  virtual ~Daemon_Singleton();
  std::shared_ptr<i2p::util::log::Log> m_Log;
};

#ifdef _WIN32
class DaemonWin32 : public Daemon_Singleton {
 public:
  static DaemonWin32& Instance() {
    static DaemonWin32 instance;
    return instance;
  }
  virtual bool Init();
  virtual bool Start();
  virtual bool Stop();
};
#else
class DaemonLinux : public Daemon_Singleton {
 public:
  DaemonLinux()
    : m_pidFilehandle() {};
  static DaemonLinux& Instance() {
    static DaemonLinux instance;
    return instance;
  }
  virtual bool Start();
  virtual bool Stop();
  void Reload();
 private:
  std::string m_pidFile;
  int m_pidFilehandle;
};
#endif

}  // namespace util
}  // namespace i2p

#endif  // SRC_APP_DAEMON_H_
