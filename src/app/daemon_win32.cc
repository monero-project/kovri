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

#include <string>

#include "daemon.h"

#include "util/config.h"
#include "util/log.h"

#ifdef _WIN32

#include "win32_service.h"

namespace i2p {
namespace util {

bool DaemonWin32::Init() {
  // TODO(unassigned): use Boost.Locale
  setlocale(LC_CTYPE, "");  // "" uses environment's default locale
  SetConsoleCP(65001);  // UTF-8
  SetConsoleOutputCP(65001);
  setlocale(LC_ALL, "");
  if (!Daemon_Singleton::Init())
    return false;
  if (I2PService::isService())
    m_IsDaemon = 1;
  else
    m_IsDaemon = 0;
  std::string serviceControl =
    i2p::util::config::var_map["service"].as<std::string>();
  if (serviceControl == "install") {
    InstallService(
        SERVICE_NAME,               // Name of service
        SERVICE_DISPLAY_NAME,       // Name to display
        SERVICE_START_TYPE,         // Service start type
        SERVICE_DEPENDENCIES,       // Dependencies
        SERVICE_ACCOUNT,            // Service running account
        SERVICE_PASSWORD);          // Password of the account
    exit(0);
  } else if (serviceControl == "remove") {
    UninstallService(SERVICE_NAME);
    exit(0);
  }
  if (m_IsDaemon == 1) {
    LogPrint(eLogInfo, "DaemonWin32: service session");
    I2PService service(SERVICE_NAME);
    if (!I2PService::Run(service)) {
      LogPrint(eLogError,
          "DaemonWin32: service failed to run w/err 0x%08lx\n", GetLastError());
      exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
  } else {
    LogPrint(eLogInfo, "DaemonWin32: user session");
  }
  return true;
}

bool DaemonWin32::Start() {
  setlocale(LC_CTYPE, "");
  SetConsoleCP(65001);
  SetConsoleOutputCP(65001);
  setlocale(LC_ALL, "");
  return Daemon_Singleton::Start();
}

bool DaemonWin32::Stop() {
  return Daemon_Singleton::Stop();
}

}  // namespace util
}  // namespace i2p

#endif
