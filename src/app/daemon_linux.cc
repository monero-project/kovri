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

#ifndef _WIN32

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "app/util/config.h"

#include "core/util/log.h"
#include "core/util/filesystem.h"

void handle_signal(int sig) {
  switch (sig) {
    case SIGHUP:
      if (Daemon.m_IsDaemon == 1) {
        static bool first = true;
        if (first) {
          first = false;
          return;
        }
      }
      LogPrint("Reloading config...");
      Daemon.Reload();
      LogPrint("Config reloaded");
      break;
    case SIGABRT:
    case SIGTERM:
    case SIGINT:
      Daemon.m_IsRunning = 0;  // Exit loop
      break;
  }
}

namespace kovri {
namespace app {

bool DaemonLinux::Config(int argc, const char* argv[]) {
  return DaemonSingleton::Config(argc, argv);
}

bool DaemonLinux::Init() {
  if (m_IsDaemon) {
    // Parent
    pid_t pid = fork();
    if (pid > 0)  {
      LogPrint(eLogDebug, "DaemonLinux: fork success");
      ::exit(EXIT_SUCCESS);
    }
    if (pid < 0) {
      LogPrint(eLogError, "DaemonLinux: fork error");
      return false;
    }
    // Child
    LogPrint(eLogDebug, "DaemonLinux: creating process group");
    umask(0);
    int sid = setsid();
    if (sid < 0) {
      LogPrint(eLogDebug, "DaemonLinux: could not create process group");
      return false;
    }
    LogPrint(eLogDebug, "DaemonLinux: changing directory to ", m_PIDPath);
    if (chdir(m_PIDPath.c_str()) == -1) {
      LogPrint(eLogError, "DaemonLinux: could not change directory: ", errno);
      return false;
    }
    // Close stdin/stdout/stderr descriptors
    LogPrint(eLogDebug, "DaemonLinux: closing descriptors");
    ::close(0);
    if (::open("/dev/null", O_RDWR) < 0)
      return false;
    ::close(1);
    if (::open("/dev/null", O_RDWR) < 0)
      return false;
    ::close(2);
    if (::open("/dev/null", O_RDWR) < 0)
      return false;
  }
  // PID file
  LogPrint(eLogDebug, "DaemonLinux: opening pid file ", m_PIDFile);
  m_PIDFileHandle = open(m_PIDFile.c_str(), O_RDWR | O_CREAT, 0600);
  if (m_PIDFileHandle < 0) {
    LogPrint(eLogError,
        "DaemonLinux: could not open pid file ", m_PIDFile, ". Is file in use?");
    return false;
  }
  LogPrint(eLogDebug, "DaemonLinux: locking pid file");
  if (lockf(m_PIDFileHandle, F_TLOCK, 0) < 0) {
    LogPrint(eLogError,
        "DaemonLinux: could not lock pid file ", m_PIDFile, ": ", errno);
    return false;
  }
  LogPrint(eLogDebug, "DaemonLinux: writing pid file");
  std::array<char, 10> pid{};
  snprintf(pid.data(), pid.size(), "%d\n", getpid());
  if (write(m_PIDFileHandle, pid.data(), strlen(pid.data())) < 0) {
    LogPrint(eLogError,
        "DaemonLinux: could not write pid file ", m_PIDFile, ": ", errno);
    return false;
  }
  LogPrint(eLogDebug, "DaemonLinux: pid file ready");
  // Signal handler
  struct sigaction sa{};
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGHUP, &sa, 0);
  sigaction(SIGABRT, &sa, 0);
  sigaction(SIGTERM, &sa, 0);
  sigaction(SIGINT, &sa, 0);
  return DaemonSingleton::Init();
}

bool DaemonLinux::Start() {
  return DaemonSingleton::Start();
}

bool DaemonLinux::Stop() {
  LogPrint(eLogDebug, "DaemonLinux: closing pid file ", m_PIDFile);
  if (close(m_PIDFileHandle) == 0) {
    unlink(m_PIDFile.c_str());
  } else {
    LogPrint(eLogError,
        "DaemonLinux: could not close pid file ", m_PIDFile, ": ", errno);
  }
  return DaemonSingleton::Stop();
}

void DaemonLinux::Reload() {
  // no linux specific reload operations
  DaemonSingleton::Reload();
}

}  // namespace app
}  // namespace kovri

#endif
