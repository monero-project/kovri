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

#include "daemon.h"

#ifndef _WIN32

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>

#include "core/util/log.h"
#include "util/config.h"
#include "util/filesystem.h"

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

namespace i2p {
namespace util {

bool DaemonLinux::Start() {
  if (m_IsDaemon == 1) {
    pid_t pid;
    pid = fork();
    if (pid > 0)  // parent
      ::exit(EXIT_SUCCESS);
    if (pid < 0)  // error
      return false;
    // child
    umask(0);
    int sid = setsid();
    if (sid < 0) {
      LogPrint("Error, could not create process group.");
      return false;
    }
    std::string d(i2p::util::filesystem::GetDataPath().string());  // makes copy
    chdir(d.c_str());
    // close stdin/stdout/stderr descriptors
    ::close(0);
    ::open("/dev/null", O_RDWR);
    ::close(1);
    ::open("/dev/null", O_RDWR);
    ::close(2);
    ::open("/dev/null", O_RDWR);
  }
  // Pidfile
  m_pidFile = (i2p::util::filesystem::GetDataPath() / "kovri.pid").string();
  m_pidFilehandle = open(
      m_pidFile.c_str(),
      O_RDWR | O_CREAT,
      0600);
  if (m_pidFilehandle == -1) {
    LogPrint("Error, could not create pid file (",
        m_pidFile, ")\nIs an instance already running?");
    return false;
  }
  if (lockf(m_pidFilehandle, F_TLOCK, 0) == -1) {
    LogPrint("Error, could not lock pid file (",
        m_pidFile, ")\nIs an instance already running?");
    return false;
  }
  char pid[10];
  snprintf(pid, sizeof(pid), "%d\n", getpid());
  write(m_pidFilehandle, pid, strlen(pid));
  // Signal handler
  struct sigaction sa;
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGHUP, &sa, 0);
  sigaction(SIGABRT, &sa, 0);
  sigaction(SIGTERM, &sa, 0);
  sigaction(SIGINT, &sa, 0);
  return Daemon_Singleton::Start();
}

bool DaemonLinux::Stop() {
  close(m_pidFilehandle);
  unlink(m_pidFile.c_str());
  return Daemon_Singleton::Stop();
}

void DaemonLinux::Reload() {
  // no linux specific reload operations
  Daemon_Singleton::Reload();
}

}  // namespace util
}  // namespace i2p

#endif
