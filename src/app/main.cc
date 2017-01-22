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

#include <thread>
#include <vector>

#include "app/daemon.h"

int main(int argc, const char* argv[]) {
  // TODO(anonimal): ideally, we would only use the daemon to house any number of
  // kovri instances (client/router contexts) of which we could configure/initialize,
  // start, and stop from *outside* the daemon instead of having the daemon singleton
  // control a single kovri instance. We *could* have an app API which creates these
  // instances on-the-fly but then there's the issue of per-instance configuration.
  // For now, we deal with the singleton and a single configuration.
  // TODO(anonimal): also note that Boost.Log uses an application-wide singleton so that must be resolved
  // before any other singleton removal is considered (if still applicable, see notes in log impl)
  std::vector<std::string> args(argv, argv + argc);
  // Configure daemon for initialization
  if (!Daemon.Config(args))
    return EXIT_FAILURE;
  // Initialize daemon mode and contexts
  if (!Daemon.Init())
    return EXIT_FAILURE;
  // Start core/client (must begin in child process if in daemon mode)
  if (Daemon.Start()) {
    while (Daemon.m_IsRunning)
      std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  // Stop client/core
  if (!Daemon.Stop())
    return EXIT_FAILURE;
  return EXIT_SUCCESS;
}
