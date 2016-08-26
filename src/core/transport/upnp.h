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

#ifndef SRC_CORE_TRANSPORT_UPNP_H_
#define SRC_CORE_TRANSPORT_UPNP_H_

#ifdef USE_UPNP

#include <boost/asio.hpp>

#include <miniupnpc/miniwget.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#include <memory>
#include <string>
#include <thread>

#define I2P_UPNP_TCP 1
#define I2P_UPNP_UDP 2

namespace i2p {
namespace transport {

class UPnP {
 public:
  UPnP();
  ~UPnP();

  void Close();

  void Start();

  void Stop();

  void Discover();

  void TryPortMapping(
      int type,
      int port);

  void CloseMapping(
      int type,
      int port);

 private:
  void Run();

  std::unique_ptr<std::thread> m_Thread;
  struct UPNPUrls m_upnpUrls;
  struct IGDdatas m_upnpData;

  // For miniupnpc
  char* m_MulticastIf = 0;
  char* m_Minissdpdpath = 0;
  struct UPNPDev* m_Devlist = 0;
  char m_NetworkAddr[64];
  char m_externalIPAddress[40];
  bool m_IsModuleLoaded;
#ifndef _WIN32
  void* m_Module;
#else
  HINSTANCE m_Module;
#endif
};

}  // namespace transport
}  // namespace i2p

#endif  // USE_UPNP
#endif  // SRC_CORE_TRANSPORT_UPNP_H_
