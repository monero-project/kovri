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

#ifdef USE_UPNP
#include "UPnP.h"

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>

#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>

#ifdef _WIN32
#include <windows.h>
#define dlsym GetProcAddress
#else
#include <dlfcn.h>
#endif

#include <string>
#include <thread>

#include "NetworkDatabase.h"
#include "RouterContext.h"
#include "util/Log.h"

// These are per-process and are safe to reuse for all threads
#ifndef UPNPDISCOVER_SUCCESS
/* miniupnpc 1.5 */
UPNPDev* (*upnpDiscoverFunc) (
    int,
    const char *,
    const char *,
    int);

int(*UPNP_AddPortMappingFunc) (
    const char*,
    const char*,
    const char*,
    const char*,
    const char*,
    const char*,
    const char*,
    const char*);
#else
/* miniupnpc 1.6 */
UPNPDev* (*upnpDiscoverFunc) (
    int,
    const char*,
    const char*,
    int,
    int,
    int*);

int(*UPNP_AddPortMappingFunc) (
    const char*,
    const char*,
    const char*,
    const char*,
    const char*,
    const char*,
    const char*,
    const char*,
    const char *);
#endif
int(*UPNP_GetValidIGDFunc) (
    struct UPNPDev*,
    struct UPNPUrls*,
    struct IGDdatas*,
    char*,
    int);

int(*UPNP_GetExternalIPAddressFunc) (
    const char*,
    const char*,
    char*);

int(*UPNP_DeletePortMappingFunc) (
    const char*,
    const char*,
    const char*,
    const char*,
    const char*);

void(*freeUPNPDevlistFunc) (
    struct UPNPDev*);

void(*FreeUPNPUrlsFunc) (
    struct UPNPUrls*);

// Nice approach http://stackoverflow.com/a/21517513/673826
template<class M, typename F>
F GetKnownProcAddressImpl(
    M hmod,
    const char *name,
    F) {
  auto proc = reinterpret_cast<F>(dlsym(hmod, name));
  if (!proc) {
    LogPrint(eLogError,
        "UPnP: error resolving ", name,
        " from UPNP library. This often happens if there is version mismatch!");
  }
  return proc;
}
#define GetKnownProcAddress(hmod, func) GetKnownProcAddressImpl(hmod, #func, func##Func);

namespace i2p {
namespace transport {

UPnP::UPnP()
    : m_Thread(nullptr),
      m_IsModuleLoaded(false) {}

void UPnP::Stop() {
  if (m_Thread) {
    m_Thread->join();
    m_Thread.reset(nullptr);
  }
}

void UPnP::Start() {
  if (!m_IsModuleLoaded) {
#ifdef MAC_OSX
    m_Module = dlopen("libminiupnpc.dylib", RTLD_LAZY);
#elif _WIN32
    // official prebuilt binary, e.g., in upnpc-exe-win32-20140422.zip
    m_Module = LoadLibrary("miniupnpc.dll");
#else
    m_Module = dlopen("libminiupnpc.so", RTLD_LAZY);
#endif
    if (m_Module == NULL) {
      LogPrint(eLogError,
          "UPnP: error loading UPNP library.",
          "This often happens if there is version mismatch!");
      return;
    } else {
      upnpDiscoverFunc = GetKnownProcAddress(
          m_Module,
          upnpDiscover);
      UPNP_GetValidIGDFunc = GetKnownProcAddress(
          m_Module,
          UPNP_GetValidIGD);
      UPNP_GetExternalIPAddressFunc = GetKnownProcAddress(
          m_Module,
          UPNP_GetExternalIPAddress);
      UPNP_AddPortMappingFunc = GetKnownProcAddress(
          m_Module,
          UPNP_AddPortMapping);
      UPNP_DeletePortMappingFunc = GetKnownProcAddress(
          m_Module,
          UPNP_DeletePortMapping);
      freeUPNPDevlistFunc = GetKnownProcAddress(
          m_Module,
          freeUPNPDevlist);
      FreeUPNPUrlsFunc = GetKnownProcAddress(
          m_Module,
          FreeUPNPUrls);
      if (upnpDiscoverFunc &&
          UPNP_GetValidIGDFunc &&
          UPNP_GetExternalIPAddressFunc &&
          UPNP_AddPortMappingFunc &&
          UPNP_DeletePortMappingFunc &&
          freeUPNPDevlistFunc &&
          FreeUPNPUrlsFunc)
        m_IsModuleLoaded = true;
    }
  }
  m_Thread =
    std::make_unique<std::thread>(
        std::bind(
            &UPnP::Run,
            this));
}

UPnP::~UPnP() {}

void UPnP::Run() {
  for (auto& address : context.GetRouterInfo().GetAddresses()) {
    if (!address.host.is_v6()) {
      Discover();
      if (address.transport_style == data::RouterInfo::eTransportSSU) {
        TryPortMapping(I2P_UPNP_UDP, address.port);
      } else if (address.transport_style == data::RouterInfo::eTransportNTCP) {
        TryPortMapping(I2P_UPNP_TCP, address.port);
      }
    }
  }
}

void UPnP::Discover() {
#ifndef UPNPDISCOVER_SUCCESS
  /* miniupnpc 1.5 */
  m_Devlist = upnpDiscoverFunc(
      2000,
      m_MulticastIf,
      m_Minissdpdpath,
      0);
#else
  /* miniupnpc 1.6 */
  int nerror = 0;
  m_Devlist = upnpDiscoverFunc(
      2000,
      m_MulticastIf,
      m_Minissdpdpath,
      0,
      0,
      &nerror);
#endif
  int r;
  r = UPNP_GetValidIGDFunc(
      m_Devlist,
      &m_upnpUrls,
      &m_upnpData,
      m_NetworkAddr,
      sizeof(m_NetworkAddr));
  if (r == 1) {
    r = UPNP_GetExternalIPAddressFunc(
        m_upnpUrls.controlURL,
        m_upnpData.first.servicetype,
        m_externalIPAddress);
    if (r != UPNPCOMMAND_SUCCESS) {
      LogPrint(eLogError,
          "UPnP: UPNP_GetExternalIPAddressFunc() returned ", r);
      return;
    } else {
      if (m_externalIPAddress[0]) {
        LogPrint(eLogInfo,
            "UPnP: external IP address: ", m_externalIPAddress);
        i2p::context.UpdateAddress(
            boost::asio::ip::address::from_string(
              m_externalIPAddress));
        return;
      } else {
        LogPrint(eLogError, "UPnP: GetExternalIPAddress failed.");
        return;
      }
    }
  }
}

void UPnP::TryPortMapping(
    int type,
    int port) {
  std::string strType;
  std::string strPort(std::to_string(port));
  switch (type) {
    case I2P_UPNP_TCP:
      strType = "TCP";
      break;
    case I2P_UPNP_UDP:
    default:
      strType = "UDP";
  }
  int r;
  std::string strDesc = "Kovri";
  try {
    for (;;) {
#ifndef UPNPDISCOVER_SUCCESS
      /* miniupnpc 1.5 */
      r = UPNP_AddPortMappingFunc(
          m_upnpUrls.controlURL,
          m_upnpData.first.servicetype,
          strPort.c_str(),
          strPort.c_str(),
          m_NetworkAddr,
          strDesc.c_str(),
          strType.c_str(),
          0);
#else
      /* miniupnpc 1.6 */
      r = UPNP_AddPortMappingFunc(
          m_upnpUrls.controlURL,
          m_upnpData.first.servicetype,
          strPort.c_str(),
          strPort.c_str(),
          m_NetworkAddr,
          strDesc.c_str(),
          strType.c_str(),
          0,
          "0");
#endif
      if (r != UPNPCOMMAND_SUCCESS) {
        LogPrint(eLogError,
            "UPnP: AddPortMapping (", strPort.c_str(),
            ", ", strPort.c_str(),
            ", ", m_NetworkAddr,
            ") failed with code ", r);
        return;
      } else {
        LogPrint(eLogInfo,
            "UPnP: port mapping successful. (", m_NetworkAddr,
            ":", strPort.c_str(),
            " type ", strType.c_str() ,
            " -> ", m_externalIPAddress,
            ":", strPort.c_str(), ")");
        return;
      }
      std::this_thread::sleep_for(std::chrono::minutes(20));  // c++11
      // boost::this_thread::sleep_for(); // pre c++11
      // sleep(20*60); // non-portable
    }
  } catch (boost::thread_interrupted) {
    CloseMapping(type, port);
    Close();
    throw;
  }
}

void UPnP::CloseMapping(
    int type,
    int port) {
  std::string strType,
              strPort(
                  std::to_string(
                    port));
  switch (type) {
    case I2P_UPNP_TCP:
      strType = "TCP";
      break;
    case I2P_UPNP_UDP:
    default:
      strType = "UDP";
  }
  int r = 0;
  r = UPNP_DeletePortMappingFunc(
      m_upnpUrls.controlURL,
      m_upnpData.first.servicetype,
      strPort.c_str(),
      strType.c_str(),
      0);
  LogPrint(eLogInfo,
      "UPnP: UPNP_DeletePortMappingFunc() returned : ", r, "\n");
}

void UPnP::Close() {
  freeUPNPDevlistFunc(m_Devlist);
  m_Devlist = 0;
  FreeUPNPUrlsFunc(&m_upnpUrls);
#ifndef _WIN32
  dlclose(m_Module);
#else
  FreeLibrary(m_Module);
#endif
}

}  // namespace transport
}  // namespace i2p

#endif
