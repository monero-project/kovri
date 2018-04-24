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

#ifdef USE_UPNP
#include "core/router/transports/upnp.h"

#include <boost/bind.hpp>
#include <boost/thread/thread.hpp>

#include "core/router/context.h"
#include "core/router/net_db/impl.h"

#include "core/util/byte_stream.h"
#include "core/util/log.h"

namespace kovri {
namespace core {

UPnP::UPnP() : m_Thread(nullptr), m_Devlist(nullptr, freeUPNPDevlist) {}

void UPnP::Stop() {
  if (m_Thread) {
    m_Thread->join();
    m_Thread.reset(nullptr);
  }
}

void UPnP::Start() {
  m_Thread =
    std::make_unique<std::thread>(
        std::bind(
            &UPnP::Run,
            this));
}

UPnP::~UPnP() = default;

void UPnP::Run() {
  for (const auto& address : context.GetRouterInfo().GetAddresses()) {
    if (!address.host.is_v6()) {
      Discover();
      if (address.transport == core::RouterInfo::Transport::SSU) {
        TryPortMapping(I2P_UPNP_UDP, address.port);
      } else if (address.transport == core::RouterInfo::Transport::NTCP) {
        TryPortMapping(I2P_UPNP_TCP, address.port);
      }
    }
  }
}

void UPnP::Discover() {
  int nerror = 0;
  // default according to miniupnpc.h
  unsigned char ttl = 2;
  m_Devlist = std::unique_ptr<struct UPNPDev, void(*)(struct UPNPDev*)>(
    upnpDiscover(
      2000,
      m_MulticastIf,
      m_Minissdpdpath,
      0,
      0,
      ttl,
      &nerror), freeUPNPDevlist);
  int r;
  r = UPNP_GetValidIGD(
      m_Devlist.get(),
      &m_upnpUrls,
      &m_upnpData,
      m_NetworkAddr,
      sizeof(m_NetworkAddr));
  if (r == 1) {
    r = UPNP_GetExternalIPAddress(
        m_upnpUrls.controlURL,
        m_upnpData.first.servicetype,
        m_externalIPAddress);
    if (r != UPNPCOMMAND_SUCCESS) {
      LOG(error) << "UPnP: UPNP_GetExternalIPAddress() returned " << r;
      return;
    } else {
      if (m_externalIPAddress[0]) {
        LOG(debug) << "UPnP: external IP address: " << m_externalIPAddress;
        auto const address = core::AddressToByteVector(
            boost::asio::ip::address::from_string(m_externalIPAddress));
        context.UpdateAddress(address.data(), address.size());
        return;
      } else {
        LOG(error) << "UPnP: GetExternalIPAddress failed.";
        return;
      }
    }
  }
}

void UPnP::TryPortMapping(
    int type,
    int port) {
  std::string upnp_type;
  std::string upnp_port(std::to_string(port));
  switch (type) {
    case I2P_UPNP_TCP:
      upnp_type = "TCP";
      break;
    case I2P_UPNP_UDP:
    default:
      upnp_type = "UDP";
  }
  int r;
  const std::string desc = "Kovri";
  try {
    for (;;) {
      r = UPNP_AddPortMapping(
          m_upnpUrls.controlURL,
          m_upnpData.first.servicetype,
          upnp_port.c_str(),
          upnp_port.c_str(),
          m_NetworkAddr,
          desc.c_str(),
          upnp_type.c_str(),
          0,
          "0");
      if (r == UPNPCOMMAND_SUCCESS) {
        LOG(debug)
          << "UPnP: port mapping successful. "
          << "(" << m_NetworkAddr
          << ":" << upnp_port.c_str()
          << " type " << upnp_type.c_str()
          << " -> " << m_externalIPAddress
          << ":" << upnp_port.c_str() << ")";
        return;
      }
      // TODO(unassigned): do we really want to retry on *all* errors? (see upnpcommands.h)
      LOG(error)
        << "UPnP: AddPortMapping "
        << "(" << upnp_port.c_str()
        << " << " << upnp_port.c_str()
        << " << " << m_NetworkAddr
        << ") failed with code " << r;
      // Try again later
      // TODO(unassigned): magic number to be addressed along with bigger refactor
      std::this_thread::sleep_for(std::chrono::minutes(20));
    }
  } catch (const boost::thread_interrupted&) {
    CloseMapping(type, port);
    Close();
    throw;
  }
}

void UPnP::CloseMapping(
    int type,
    int port) {
  std::string upnp_type;
  std::string upnp_port(std::to_string(port));
  switch (type) {
    case I2P_UPNP_TCP:
      upnp_type = "TCP";
      break;
    case I2P_UPNP_UDP:
    default:
      upnp_type = "UDP";
  }
  int r = 0;
  r = UPNP_DeletePortMapping(
      m_upnpUrls.controlURL,
      m_upnpData.first.servicetype,
     upnp_port.c_str(),
      upnp_type.c_str(),
      0);
  LOG(debug) << "UPnP: UPNP_DeletePortMapping() returned : " << r << "\n";
}

void UPnP::Close() {
  FreeUPNPUrls(&m_upnpUrls);
}

}  // namespace core
}  // namespace kovri

#endif  // USE_UPNP
