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

#include "core/router/context.h"

#include <boost/lexical_cast.hpp>

#include <fstream>

#include "core/router/i2np.h"
#include "core/router/net_db/impl.h"

#include "core/util/filesystem.h"
#include "core/util/mtu.h"
#include "core/util/timestamp.h"

#include "version.h"

namespace kovri {
// TODO(anonimal): this belongs in core namespace

// Simply instantiating in namespace scope ties into, and is limited by, the current singleton design
// TODO(unassigned): refactoring this requires global work but will help to remove the singleton
RouterContext context;

RouterContext::RouterContext()
    : m_LastUpdateTime(0),
      m_AcceptsTunnels(true),
      m_IsFloodfill(false),
      m_StartupTime(0),
      m_Status(eRouterStatusOK),
      m_Port(0),
      m_ReseedSkipSSLCheck(false),
      m_SupportsNTCP(true),
      m_SupportsSSU(true) {}

void RouterContext::Init(
    const std::string& host,
    std::uint16_t port) {
  m_Host = host;
  m_Port = port;
  m_StartupTime = kovri::core::GetSecondsSinceEpoch();
  if (!Load())
    CreateNewRouter();
  UpdateRouterInfo();
}

void RouterContext::CreateNewRouter() {
  m_Keys = kovri::core::PrivateKeys::CreateRandomKeys(
      kovri::core::DEFAULT_ROUTER_SIGNING_KEY_TYPE);
  SaveKeys();
  NewRouterInfo();
}

void RouterContext::NewRouterInfo() {
  kovri::core::RouterInfo routerInfo;
  routerInfo.SetRouterIdentity(
      GetIdentity());
  routerInfo.AddSSUAddress(m_Host, m_Port, routerInfo.GetIdentHash());
  routerInfo.AddNTCPAddress(m_Host, m_Port);
  routerInfo.SetCaps(
    core::RouterInfo::Caps::Reachable |
    core::RouterInfo::Caps::SSUTesting |
    core::RouterInfo::Caps::SSUIntroducer);
  routerInfo.SetProperty("netId", I2P_NETWORK_ID);
  routerInfo.SetProperty("router.version", I2P_VERSION);
  routerInfo.CreateBuffer(m_Keys);
  m_RouterInfo.Update(
      routerInfo.GetBuffer(),
      routerInfo.GetBufferLen());
}

void RouterContext::UpdateRouterInfo() {
  m_RouterInfo.CreateBuffer(m_Keys);
  m_RouterInfo.SaveToFile((kovri::core::GetCorePath() / ROUTER_INFO).string());
  m_LastUpdateTime = kovri::core::GetSecondsSinceEpoch();
}

void RouterContext::UpdatePort(
    std::uint16_t port) {
  bool updated = false;
  for (auto& address : m_RouterInfo.GetAddresses()) {
    if (address.port != port) {
      address.port = port;
      updated = true;
    }
  }
  if (updated)
    UpdateRouterInfo();
}

void RouterContext::UpdateAddress(
    const boost::asio::ip::address& host) {
  bool updated = false;
  for (auto& address : m_RouterInfo.GetAddresses()) {
    if (address.host != host && address.IsCompatible(host)) {
      address.host = host;
      updated = true;
    }
  }
  auto ts = kovri::core::GetSecondsSinceEpoch();
  if (updated || ts > m_LastUpdateTime + ROUTER_INFO_UPDATE_INTERVAL)
    UpdateRouterInfo();
}

bool RouterContext::AddIntroducer(
    const kovri::core::RouterInfo& routerInfo,
    std::uint32_t tag) {
  bool ret = false;
  auto address = routerInfo.GetSSUAddress();
  if (address) {
    ret = m_RouterInfo.AddIntroducer(address, tag);
    if (ret)
      UpdateRouterInfo();
  }
  return ret;
}

void RouterContext::RemoveIntroducer(
    const boost::asio::ip::udp::endpoint& e) {
  if (m_RouterInfo.RemoveIntroducer(e))
    UpdateRouterInfo();
}

void RouterContext::SetFloodfill(
    bool floodfill) {
  m_IsFloodfill = floodfill;
  if (floodfill) {
    m_RouterInfo.SetCaps(
        m_RouterInfo.GetCaps() | core::RouterInfo::Caps::Floodfill);
  } else {
    m_RouterInfo.SetCaps(
        m_RouterInfo.GetCaps() & ~core::RouterInfo::Caps::Floodfill);
    // we don't publish number of routers and leaseset for non-floodfill
    m_RouterInfo.DeleteProperty(ROUTER_INFO_PROPERTY_LEASESETS);
    m_RouterInfo.DeleteProperty(ROUTER_INFO_PROPERTY_ROUTERS);
  }
  UpdateRouterInfo();
}

void RouterContext::SetHighBandwidth() {
  if (!m_RouterInfo.IsHighBandwidth()) {
    m_RouterInfo.SetCaps(
        m_RouterInfo.GetCaps() | core::RouterInfo::Caps::HighBandwidth);
    UpdateRouterInfo();
  }
}

void RouterContext::SetLowBandwidth() {
  if (m_RouterInfo.IsHighBandwidth()) {
    m_RouterInfo.SetCaps(
        m_RouterInfo.GetCaps() & ~core::RouterInfo::Caps::HighBandwidth);
    UpdateRouterInfo();
  }
}

bool RouterContext::IsUnreachable() const {
  return m_RouterInfo.GetCaps() & core::RouterInfo::Caps::Unreachable;
}

void RouterContext::SetUnreachable() {
  // set caps
  m_RouterInfo.SetCaps(  // LU, B
      core::RouterInfo::Caps::Unreachable | core::RouterInfo::Caps::SSUTesting);
  // remove NTCP address
  RemoveTransport(core::RouterInfo::Transport::NTCP);
  // delete previous introducers
  for (auto& addr : m_RouterInfo.GetAddresses())
    addr.introducers.clear();
  // update
  UpdateRouterInfo();
}

void RouterContext::SetReachable() {
  // update caps
  std::uint8_t caps = m_RouterInfo.GetCaps();
  caps &= ~core::RouterInfo::Caps::Unreachable;
  caps |= core::RouterInfo::Caps::Reachable;
  caps |= core::RouterInfo::Caps::SSUIntroducer;
  if (m_IsFloodfill)
    caps |= core::RouterInfo::Caps::Floodfill;
  m_RouterInfo.SetCaps(caps);

  // insert NTCP back
  auto& addresses = m_RouterInfo.GetAddresses();
  for (std::size_t i = 0; i < addresses.size(); i++) {
    if (addresses[i].transport_style == core::RouterInfo::Transport::SSU) {
      // insert NTCP address with host/port form SSU
      m_RouterInfo.AddNTCPAddress(
          addresses[i].host.to_string().c_str(),
          addresses[i].port);
      break;
    }
  }
  // delete previous introducers
  for (auto& addr : addresses)
    addr.introducers.clear();
  // update
  UpdateRouterInfo();
}

void RouterContext::SetSupportsV6(
    bool supportsV6) {
  if (supportsV6)
    m_RouterInfo.EnableV6();
  else
    m_RouterInfo.DisableV6();
  UpdateRouterInfo();
}

void RouterContext::SetSupportsNTCP(bool supportsNTCP) {
  m_SupportsNTCP = supportsNTCP;
  if(supportsNTCP && !m_RouterInfo.GetNTCPAddress())
    m_RouterInfo.AddNTCPAddress(m_Host, m_Port);
  if(!supportsNTCP)
    RemoveTransport(core::RouterInfo::Transport::NTCP);
  UpdateRouterInfo();
}

void RouterContext::SetSupportsSSU(bool supportsSSU) {
  m_SupportsSSU = supportsSSU;
  if(supportsSSU && !m_RouterInfo.GetSSUAddress())
    m_RouterInfo.AddSSUAddress(m_Host, m_Port, m_RouterInfo.GetIdentHash());
  if(!supportsSSU)
    RemoveTransport(core::RouterInfo::Transport::SSU);
  // Remove SSU-related flags
  m_RouterInfo.SetCaps(m_RouterInfo.GetCaps()
      & ~core::RouterInfo::Caps::SSUTesting
      & ~core::RouterInfo::Caps::SSUIntroducer);

  UpdateRouterInfo();
}

void RouterContext::UpdateNTCPV6Address(
    const boost::asio::ip::address& host) {
  bool updated = false,
       found = false;
  std::uint16_t port = 0;
  auto& addresses = m_RouterInfo.GetAddresses();
  for (auto& addr : addresses) {
    if (addr.host.is_v6() &&
        addr.transport_style == core::RouterInfo::Transport::NTCP) {
      if (addr.host != host) {
        addr.host = host;
        updated = true;
      }
      found = true;
    } else {
      port = addr.port;
    }
  }
  if (!found) {
    // create new address
    m_RouterInfo.AddNTCPAddress(
        host.to_string().c_str(),
        port);
    m_RouterInfo.AddSSUAddress(
        host.to_string().c_str(),
        port,
        GetIdentHash(),
        kovri::core::GetMTU(host));
    updated = true;
  }
  if (updated)
    UpdateRouterInfo();
}

void RouterContext::UpdateStats() {
  if (m_IsFloodfill) {
    // update routers and leasesets
    m_RouterInfo.SetProperty(
        ROUTER_INFO_PROPERTY_LEASESETS,
        boost::lexical_cast<std::string>(kovri::core::netdb.GetNumLeaseSets()));
    m_RouterInfo.SetProperty(
        ROUTER_INFO_PROPERTY_ROUTERS,
        boost::lexical_cast<std::string>(kovri::core::netdb.GetNumRouters()));
    UpdateRouterInfo();
  }
}

bool RouterContext::Load() {
  auto path = kovri::core::EnsurePath(kovri::core::GetCorePath());
  std::ifstream fk((path / ROUTER_KEYS).string(), std::ifstream::binary);
  // If key does not exist, create
  if (!fk.is_open())
    return false;
  fk.seekg(0, std::ios::end);
  const std::size_t len = fk.tellg();
  fk.seekg(0, std::ios::beg);
  std::unique_ptr<std::uint8_t[]> buf(std::make_unique<std::uint8_t[]>(len));
  fk.read(reinterpret_cast<char*>(buf.get()), len);
  m_Keys.FromBuffer(buf.get(), len);
  kovri::core::RouterInfo router_info(
      (kovri::core::GetCorePath() / ROUTER_INFO).string());
  m_RouterInfo.Update(
      router_info.GetBuffer(),
      router_info.GetBufferLen());
  m_RouterInfo.SetProperty("coreVersion", I2P_VERSION);
  m_RouterInfo.SetProperty("router.version", I2P_VERSION);
  if (IsUnreachable())
    // we assume reachable until we discover firewall through peer tests
    SetReachable();
  return true;
}

void RouterContext::SaveKeys() {
  std::ofstream fk(
      (kovri::core::GetCorePath() / ROUTER_KEYS).string(),
      std::ofstream::binary);
  const std::size_t len = m_Keys.GetFullLen();
  std::unique_ptr<std::uint8_t[]> buf(std::make_unique<std::uint8_t[]>(len));
  m_Keys.ToBuffer(buf.get(), len);
  fk.write(reinterpret_cast<char*>(buf.get()), len);
}

void RouterContext::RemoveTransport(
    core::RouterInfo::Transport transport) {
  auto& addresses = m_RouterInfo.GetAddresses();
  for (std::size_t i = 0; i < addresses.size(); i++) {
    if (addresses[i].transport_style == transport) {
      addresses.erase(addresses.begin() + i);
      break;
    }
  }
}

std::shared_ptr<kovri::core::TunnelPool> RouterContext::GetTunnelPool() const {
  return kovri::core::tunnels.GetExploratoryPool();
}

void RouterContext::HandleI2NPMessage(
    const std::uint8_t* buf,
    std::size_t,
    std::shared_ptr<kovri::core::InboundTunnel> from) {
  kovri::core::HandleI2NPMessage(
      CreateI2NPMessage(
        buf,
        kovri::core::GetI2NPMessageLength(buf),
        from));
}

void RouterContext::ProcessGarlicMessage(
    std::shared_ptr<kovri::core::I2NPMessage> msg) {
  std::unique_lock<std::mutex> l(m_GarlicMutex);
  kovri::core::GarlicDestination::ProcessGarlicMessage(msg);
}

void RouterContext::ProcessDeliveryStatusMessage(
    std::shared_ptr<kovri::core::I2NPMessage> msg) {
  std::unique_lock<std::mutex> l(m_GarlicMutex);
  kovri::core::GarlicDestination::ProcessDeliveryStatusMessage(msg);
}

std::uint32_t RouterContext::GetUptime() const {
  return kovri::core::GetSecondsSinceEpoch () - m_StartupTime;
}

}  // namespace kovri
