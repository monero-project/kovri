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
#include <boost/program_options.hpp>

#include <fstream>

#include "core/router/i2np.h"
#include "core/router/net_db/impl.h"

#include "core/util/filesystem.h"
#include "core/util/mtu.h"
#include "core/util/timestamp.h"

#include "version.h"

namespace kovri
{
namespace core
{
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
      m_EnableSSL(true),
      m_DisableSU3Verification(false),
      m_SupportsNTCP(true),
      m_SupportsSSU(true) {}

// TODO(anonimal): review context's RI initialization options
void RouterContext::Initialize(const boost::program_options::variables_map& map)
{
  m_StartupTime = core::GetSecondsSinceEpoch();
  m_Host = map["host"].as<std::string>();
  m_Port = map["port"].defaulted()
               ? RandInRange32(RouterInfo::MinPort, RouterInfo::MaxPort)
               : map["port"].as<int>();

  // Set paths
  auto path = core::EnsurePath(core::GetCorePath());
  auto keys_path = (path / ROUTER_KEYS).string();
  auto info_path = (path / ROUTER_INFO).string();

  //  Load keys for RI creation
  LOG(debug) << "RouterContext: attempting to use keys " << keys_path;
  core::InputFileStream keys(keys_path, std::ifstream::binary);

  // If key does not exist, create - then create RI
  if (keys.Fail())
    {
      LOG(debug) << "RouterContext: creating router keys";
      m_Keys = core::PrivateKeys::CreateRandomKeys(
          core::DEFAULT_ROUTER_SIGNING_KEY_TYPE);

      LOG(debug) << "RouterContext: writing router keys";
      core::OutputFileStream keys(keys_path, std::ofstream::binary);
      std::vector<std::uint8_t> buf(m_Keys.GetFullLen());
      m_Keys.ToBuffer(buf.data(), buf.size());
      keys.Write(buf.data(), buf.size());

      LOG(debug) << "RouterContext: preparing RI creation";
      core::RouterInfo router;

      router.SetRouterIdentity(GetIdentity());
      router.AddSSUAddress(m_Host, m_Port, router.GetIdentHash());
      router.AddNTCPAddress(m_Host, m_Port);
      router.SetCaps(
          core::RouterInfo::Cap::Reachable
          // TODO(anonimal): but what if we've disabled run-time SSU...
          | core::RouterInfo::Cap::SSUTesting
          | core::RouterInfo::Cap::SSUIntroducer);
      router.SetOption("netId", std::to_string(I2P_NETWORK_ID));
      router.SetOption("router.version", I2P_VERSION);

      LOG(debug) << "RouterContext: creating RI from in-memory keys";
      router.CreateBuffer(m_Keys);
      m_RouterInfo.Update(router.GetBuffer(), router.GetBufferLen());
    }
  else
    {
      LOG(debug) << "RouterContext: reading existing keys into memory";
      std::vector<std::uint8_t> buf = keys.ReadAll();
      // Note: over/underflow checks done in callee
      m_Keys.FromBuffer(buf.data(), buf.size());

      LOG(debug) << "RouterContext: updating existing RI " << info_path;
      core::RouterInfo router(info_path);

      m_RouterInfo.Update(router.GetBuffer(), router.GetBufferLen());
      m_RouterInfo.SetOption("coreVersion", I2P_VERSION);
      m_RouterInfo.SetOption("router.version", I2P_VERSION);

      if (IsUnreachable())
        // we assume reachable until we discover firewall through peer tests
        SetReachable();
    }

  // TODO(anonimal): logically speaking, this should be called *after* updating
  //   address and port (though this is called within those functions)
  UpdateRouterInfo();

  // TODO(anonimal): micro-managing RI traits on a per-function basis feels like an anti-pattern
  UpdateAddress(boost::asio::ip::address::from_string(m_Host));
  UpdatePort(m_Port);

  // TODO(anonimal): rewrite all core context setters

  SetSupportsV6(map["v6"].as<bool>());
  SetFloodfill(map["floodfill"].as<bool>());

  auto const bandwidth = map["bandwidth"].as<std::string>();
  if (!bandwidth.empty())
    {
      if (bandwidth[0] > 'L')
        SetHighBandwidth();
      else
        SetLowBandwidth();
    }

  // Set reseed options
  SetOptionReseedFrom(map["reseed-from"].as<std::string>());
  SetOptionDisableSU3Verification(map["disable-su3-verification"].as<bool>());

  // Set transport options
  SetSupportsNTCP(map["enable-ntcp"].as<bool>());
  SetSupportsSSU(map["enable-ssu"].as<bool>());

  // Set SSL option
  SetOptionEnableSSL(map["enable-ssl"].as<bool>());
}

void RouterContext::UpdateRouterInfo() {
  LOG(debug) << "RouterContext: updating RI, saving to file";
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
   {
     LOG(info) << "RouterContext: listening on port " << m_Port;
     UpdateRouterInfo();
   }
}

void RouterContext::UpdateAddress(
    const boost::asio::ip::address& host) {
  bool updated = false;
  for (auto& address : m_RouterInfo.GetAddresses()) {
    if (address.host != host && address.HasCompatibleHost(host)) {
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
        m_RouterInfo.GetCaps() | core::RouterInfo::Cap::Floodfill);
  } else {
    m_RouterInfo.SetCaps(
        m_RouterInfo.GetCaps() & ~core::RouterInfo::Cap::Floodfill);
    // we don't publish number of routers and leaseset for non-floodfill
    m_RouterInfo.GetOptions().erase(ROUTER_INFO_OPTION_LEASESETS);
    m_RouterInfo.GetOptions().erase(ROUTER_INFO_OPTION_ROUTERS);
  }
  UpdateRouterInfo();
}

void RouterContext::SetHighBandwidth() {
  auto cap = core::RouterInfo::Cap::HighBandwidth;
  if (!m_RouterInfo.HasCap(cap)) {
    m_RouterInfo.SetCaps(m_RouterInfo.GetCaps() | cap);
    UpdateRouterInfo();
  }
}

void RouterContext::SetLowBandwidth() {
  auto cap = core::RouterInfo::Cap::HighBandwidth;
  if (m_RouterInfo.HasCap(cap)) {
    m_RouterInfo.SetCaps(m_RouterInfo.GetCaps() & ~cap);
    UpdateRouterInfo();
  }
}

bool RouterContext::IsUnreachable() const {
  return m_RouterInfo.GetCaps() & core::RouterInfo::Cap::Unreachable;
}

void RouterContext::SetUnreachable() {
  // set caps
  m_RouterInfo.SetCaps(  // LU, B
      core::RouterInfo::Cap::Unreachable | core::RouterInfo::Cap::SSUTesting);
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
  caps &= ~core::RouterInfo::Cap::Unreachable;
  caps |= core::RouterInfo::Cap::Reachable;
  caps |= core::RouterInfo::Cap::SSUIntroducer;
  if (m_IsFloodfill)
    caps |= core::RouterInfo::Cap::Floodfill;
  m_RouterInfo.SetCaps(caps);

  // insert NTCP back
  auto& addresses = m_RouterInfo.GetAddresses();
  for (std::size_t i = 0; i < addresses.size(); i++) {
    if (addresses[i].transport == core::RouterInfo::Transport::SSU) {
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
    m_RouterInfo.DisableV6();  // TODO(anonimal): unused (we disable by default)
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
      & ~core::RouterInfo::Cap::SSUTesting
      & ~core::RouterInfo::Cap::SSUIntroducer);

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
        addr.transport == core::RouterInfo::Transport::NTCP) {
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
    m_RouterInfo.SetOption(
        ROUTER_INFO_OPTION_LEASESETS,
        boost::lexical_cast<std::string>(kovri::core::netdb.GetNumLeaseSets()));
    m_RouterInfo.SetOption(
        ROUTER_INFO_OPTION_ROUTERS,
        boost::lexical_cast<std::string>(kovri::core::netdb.GetNumRouters()));
    UpdateRouterInfo();
  }
}

void RouterContext::RemoveTransport(
    core::RouterInfo::Transport transport) {
  auto& addresses = m_RouterInfo.GetAddresses();
  for (std::size_t i = 0; i < addresses.size(); i++) {
    if (addresses[i].transport == transport) {
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

}  // namespace core
}  // namespace kovri
