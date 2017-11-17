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
#include "core/router/info.h"
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
      m_StartupTime(0),
      m_State(RouterState::OK) {}

// TODO(anonimal): review context's RI initialization options
// TODO(anonimal): determine which functions are truly context and which are RI
void RouterContext::Initialize(const boost::program_options::variables_map& map)
{
  // TODO(anonimal): we want context ctor initialization with non-bpo object
  m_Opts = map;

  // Set paths
  auto path = core::EnsurePath(core::GetCorePath());
  auto keys_path = (path / GetTrait(Trait::KeyFile)).string();
  auto info_path = (path / GetTrait(Trait::InfoFile)).string();

  // Set host/port for RI creation/updating
  // Note: host/port sanity checks done during configuration construction
  auto host = m_Opts["host"].as<std::string>();  // TODO(anonimal): fix default host
  auto port = m_Opts["port"].defaulted()
                  ? RandInRange32(RouterInfo::MinPort, RouterInfo::MaxPort)
                  : m_Opts["port"].as<int>();

  // Set available transports
  bool has_ntcp = m_Opts["enable-ntcp"].as<bool>();
  bool has_ssu = m_Opts["enable-ssu"].as<bool>();

  // Set startup time
  m_StartupTime = core::GetSecondsSinceEpoch();

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

      LOG(debug) << "RouterContext: creating RI from in-memory keys";
      core::RouterInfo router(
          m_Keys,
          std::make_pair(host, port),
          std::make_pair(has_ntcp, has_ssu));  // TODO(anonimal): brittle, see TODO in header

      // Update context RI
      m_RouterInfo.Update(router.GetBuffer(), router.GetBufferLen());
    }
  else  // Keys (and RI should also) exist
    {
      LOG(debug) << "RouterContext: reading existing keys into memory";
      std::vector<std::uint8_t> buf = keys.ReadAll();
      // Note: over/underflow checks done in callee
      m_Keys.FromBuffer(buf.data(), buf.size());

      LOG(debug) << "RouterContext: updating existing RI " << info_path;
      core::RouterInfo router(info_path);

      // NTCP
      if (has_ntcp && !router.GetNTCPAddress())
        router.AddNTCPAddress(host, port);
      if (!has_ntcp)
        RemoveTransport(core::RouterInfo::Transport::NTCP);

      // SSU
      if (has_ssu && !router.GetSSUAddress())
        router.AddSSUAddress(host, port, router.GetIdentHash());
      if (!has_ssu)
        {
          RemoveTransport(core::RouterInfo::Transport::SSU);

          // Remove constructed SSU capabilities
          router.SetCaps(
              router.GetCaps() & ~core::RouterInfo::Cap::SSUTesting
              & ~core::RouterInfo::Cap::SSUIntroducer);
        }

      // Update RI options (in case RI was older than these version)
      router.SetOption(GetTrait(Trait::CoreVersion), I2P_VERSION);
      router.SetOption(GetTrait(Trait::RouterVersion), I2P_VERSION);

      // Update context RI
      m_RouterInfo.Update(router.GetBuffer(), router.GetBufferLen());

      // Test for reachability of context's RI
      if (IsUnreachable())
        // we assume reachable until we discover firewall through peer tests
        SetReachable();
    }

  LOG(info) << "RouterContext: will listen on host " << host;
  LOG(info) << "RouterContext: will listen on port " << port;

  // TODO(anonimal): we don't want a flurry of micro-managed setter functions
  //  but we also don't want to re-initialize context just to update certain RI
  //  traits! Note: updating RI traits doesn't update server sockets
  LOG(debug) << "RouterContext: setting context RI traits";

  // IPv6
  m_Opts["v6"].as<bool>() ? m_RouterInfo.EnableV6() : m_RouterInfo.DisableV6();

  // Floodfill
  if (m_Opts["floodfill"].as<bool>())
    {
      m_RouterInfo.SetCaps(
          m_RouterInfo.GetCaps() | core::RouterInfo::Cap::Floodfill);
    }
  else
    {
      m_RouterInfo.SetCaps(
          m_RouterInfo.GetCaps() & ~core::RouterInfo::Cap::Floodfill);
      // we don't publish number of routers and leaseset for non-floodfill
      m_RouterInfo.GetOptions().erase(GetTrait(Trait::LeaseSets));
      m_RouterInfo.GetOptions().erase(GetTrait(Trait::Routers));
    }

  // Bandcaps
  auto const bandwidth = m_Opts["bandwidth"].as<std::string>();
  if (!bandwidth.empty())
    {
      auto const cap = core::RouterInfo::Cap::HighBandwidth;
      if (bandwidth[0] > 'L')  // TODO(anonimal): refine
        {
          if (!m_RouterInfo.HasCap(cap))
            m_RouterInfo.SetCaps(m_RouterInfo.GetCaps() | cap);
        }
      else
        {
          if (m_RouterInfo.HasCap(cap))
            m_RouterInfo.SetCaps(m_RouterInfo.GetCaps() & ~cap);
        }
    }

  // TODO(anonimal): we don't want to update twice when once at the right time will suffice
  // Update RI/commit to disk
  UpdateRouterInfo();
}

void RouterContext::UpdateRouterInfo() {
  LOG(debug) << "RouterContext: updating RI, saving to file";
  m_RouterInfo.CreateBuffer(m_Keys);
  m_RouterInfo.SaveToFile(
      (core::GetCorePath() / GetTrait(Trait::InfoFile)).string());
  m_LastUpdateTime = kovri::core::GetSecondsSinceEpoch();
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
  if (updated || ts > m_LastUpdateTime + Interval::Update)
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
  caps |= core::RouterInfo::Cap::SSUIntroducer;  // TODO(anonimal): but if SSU is disabled?...
  if (IsFloodfill())
    caps |= core::RouterInfo::Cap::Floodfill;
  m_RouterInfo.SetCaps(caps);

  // insert NTCP back
  auto& addresses = m_RouterInfo.GetAddresses();
  for (std::size_t i = 0; i < addresses.size(); i++) {
    if (addresses[i].transport == core::RouterInfo::Transport::SSU) {
      // insert NTCP address with host/port form SSU
      m_RouterInfo.AddNTCPAddress(  // TODO(anonimal): but if NTCP is disabled?...
          addresses[i].host.to_string().c_str(),
          addresses[i].port);
      break;
    }
  }
  // delete previous introducers
  for (auto& addr : addresses)
    addr.introducers.clear();

  // TODO(anonimal): if we continue to use these setters (or a single template setter),
  //  we'll need to ensure router info is updated after setting (either through context
  //  or other means).
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
  if (IsFloodfill()) {
    // update routers and leasesets
    m_RouterInfo.SetOption(
        GetTrait(Trait::LeaseSets),
        boost::lexical_cast<std::string>(kovri::core::netdb.GetNumLeaseSets()));
    m_RouterInfo.SetOption(
        GetTrait(Trait::Routers),
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
  // Remove SSU capabilities
  if (transport == core::RouterInfo::Transport::SSU)
    m_RouterInfo.SetCaps(
        m_RouterInfo.GetCaps() & ~core::RouterInfo::Cap::SSUTesting
        & ~core::RouterInfo::Cap::SSUIntroducer);
}

std::shared_ptr<kovri::core::TunnelPool> RouterContext::GetTunnelPool() const {
  return kovri::core::tunnels.GetExploratoryPool();
}

// TODO(anonimal): no real reason to have message handling here, despite inheritance

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

std::uint64_t RouterContext::GetUptime() const
{
  return core::GetSecondsSinceEpoch () - m_StartupTime;
}

}  // namespace core
}  // namespace kovri
