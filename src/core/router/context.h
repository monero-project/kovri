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

#ifndef SRC_CORE_ROUTER_CONTEXT_H_
#define SRC_CORE_ROUTER_CONTEXT_H_

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "core/router/garlic.h"
#include "core/router/identity.h"
#include "core/router/info.h"

namespace kovri {
// TODO(anonimal): this belongs in core namespace

const char ROUTER_INFO[] = "router.info";
const char ROUTER_KEYS[] = "router.keys";
const int ROUTER_INFO_UPDATE_INTERVAL = 1800;  // 30 minutes

const char ROUTER_INFO_PROPERTY_LEASESETS[] = "netdb.knownLeaseSets";
const char ROUTER_INFO_PROPERTY_ROUTERS[] = "netdb.knownRouters";

enum RouterStatus {
  eRouterStatusOK = 0,
  eRouterStatusTesting = 1,
  eRouterStatusFirewalled = 2
};

class RouterContext : public kovri::core::GarlicDestination {
 public:
  RouterContext();

  /// Initializes the router context, must be called before use
  /// @param host The external address of this router
  /// @param port The external port of this router
  void Init(
      const std::string& host,
      int port);

  // @return This RouterContext's RouterInfo
  kovri::core::RouterInfo& GetRouterInfo() {
    return m_RouterInfo;
  }

  // @return This RouterContext's RouterInfo wrapped in a smart pointer
  std::shared_ptr<const kovri::core::RouterInfo> GetSharedRouterInfo() const  {
    return std::shared_ptr<const kovri::core::RouterInfo>(
        &m_RouterInfo,
        [](const kovri::core::RouterInfo *) {});
  }

  // @return How long this RouterContext has been online in seconds since epoch
  std::uint32_t GetUptime() const;

  // @return Time that this RouterContext started in seconds since epoch
  std::uint32_t GetStartupTime() const {
    return m_StartupTime;
  }

  // @return Time this RouterContext last updated its RouterInfo
  std::uint64_t GetLastUpdateTime() const {
    return m_LastUpdateTime;
  }

  // @return
  // eRouterStatusOk - if the RouterContext is fully port forwarded,
  // eRouterStatusTesting - if the RouterContext is testing connectivity
  // eRouterStatusFirewalled - if the RouterContext detects being firewalled
  RouterStatus GetStatus() const {
    return m_Status;
  }

  // Set RouterContext's Status
  // @see GetStatus
  // @param status the new status this RouterContext will have
  void SetStatus(
      RouterStatus status) {
    m_Status = status;
  }

  // Called from Daemon, updates this RouterContext's Port.
  // Rebuilds RouterInfo
  // @param port port number
  void UpdatePort(int port);

  // Called From SSU or Daemon.
  // Update Our IP Address, external IP Address if behind NAT.
  // Rebuilds RouterInfo
  // @param host the ip address
  void UpdateAddress(
      const boost::asio::ip::address& host);

  // Add an SSU introducer to our RouterInfo.
  // Rebuild RouterInfo.
  // @param routerInfo the RouterInfo to use in the Introducer
  // @param tag
  bool AddIntroducer(
      const kovri::core::RouterInfo& routerInfo,
      std::uint32_t tag);

  // Remove and SSU introducer given its endpoint.
  // Rebuilds RouterInfo.
  // @param e the SSU introducer's endpoint
  void RemoveIntroducer(
      const boost::asio::ip::udp::endpoint& e);

  // @return true if other routers cannot reach us otherwise false
  bool IsUnreachable() const;

  // Set that other routers cannot reach us
  void SetUnreachable();

  // Set that other routers *can* reach us
  void SetReachable();

  // @return true if we are a floodfill router otherwise false
  bool IsFloodfill() const {
    return m_IsFloodfill;
  }

  // Set if we are a floodfill router, rebuild RouterInfo.
  // @param floodfill true if we want to become floodfill, false if we don't
  void SetFloodfill(
      bool floodfill);

  // Mark ourselves as having high bandwidth.
  // Changes caps flags.
  // Rebuilds RouterInfo.
  void SetHighBandwidth();

  // Mark ourselves as having low (aka NOT high) Bandwidth.
  // Changes Capacity Flags.
  // Rebuilds RouterInfo.
  void SetLowBandwidth();

  // @return true if we are going to accept tunnels right now.
  bool AcceptsTunnels() const {
    return m_AcceptsTunnels;
  }

  // Set explicitly if we want to accept tunnels right now.
  // @param acceptTunnels true if we want to accept tunnels otherwise false
  void SetAcceptsTunnels(
      bool acceptsTunnels) {
    m_AcceptsTunnels = acceptsTunnels;
  }

  // @return true if we support IPv6 connectivity otherwise false
  bool SupportsV6() const {
    return m_RouterInfo.IsV6();
  }

  /// @return true if we support the NTCP transport, false otherwise
  bool SupportsNTCP() const {
    return m_SupportsNTCP;
  }

  /// @return true if we support the SSU transport, false otherwise
  bool SupportsSSU() const {
    return m_SupportsSSU;
  }

  // Set if we support IPv6 connectivity.
  // Rebuilds RouterInfo.
  // @param supportsV6 true if we support IPv6, false if we don't
  void SetSupportsV6(
      bool supportsV6);

  /// @brief Sets whether or not this router supports the NTCP transport
  /// @param supportsNTCP true if NTCP is supported, false otherwise
  void SetSupportsNTCP(bool supportsNTCP);

  /// @brief Sets whether or not this router supports the SSU transport
  /// @param supportsNTCP true if SSU is supported, false otherwise
  void SetSupportsSSU(bool supportsSSU);

  // Called From NTCPSession.
  // Update our NTCP IPv6 address.
  // Rebuilds RouterInfo.
  // @param host Our reachable IPv6 address for NTCP
  void UpdateNTCPV6Address(
      const boost::asio::ip::address& host);

  // Update Stats in Router Info when floodfill.
  // Rebuilds RouterInfo.
  void UpdateStats();

  // implements LocalDestination
  const kovri::core::PrivateKeys& GetPrivateKeys() const {
    return m_Keys;
  }

  const std::uint8_t* GetEncryptionPrivateKey() const {
    return m_Keys.GetPrivateKey();
  }

  const std::uint8_t* GetEncryptionPublicKey() const {
    return GetIdentity().GetStandardIdentity().public_key;
  }

  void SetLeaseSetUpdated() {}

  // implements GarlicDestination
  std::shared_ptr<const kovri::core::LeaseSet> GetLeaseSet() {
    return nullptr;
  }

  std::shared_ptr<kovri::core::TunnelPool> GetTunnelPool() const;

  void HandleI2NPMessage(
      const std::uint8_t* buf,
      std::size_t len,
      std::shared_ptr<kovri::core::InboundTunnel> from);

  // override GarlicDestination
  void ProcessGarlicMessage(
      std::shared_ptr<kovri::core::I2NPMessage> msg);

  void ProcessDeliveryStatusMessage(
      std::shared_ptr<kovri::core::I2NPMessage> msg);

  /**
   * Note: these reseed functions are not ideal but
   * they fit into our current design. We need to initialize
   * here because we cannot (should not/don't need to) link
   * unit-tests to executables (src/app) so, without these,
   * current reseed tests won't compile.
   */

  /// @brief Sets user-supplied reseed stream
  void SetOptionReseedFrom(
      const std::string& stream) {
    m_ReseedFrom = stream;
  }

  /// @return User-supplied reseed stream
  std::string GetOptionReseedFrom() {
    return m_ReseedFrom;
  }

  /// @brief Sets user-supplied reseed SSL option
  void SetOptionReseedSkipSSLCheck(
      bool option) {
    m_ReseedSkipSSLCheck = option;
  }

  /// @return User-supplied option to skip SSL
  bool GetOptionReseedSkipSSLCheck() {
    return m_ReseedSkipSSLCheck;
  }

 private:
  void CreateNewRouter();
  void NewRouterInfo();
  void UpdateRouterInfo();
  bool Load();
  void SaveKeys();
  void RemoveTransport(kovri::core::RouterInfo::TransportStyle transport);

 private:
  kovri::core::RouterInfo m_RouterInfo;
  kovri::core::PrivateKeys m_Keys;
  std::uint64_t m_LastUpdateTime;
  bool m_AcceptsTunnels, m_IsFloodfill;
  std::uint64_t m_StartupTime;  // in seconds since epoch
  RouterStatus m_Status;
  std::mutex m_GarlicMutex;
  std::string m_Host;
  int m_Port;
  std::string m_ReseedFrom;
  bool m_ReseedSkipSSLCheck;
  bool m_SupportsNTCP, m_SupportsSSU;
};

extern RouterContext context;

}  // namespace kovri

#endif  // SRC_CORE_ROUTER_CONTEXT_H_
