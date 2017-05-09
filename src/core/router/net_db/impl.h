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

#ifndef SRC_CORE_ROUTER_NET_DB_IMPL_H_
#define SRC_CORE_ROUTER_NET_DB_IMPL_H_

#include <cstddef>
#include <cstdint>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "core/router/i2np.h"
#include "core/router/info.h"
#include "core/router/lease_set.h"
#include "core/router/net_db/requests.h"
#include "core/router/tunnel/pool.h"
#include "core/router/tunnel/impl.h"

#include "core/util/exception.h"
#include "core/util/queue.h"

namespace kovri {
namespace core {

/// @class NetDbTraits
struct NetDbTraits
{
  /// @enum Time
  /// @brief NetDb time-related traits
  enum Time : const std::uint32_t
  {
    /// @notes Measured in milliseconds
    WaitForMessageTimeout = 15000,

    /// @notes Measured in seconds
    ManageRequests = 15,

    /// @notes Measured in seconds
    Save = 60,

    /// @notes Measured in seconds
    PublishRouterInfo = 2400,

    /// @notes Measured in seconds
    Exploratory = 30,

    /// @notes Measured in seconds
    DelayedExploratory = 90,

    /// @brief Measured in milliseconds
    RouterExpiration = 3600 * 1000,

    /// @brief Defines a grace period when a router has just started to not set
    ///   expired routers as unreachable, so tunnels will be built quickly
    /// @notes Measured in seconds
    RouterStartupPeriod = 600,

    /// @brief Defines a grace period for expiring routers when router count
    ///   exceeds maximum unreachable routers
    /// @notes Measured in hours
    RouterMinGracePeriod = 30,

    /// @brief Defines a grace period for expiring routers when router count
    ///   exceeds minimum unreachable routers
    /// @notes Measured in hours
    RouterMaxGracePeriod = 72,
  };

  /// @enum Size
  /// @brief NetDb sizes/counts-related traits
  enum Size : const std::uint16_t
  {
    /// @brief Minimum number of known routers desired for building tunnels
    MinKnownRouters = 800,

    /// @brief Desired number of known routers for building tunnels
    DesiredKnownRouters = 2500,

    /// @brief Minimum number of exploratory tunnels to be built
    /// @notes Used when min known routers is less than known routers and less
    ///   than preferred known router count
    MinExploratoryTunnels = 1,

    /// @brief Number of exploratory tunnels to be built for
    /// @notes Used when router count is less than min known routers
    MaxExploratoryTunnels = 9,

    /// @brief Max number of NetDb messages that can be processed in succession
    MaxMessagesRead = 100,

    /// @brief Max number of excluded peers for handling database lookup messages
    MaxExcludedPeers = 512,

    /// @brief Defines the threshold where routers get checked if they have
    ///  expired (i.e., unreachable)
    RouterUnreachableThreshold = 75,

    /// @brief Minimum limit for number of routers to be set unreachable
    MinRouterUnreachable = 120,

    /// @brief the maximum limit for number of routers to be set unreachable
    MaxRouterUnreachable = 300,
  };
};

class NetDb : public NetDbTraits {
 public:
  NetDb();
  ~NetDb();

  bool Start();
  void Stop();

  /// @return False on failure
  bool AddRouterInfo(
      const std::uint8_t* buf,
      int len);

  void AddRouterInfo(
      const IdentHash& ident,
      const std::uint8_t* buf,
      int len);

  void AddLeaseSet(
      const IdentHash& ident,
      const std::uint8_t* buf,
      int len,
      std::shared_ptr<kovri::core::InboundTunnel> from);

  std::shared_ptr<RouterInfo> FindRouter(
      const IdentHash& ident) const;

  std::shared_ptr<LeaseSet> FindLeaseSet(
      const IdentHash& destination) const;

  void RequestDestination(
      const IdentHash& destination,
      RequestedDestination::RequestComplete request_complete = nullptr);

  void HandleDatabaseStoreMsg(
      std::shared_ptr<const I2NPMessage> msg);

  void HandleDatabaseSearchReplyMsg(
      std::shared_ptr<const I2NPMessage> msg);

  void HandleDatabaseLookupMsg(
      std::shared_ptr<const I2NPMessage> msg);

  std::shared_ptr<const RouterInfo> GetRandomRouter() const;

  std::shared_ptr<const RouterInfo> GetRandomRouter(
      std::shared_ptr<const RouterInfo> compatible_with) const;

  std::shared_ptr<const RouterInfo> GetHighBandwidthRandomRouter(
      std::shared_ptr<const RouterInfo> compatible_with) const;

  std::shared_ptr<const RouterInfo> GetRandomPeerTestRouter() const;

  std::shared_ptr<const RouterInfo> GetRandomIntroducer() const;

  std::shared_ptr<const RouterInfo> GetClosestFloodfill(
      const IdentHash& destination,
      const std::set<IdentHash>& excluded) const;

  std::vector<IdentHash> GetClosestFloodfills(
      const IdentHash& destination,
      std::size_t num,
      std::set<IdentHash>& excluded) const;

  std::shared_ptr<const RouterInfo> GetClosestNonFloodfill(
      const IdentHash& destination,
      const std::set<IdentHash>& excluded) const;

  void SetUnreachable(
      const IdentHash& ident,
      bool unreachable);

  void PostI2NPMsg(
      std::shared_ptr<const I2NPMessage> msg);

  // TODO(unassigned): std::size_t refactor
  int GetNumRouters() const {
    return m_RouterInfos.size();
  }

  // TODO(unassigned): std::size_t refactor
  int GetNumFloodfills() const {
    return m_Floodfills.size();
  }

  // TODO(unassigned): std::size_t refactor
  int GetNumLeaseSets() const {
    return m_LeaseSets.size();
  }

  // Java i2p defined
  const std::uint8_t MIN_REQUIRED_ROUTERS = 50;

 private:
  bool CreateNetDb(boost::filesystem::path directory);
  /// @brief Loads RI's from disk
  /// @return False on failure
  bool Load();
  void SaveUpdated();
  void Run();  // exploratory thread
  void Explore(int num_destinations);
  void Publish();
  void ManageLeaseSets();
  void ManageRequests();

  /// @brief Randomly selects a router from stored RI's according to filter
  ///   (and other criteria determined internally)
  /// @param filter Template type which serves as filter for criteria
  template<typename Filter>
  std::shared_ptr<const RouterInfo> GetRandomRouter(
      Filter filter) const;

 private:
  std::map<IdentHash, std::shared_ptr<LeaseSet>> m_LeaseSets;
  mutable std::mutex m_RouterInfosMutex;
  std::map<IdentHash, std::shared_ptr<RouterInfo>> m_RouterInfos;
  mutable std::mutex m_FloodfillsMutex;
  std::list<std::shared_ptr<RouterInfo>> m_Floodfills;

  bool m_IsRunning;
  std::unique_ptr<std::thread> m_Thread;

  // of I2NPDatabaseStoreMsg
  kovri::core::Queue<std::shared_ptr<const I2NPMessage>> m_Queue;

  friend class NetDbRequests;
  NetDbRequests m_Requests;

  kovri::core::Exception m_Exception;
};

extern NetDb netdb;

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_NET_DB_IMPL_H_
