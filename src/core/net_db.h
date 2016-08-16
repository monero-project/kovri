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

#ifndef SRC_CORE_NET_DB_H_
#define SRC_CORE_NET_DB_H_

#include <inttypes.h>

#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "i2np_protocol.h"
#include "lease_set.h"
#include "net_db_requests.h"
#include "reseed.h"
#include "router_info.h"
#include "tunnel/tunnel.h"
#include "tunnel/tunnel_pool.h"
#include "util/queue.h"

namespace i2p {
namespace data {

class NetDb {
 public:
  NetDb();
  ~NetDb();

  bool Start();
  void Stop();

  /// @return False on failure
  bool AddRouterInfo(
      const uint8_t* buf,
      int len);

  void AddRouterInfo(
      const IdentHash& ident,
      const uint8_t* buf,
      int len);

  void AddLeaseSet(
      const IdentHash& ident,
      const uint8_t* buf,
      int len,
      std::shared_ptr<i2p::tunnel::InboundTunnel> from);

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
      size_t num,
      std::set<IdentHash>& excluded) const;

  std::shared_ptr<const RouterInfo> GetClosestNonFloodfill(
      const IdentHash& destination,
      const std::set<IdentHash>& excluded) const;

  void SetUnreachable(
      const IdentHash& ident,
      bool unreachable);

  void PostI2NPMsg(
      std::shared_ptr<const I2NPMessage> msg);

  bool Reseed();

  int GetNumRouters() const {
    return m_RouterInfos.size();
  }

  int GetNumFloodfills() const {
    return m_Floodfills.size();
  }

  int GetNumLeaseSets() const {
    return m_LeaseSets.size();
  }

 private:
  bool CreateNetDb(boost::filesystem::path directory);
  void Load();
  void SaveUpdated();
  void Run();  // exploratory thread
  void Explore(int num_destinations);
  void Publish();
  void ManageLeaseSets();
  void ManageRequests();

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
  i2p::util::Queue<std::shared_ptr<const I2NPMessage>> m_Queue;

  std::unique_ptr<i2p::data::Reseed> m_Reseed;

  friend class NetDbRequests;
  NetDbRequests m_Requests;

  static const char m_NetDbPath[];
};

extern NetDb netdb;

}  // namespace data
}  // namespace i2p

#endif  // SRC_CORE_NET_DB_H_
