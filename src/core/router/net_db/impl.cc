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

#include "core/router/net_db/impl.h"

#include <boost/asio.hpp>

#include <string.h>

#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "core/crypto/rand.h"
#include "core/crypto/util/compression.h"

#include "core/router/context.h"
#include "core/router/garlic.h"
#include "core/router/i2np.h"
#include "core/router/transports/impl.h"
#include "core/router/tunnel/impl.h"

#include "core/util/base64.h"
#include "core/util/filesystem.h"
#include "core/util/i2p_endian.h"
#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {

const char NetDb::m_NetDbPath[] = "netDb";

// Simply instantiating in namespace scope ties into, and is limited by, the current singleton design
// TODO(unassigned): refactoring this requires global work but will help to remove the singleton
NetDb netdb;

NetDb::NetDb()
    : m_IsRunning(false),
      m_Thread(nullptr) {}

NetDb::~NetDb() {
  Stop();
}

bool NetDb::Start() {
  if (!Load())
    return false;
  m_IsRunning = true;
  m_Thread = std::make_unique<std::thread>(std::bind(&NetDb::Run, this));
  return m_IsRunning;
}

void NetDb::Stop() {
  if (m_IsRunning) {
    for (auto it : m_RouterInfos)
      it.second->SaveProfile();
    DeleteObsoleteProfiles();
    m_RouterInfos.clear();
    m_Floodfills.clear();
    if (m_Thread) {
      m_IsRunning = false;
      m_Queue.WakeUp();
      m_Thread->join();
      m_Thread.reset(nullptr);
    }
    m_LeaseSets.clear();
    m_Requests.Stop();
  }
}

void NetDb::Run() {
  std::uint32_t last_save = 0,
           last_publish = 0,
           last_exploratory = 0,
           last_manage_request = 0;
  while (m_IsRunning) {
    try {
      // if there are no messages a timeout is executed to wait
      // for messages to be received
      auto msg =
        m_Queue.GetNextWithTimeout(
            static_cast<std::uint16_t>(NetDbInterval::WaitForMessageTimeout));
      if (msg) {
        std::uint8_t num_msgs = 0;
        while (msg) {
          switch (msg->GetTypeID()) {
            case I2NPDatabaseStore:
              LogPrint(eLogDebug, "NetDb: DatabaseStore");
              HandleDatabaseStoreMsg(msg);
            break;
            case I2NPDatabaseSearchReply:
              LogPrint(eLogDebug, "NetDb: DatabaseSearchReply");
              HandleDatabaseSearchReplyMsg(msg);
            break;
            case I2NPDatabaseLookup:
              LogPrint(eLogDebug, "NetDb: DatabaseLookup");
              HandleDatabaseLookupMsg(msg);
            break;
            default:
              // TODO(unassigned): error handling
              LogPrint(eLogError,
                  "NetDb: unexpected message type ", msg->GetTypeID());
              // kovri::HandleI2NPMessage(msg);
          }
          if (num_msgs > static_cast<std::uint16_t>(NetDbSize::MaxMessagesRead))
            break;
          msg = m_Queue.Get();
          num_msgs++;
        }
      }
      if (!m_IsRunning)
        break;
      std::uint64_t ts = kovri::core::GetSecondsSinceEpoch();
      // builds tunnels for requested destinations
      if (ts - last_manage_request >=
          static_cast<std::uint16_t>(NetDbInterval::ManageRequests)) {
        m_Requests.ManageRequests();
        last_manage_request = ts;
      }
      // save routers, manage leasesets and validate subscriptions
      if (ts - last_save >= static_cast<std::uint16_t>(NetDbInterval::Save)) {
        if (last_save) {
          SaveUpdated();
          ManageLeaseSets();
        }
        last_save = ts;
      }
      // publishes router info to a floodfill at Nth interval
      if (ts - last_publish >=
	  static_cast<std::uint16_t>(NetDbInterval::PublishRouterInfo)) {
        Publish();
        last_publish = ts;
      }
      // builds exploratory tunnels at Nth interval to find more peers
      if (ts - last_exploratory >= static_cast<std::uint16_t>(NetDbInterval::Exploratory)) {
        // Set default exploratory count
        std::uint16_t exploratory_count =
          static_cast<std::uint16_t>(NetDbSize::MinExploratoryTunnels);
        // Get number of current available routers
        auto known_routers = GetNumRouters();
        // Evaluates if a router has a sufficient number of known routers
        // to use for building tunnels and sets exploratory count as needed
        if (known_routers <
            static_cast<std::uint16_t>(NetDbSize::FavouredKnownRouters)
            || ts - last_exploratory >=
            static_cast<std::uint16_t>(NetDbInterval::DelayedExploratory)) {
          // Test if we're below the desired threshold
          if (known_routers <
              static_cast<std::uint16_t>(NetDbSize::MinKnownRouters)) {
            // Set the max exploratory count
            exploratory_count =
              static_cast<std::uint16_t>(NetDbSize::MaxExploratoryTunnels);
          }
        }
        m_Requests.ManageRequests();
        Explore(exploratory_count);
        last_exploratory = ts;
      }
    } catch(std::exception& ex) {
      LogPrint(eLogError, "NetDb::Run(): ", ex.what());
    }
  }
}

bool NetDb::AddRouterInfo(
    const std::uint8_t* buf,
    int len) {
  IdentityEx identity;
  if (!identity.FromBuffer(buf, len)) {
    LogPrint(eLogError, "NetDb: unable to add router info");
    return false;
  }
  AddRouterInfo(identity.GetIdentHash(), buf, len);
  return true;
}

void NetDb::AddRouterInfo(
    const IdentHash& ident,
    const std::uint8_t* buf,
    int len) {
  auto r = FindRouter(ident);
  if (r) {
    auto ts = r->GetTimestamp();
    r->Update(buf, len);
    if (r->GetTimestamp() > ts)
      LogPrint(eLogInfo, "NetDb: RouterInfo updated");
  } else {
    LogPrint(eLogDebug, "NetDb: new RouterInfo added");
    r = std::make_shared<RouterInfo> (buf, len); {
      std::unique_lock<std::mutex> l(m_RouterInfosMutex);
      m_RouterInfos[r->GetIdentHash()] = r;
    }
    if (r->IsFloodfill()) {
      std::unique_lock<std::mutex> l(m_FloodfillsMutex);
      m_Floodfills.push_back(r);
    }
  }
  // take care about requested destination
  m_Requests.RequestComplete(ident, r);
}

void NetDb::AddLeaseSet(
    const IdentHash& ident,
    const std::uint8_t* buf,
    int len,
    std::shared_ptr<kovri::core::InboundTunnel> from) {
  if (!from) {  // unsolicited LS must be received directly
    auto it = m_LeaseSets.find(ident);
    if (it != m_LeaseSets.end()) {
      it->second->Update(buf, len);
      if (it->second->IsValid()) {
        LogPrint(eLogInfo, "NetDb: LeaseSet updated");
      } else {
        LogPrint(eLogInfo, "NetDb: LeaseSet update failed");
        m_LeaseSets.erase(it);
      }
    } else {
      auto lease_set = std::make_shared<LeaseSet>(buf, len);
      if (lease_set->IsValid()) {
        LogPrint(eLogInfo, "NetDb: new LeaseSet added");
        m_LeaseSets[ident] = lease_set;
      } else {
        LogPrint(eLogError, "NetDb: new LeaseSet validation failed");
      }
    }
  }
}

std::shared_ptr<RouterInfo> NetDb::FindRouter(
    const IdentHash& ident) const {
  std::unique_lock<std::mutex> l(m_RouterInfosMutex);
  auto it = m_RouterInfos.find(ident);
  if (it != m_RouterInfos.end())
    return it->second;
  else
    return nullptr;
}

std::shared_ptr<LeaseSet> NetDb::FindLeaseSet(
    const IdentHash& destination) const {
  auto it = m_LeaseSets.find(destination);
  if (it != m_LeaseSets.end())
    return it->second;
  else
    return nullptr;
}

void NetDb::SetUnreachable(
    const IdentHash& ident,
    bool is_unreachable) {
  auto it = m_RouterInfos.find(ident);
  if (it != m_RouterInfos.end())
    return it->second->SetUnreachable(is_unreachable);
}

// TODO(unassigned): Move to reseed and/or scheduled tasks.
// (In java version, scheduler fixes this as well as sort RIs.)
bool NetDb::CreateNetDb(
    boost::filesystem::path directory) {
  LogPrint(eLogInfo, "NetDb: creating ", directory.string());
  if (!boost::filesystem::create_directory(directory)) {
    LogPrint(eLogError, "NetDb: failed to create ", directory.string());
    return false;
  }
  // list of chars might appear in base64 string
  const char* chars = kovri::core::GetBase64SubstitutionTable();  // 64 bytes
  boost::filesystem::path suffix;
  for (int i = 0; i < 64; i++) {
#ifndef _WIN32
    suffix = std::string("/r") + chars[i];
#else
    suffix = std::string("\\r") + chars[i];
#endif
    if (!boost::filesystem::create_directory(
          boost::filesystem::path(
            directory / suffix) ))
      return false;
  }
  return true;
}

bool NetDb::Load() {
  boost::filesystem::path p(kovri::core::GetDataPath() / m_NetDbPath);
  if (!boost::filesystem::exists(p)) {
    // seems netDb doesn't exist yet
    if (!CreateNetDb(p))
      return false;
  }
  // make sure we cleanup netDb from previous attempts
  m_RouterInfos.clear();
  m_Floodfills.clear();
  // load routers now
  std::uint64_t ts = kovri::core::GetMillisecondsSinceEpoch();
  boost::filesystem::directory_iterator end;
  std::size_t num_routers = 0;
  for (boost::filesystem::directory_iterator it(p); it != end; ++it) {
    if (boost::filesystem::is_directory(it->status())) {
      for (boost::filesystem::directory_iterator it1(it->path());
          it1 != end;
          ++it1) {
#if BOOST_VERSION > 10500
        const std::string& full_path = it1->path().string();
#else
        const std::string& full_path = it1->path();
#endif
        auto r = std::make_shared<RouterInfo>(full_path);
        if (!r->IsUnreachable() &&
            (!r->UsesIntroducer() || ts < r->GetTimestamp() +
             static_cast<std::uint32_t>(NetDbTime::RouterExpiration))) {
          r->DeleteBuffer();
          r->ClearProperties();  // properties are not used for regular routers
          m_RouterInfos[r->GetIdentHash()] = r;
          if (r->IsFloodfill())
            m_Floodfills.push_back(r);
          num_routers++;
        } else {
          bool is_removed = boost::filesystem::remove(full_path);
          if (is_removed)
            LogPrint(eLogInfo,
                "NetDb: ", full_path, " unreachable router removed");
        }
      }
    }
  }
  LogPrint(eLogInfo, "NetDb: ", num_routers, " routers loaded");
  LogPrint(eLogInfo, "NetDb: ", m_Floodfills.size(), " floodfills loaded");
  return true;
}

void NetDb::SaveUpdated() {
  auto GetFilePath = [](
      const boost::filesystem::path& directory,
      const RouterInfo* router_info) {
    std::string s(router_info->GetIdentHashBase64());
    return directory / (std::string("r") + s[0]) / ("router_info_" + s + ".dat");
  };
  boost::filesystem::path full_directory(
      kovri::core::GetDataPath() / m_NetDbPath);
  int count = 0,
      deleted_count = 0;
  auto total = GetNumRouters();
  std::uint64_t ts = kovri::core::GetMillisecondsSinceEpoch();
  for (auto it : m_RouterInfos) {
    if (it.second->IsUpdated()) {
      std::string f = GetFilePath(full_directory, it.second.get()).string();
      it.second->SaveToFile(f);
      it.second->SetUpdated(false);
      it.second->SetUnreachable(false);
      it.second->DeleteBuffer();
      count++;
    } else {
      // RouterInfo expires after N minutes if it uses an introducer
      if (it.second->UsesIntroducer() && ts > it.second->GetTimestamp()
          + static_cast<std::uint32_t>(NetDbTime::RouterExpiration)) {
        it.second->SetUnreachable(true);
        // if the router count is greater than the threshold check, and the router
        // is no longer starting up, then continue to check for unreachable routers
      } else if (total >
          static_cast<std::uint16_t>(NetDbSize::RouterCheckUnreachableThreshold)
          && ts > (kovri::context.GetStartupTime()
            + static_cast<std::uint32_t>(NetDbTime::RouterStartupPeriod)) * 1000LL) {
        if (kovri::context.IsFloodfill()) {
          if (ts > it.second->GetTimestamp()
              + static_cast<std::uint32_t>(NetDbTime::RouterExpiration)) {
            it.second->SetUnreachable(true);
            total--;
          }
          //  if router count is higher, expiration date for unreachable
          //  peers is shorter
        } else if (total >
            static_cast<std::uint16_t>(NetDbSize::MaxRouterCheckUnreachable)) {
          if (ts > it.second->GetTimestamp()
              + static_cast<std::uint32_t>(NetDbTime::RouterMinGracePeriod)
              * static_cast<std::uint32_t>(NetDbTime::RouterExpiration)) {
            it.second->SetUnreachable(true);
            total--;
          }
          //  if router count is low, expiration date for unreachable
          //  peers is longer
        } else if (total >
            static_cast<std::uint16_t>(NetDbSize::MinRouterCheckUnreachable)) {
           if (ts > it.second->GetTimestamp()
               + static_cast<std::uint32_t>(NetDbTime::RouterMaxGracePeriod)
               * static_cast<std::uint32_t>(NetDbTime::RouterExpiration)) {
            it.second->SetUnreachable(true);
            total--;
          }
        }
      }
      if (it.second->IsUnreachable()) {
        total--;
        // delete RI file
        bool is_removed =
	  boost::filesystem::remove(
	      GetFilePath(full_directory, it.second.get()));
	 if (is_removed)
	   deleted_count++;
        // delete from floodfills list
        if (it.second->IsFloodfill()) {
          std::unique_lock<std::mutex> l(m_FloodfillsMutex);
          m_Floodfills.remove(it.second);
        }
      }
    }
  }
  if (count > 0)
    LogPrint(eLogInfo, "NetDb: ", count, " new/updated routers saved");
  if (deleted_count > 0) {
    LogPrint(eLogInfo, "NetDb: ", deleted_count, " routers deleted");
    // clean up RouterInfos table
    std::unique_lock<std::mutex> l(m_RouterInfosMutex);
    for (auto it = m_RouterInfos.begin(); it != m_RouterInfos.end();) {
      if (it->second->IsUnreachable()) {
        it->second->SaveProfile();
        it = m_RouterInfos.erase(it);
      } else {
        it++;
      }
    }
  }
}

void NetDb::RequestDestination(
    const IdentHash& destination,
    RequestedDestination::RequestComplete request_complete) {
  auto dest =
    m_Requests.CreateRequest(
        destination,
        false,
        request_complete);  // non-exploratory
  if (!dest) {
    LogPrint(eLogWarn,
        "NetDb: destination ", destination.ToBase64(), " was already requested");
    return;
  }
  auto floodfill =
    GetClosestFloodfill(
        destination,
        dest->GetExcludedPeers());
  if (floodfill) {
    kovri::core::transports.SendMessage(
        floodfill->GetIdentHash(),
        dest->CreateRequestMessage(
            floodfill->GetIdentHash()));
  } else {
    LogPrint(eLogError, "NetDb: no floodfills found");
    m_Requests.RequestComplete(destination, nullptr);
  }
}

void NetDb::HandleDatabaseStoreMsg(
    std::shared_ptr<const I2NPMessage> m) {
  const std::uint8_t* buf = m->GetPayload();
  std::size_t len = m->GetSize();
  IdentHash ident(buf + DATABASE_STORE_KEY_OFFSET);
  if (ident.IsZero()) {
    LogPrint(eLogError, "NetDb: database store with zero ident, dropped");
    return;
  }
  std::uint32_t reply_token = bufbe32toh(buf + DATABASE_STORE_REPLY_TOKEN_OFFSET);
  std::size_t offset = DATABASE_STORE_HEADER_SIZE;
  if (reply_token) {
    auto delivery_status = CreateDeliveryStatusMsg(reply_token);
    std::uint32_t tunnel_ID = bufbe32toh(buf + offset);
    offset += 4;
    if (!tunnel_ID) {  // send response directly
      kovri::core::transports.SendMessage(buf + offset, delivery_status);
    } else {
      auto pool = kovri::core::tunnels.GetExploratoryPool();
      auto outbound = pool ? pool->GetNextOutboundTunnel() : nullptr;
      if (outbound)
        outbound->SendTunnelDataMsg(buf + offset, tunnel_ID, delivery_status);
      else
        LogPrint(eLogError,
            "NetDb: no outbound tunnels for DatabaseStore reply found");
    }
    offset += 32;
    if (context.IsFloodfill()) {
      // flood it
      auto flood_msg = ToSharedI2NPMessage(NewI2NPShortMessage());
      std::uint8_t* payload = flood_msg->GetPayload();
      memcpy(payload, buf, 33);  // key + type
      // zero reply token
      htobe32buf(payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0);
      memcpy(payload + DATABASE_STORE_HEADER_SIZE, buf + offset, len - offset);
      flood_msg->len += DATABASE_STORE_HEADER_SIZE + len -offset;
      flood_msg->FillI2NPMessageHeader(I2NPDatabaseStore);
      std::set<IdentHash> excluded;
      for (int i = 0; i < 3; i++) {
        auto floodfill = GetClosestFloodfill(ident, excluded);
        if (floodfill)
          kovri::core::transports.SendMessage(
              floodfill->GetIdentHash(),
              flood_msg);
      }
    }
  }
  if (buf[DATABASE_STORE_TYPE_OFFSET]) {  // type
    LogPrint(eLogDebug, "NetDb: LeaseSet");
    AddLeaseSet(ident, buf + offset, len - offset, m->from);
  } else {
    LogPrint(eLogDebug, "NetDb: RouterInfo");
    std::size_t size = bufbe16toh(buf + offset);
    offset += 2;
    if (size > MAX_RI_BUFFER_SIZE || size > len - offset) {
      LogPrint(eLogError,
          "NetDb: invalid RouterInfo length ", static_cast<int>(size));
      return;
    }
    try {
      kovri::core::Gunzip decompressor;
      decompressor.Put(buf + offset, size);
      std::array<std::uint8_t, MAX_RI_BUFFER_SIZE> uncompressed;
      std::size_t uncompressed_size = decompressor.MaxRetrievable();
      if (uncompressed_size <= MAX_RI_BUFFER_SIZE) {
        decompressor.Get(uncompressed.data(), uncompressed_size);
        AddRouterInfo(ident, uncompressed.data(), uncompressed_size);
      } else {
        LogPrint(eLogError,
            "NetDb: invalid RouterInfo uncompressed length ",
            static_cast<int>(uncompressed_size));
      }
    } catch (...) {
      LogPrint(eLogError,
          "NetDb: HandleDatabaseStoreMsg() caught exception ");
    }
  }
}

void NetDb::HandleDatabaseSearchReplyMsg(
    std::shared_ptr<const I2NPMessage> msg) {
  const std::uint8_t* buf = msg->GetPayload();
  std::array<char, 48> key;
  int l = kovri::core::ByteStreamToBase64(buf, 32, key.data(), key.size());
  key.at(l) = 0;
  int num = buf[32];  // num
  LogPrint(eLogInfo, "NetDb: DatabaseSearchReply for ", key.data(), " num=", num);
  IdentHash ident(buf);
  auto dest = m_Requests.FindRequest(ident);
  if (dest) {
    bool delete_dest = true;
    if (num > 0) {
      auto pool = kovri::core::tunnels.GetExploratoryPool();
      auto outbound = pool ? pool->GetNextOutboundTunnel() : nullptr;
      auto inbound = pool ? pool->GetNextInboundTunnel() : nullptr;
      if (!dest->IsExploratory()) {
        // reply to our destination. Try other floodfills
        if (outbound && inbound) {
          std::vector<kovri::core::TunnelMessageBlock> msgs;
          auto count = dest->GetExcludedPeers().size();
          std::size_t max_ff(7);
          if (count < max_ff) {
            auto next_floodfill = GetClosestFloodfill(
                dest->GetDestination(),
                dest->GetExcludedPeers());
            if (next_floodfill) {
              // tell floodfill about us
              msgs.push_back(
                  kovri::core::TunnelMessageBlock {
                  kovri::core::e_DeliveryTypeRouter,
                  next_floodfill->GetIdentHash(),
                  0,
                  CreateDatabaseStoreMsg()
                  });
              // request destination
              LogPrint(eLogInfo, 
                  "NetDb: trying ", key.data(),
                  " at ", count,
                  " floodfill ", next_floodfill->GetIdentHash().ToBase64());
              auto msg = dest->CreateRequestMessage(next_floodfill, inbound);
              msgs.push_back(
                  kovri::core::TunnelMessageBlock {
                  kovri::core::e_DeliveryTypeRouter,
                  next_floodfill->GetIdentHash(),
                  0,
                  msg
                });
              delete_dest = false;
            }
          } else {
            LogPrint(eLogWarn,
                "NetDb: ", key.data(), " was not found in ", max_ff, "floodfills");
          }
          if (msgs.size() > 0)
            outbound->SendTunnelDataMsg(msgs);
        }
      }
      if (delete_dest)
        // no more requests for the destination. delete it
        m_Requests.RequestComplete(ident, nullptr);
    } else {
      // no more requests for destination possible. delete it
      m_Requests.RequestComplete(ident, nullptr);
    }
  } else {
    LogPrint(eLogWarn,
        "NetDb: requested destination for ", key.data(), " not found");
  }
  // try responses
  for (int i = 0; i < num; i++) {
    const std::uint8_t* router = buf + 33 + i * 32;
    std::array<char, 48> peer_hash;
    int l1 = kovri::core::ByteStreamToBase64(router, 32, peer_hash.data(), peer_hash.size());
    peer_hash.at(l1) = 0;
    LogPrint(eLogInfo, "NetDb: ", i, ": ", peer_hash.data());
    auto r = FindRouter(router);
    if (!r || kovri::core::GetMillisecondsSinceEpoch() >
        r->GetTimestamp() +
        static_cast<std::uint32_t>(NetDbTime::RouterExpiration))  {
      // router with ident not found or too old
      LogPrint(eLogInfo,
          "NetDb: found new/outdated router, requesting RouterInfo");
      RequestDestination(router);
    } else {
      LogPrint(eLogInfo,
          "NetDb: router with ident found");
    }
  }
}

void NetDb::HandleDatabaseLookupMsg(
    std::shared_ptr<const I2NPMessage> msg) {
  const std::uint8_t* buf = msg->GetPayload();
  IdentHash ident(buf);
  if (ident.IsZero()) {
    LogPrint(eLogError, "NetDb: DatabaseLookup for zero ident. Ignored");
    return;
  }
  std::array<char, 48> key;
  int l = kovri::core::ByteStreamToBase64(buf, 32, key.data(), key.size());
  key.at(l) = 0;
  std::uint8_t flag = buf[64];
  LogPrint(eLogInfo, "NetDb: DatabaseLookup for ", key.data(),
      " received flags=", static_cast<int>(flag));
  std::uint8_t lookup_type = flag & DATABASE_LOOKUP_TYPE_FLAGS_MASK;
  const std::uint8_t* excluded = buf + 65;
  std::uint32_t reply_tunnel_ID = 0;
  if (flag & DATABASE_LOOKUP_DELIVERY_FLAG) {  // reply to tunnel
    reply_tunnel_ID = bufbe32toh(buf + 64);
    excluded += 4;
  }
  std::uint16_t num_excluded = bufbe16toh(excluded);
  excluded += 2;
  if (num_excluded >
      static_cast<std::uint16_t>(NetDbSize::MaxExcludedPeers)) {
    LogPrint(eLogWarn,
        "NetDb: number of excluded peers", num_excluded, " exceeds the maximum");
    num_excluded = 0;  // TODO(unassigned): ???
  }
  std::shared_ptr<I2NPMessage> reply_msg;
  if (lookup_type == DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP) {
    LogPrint(eLogInfo,
        "NetDb: exploratory close to  ", key.data(), " ", num_excluded, " excluded");
    std::set<IdentHash> excluded_routers;
    for (int i = 0; i < num_excluded; i++) {
      excluded_routers.insert(excluded);
      excluded += 32;
    }
    std::vector<IdentHash> routers;
    for (int i = 0; i < 3; i++) {
      auto r = GetClosestNonFloodfill(ident, excluded_routers);
      if (r) {
        routers.push_back(r->GetIdentHash());
        excluded_routers.insert(r->GetIdentHash());
      }
    }
    reply_msg = CreateDatabaseSearchReply(ident, routers);
  } else {
    if (lookup_type == DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP  ||
        lookup_type == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP) {
      auto router = FindRouter(ident);
      if (router) {
        LogPrint(eLogInfo, "NetDb: requested RouterInfo ", key.data(), " found");
        router->LoadBuffer();
        if (router->GetBuffer())
          reply_msg = CreateDatabaseStoreMsg(router);
      }
    }
    if (!reply_msg && (lookup_type == DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP  ||
          lookup_type == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP)) {
      auto lease_set = FindLeaseSet(ident);
      if (lease_set) {  // we don't send back our LeaseSets
        LogPrint(eLogInfo, "NetDb: requested LeaseSet ", key.data(), " found");
        reply_msg = CreateDatabaseStoreMsg(lease_set);
      }
    }
    if (!reply_msg) {
      LogPrint(eLogInfo,
          "NetDb: requested ", key.data(), " not found. ", num_excluded, " excluded");
      std::set<IdentHash> excluded_routers;
      for (int i = 0; i < num_excluded; i++) {
        excluded_routers.insert(excluded);
        excluded += 32;
      }
      reply_msg = CreateDatabaseSearchReply(
          ident,
          GetClosestFloodfills(
              ident,
              3,
              excluded_routers));
    }
  }
  if (reply_msg) {
    if (reply_tunnel_ID) {
      // encryption might be used though tunnel only
      if (flag & DATABASE_LOOKUP_ENCYPTION_FLAG) {  // encrypted reply requested
        const std::uint8_t* session_key = excluded;
        std::uint8_t num_tags = session_key[32];
        if (num_tags > 0)  {
          const std::uint8_t* session_tag = session_key + 33;  // take first tag
          kovri::core::GarlicRoutingSession garlic(session_key, session_tag);
          reply_msg = garlic.WrapSingleMessage(reply_msg);
        }
      }
      auto exploratory_pool = kovri::core::tunnels.GetExploratoryPool();
      auto outbound =
        exploratory_pool ? exploratory_pool->GetNextOutboundTunnel() : nullptr;
      if (outbound)
        outbound->SendTunnelDataMsg(
            buf + 32,
            reply_tunnel_ID,
            reply_msg);
      else
        kovri::core::transports.SendMessage(
            buf + 32,
            kovri::core::CreateTunnelGatewayMsg(
                reply_tunnel_ID,
                reply_msg));
    } else {
      kovri::core::transports.SendMessage(buf + 32, reply_msg);
    }
  }
}

void NetDb::Explore(
    int num_destinations) {
  // new requests
  auto exploratory_pool = kovri::core::tunnels.GetExploratoryPool();
  auto outbound =
    exploratory_pool ? exploratory_pool->GetNextOutboundTunnel() : nullptr;
  auto inbound =
    exploratory_pool ? exploratory_pool->GetNextInboundTunnel() : nullptr;
  bool through_tunnels = outbound && inbound;
  std::array<std::uint8_t, 32> random_hash;
  std::vector<kovri::core::TunnelMessageBlock> msgs;
  std::set<const RouterInfo *> floodfills;
  // TODO(unassigned): docs
  LogPrint(eLogInfo, "NetDb: exploring ", num_destinations, " new routers");
  for (int i = 0; i < num_destinations; i++) {
    kovri::core::RandBytes(random_hash.data(), random_hash.size());
    auto dest = m_Requests.CreateRequest(random_hash.data(), true);  // exploratory
    if (!dest) {
      LogPrint(eLogWarn,
          "NetDb: exploratory destination was already requested");
      return;
    }
    auto floodfill = GetClosestFloodfill(random_hash.data(), dest->GetExcludedPeers());
    if (floodfill &&
        !floodfills.count(floodfill.get())) {  // request floodfill only once
      floodfills.insert(floodfill.get());
      if (kovri::core::transports.IsConnected(floodfill->GetIdentHash()))
        through_tunnels = false;
      if (through_tunnels) {
        msgs.push_back(
            kovri::core::TunnelMessageBlock {
            kovri::core::e_DeliveryTypeRouter,
            floodfill->GetIdentHash(),
            0,
            CreateDatabaseStoreMsg()  // tell floodfill about us
          });
        msgs.push_back(
            kovri::core::TunnelMessageBlock  {
            kovri::core::e_DeliveryTypeRouter,
            floodfill->GetIdentHash(),
            0,
            dest->CreateRequestMessage(
                floodfill,
                inbound)  // explore
          });
      } else {
        kovri::core::transports.SendMessage(
            floodfill->GetIdentHash(),
            dest->CreateRequestMessage(
              floodfill->GetIdentHash()));
      }
    } else {
      m_Requests.RequestComplete(random_hash.data(), nullptr);
    }
  }
  if (through_tunnels && msgs.size() > 0)
    outbound->SendTunnelDataMsg(msgs);
}

void NetDb::Publish() {
  std::set<IdentHash> excluded;  // TODO(unassigned): fill up later
  for (int i = 0; i < 2; i++) {
    auto floodfill = GetClosestFloodfill(
        kovri::context.GetRouterInfo().GetIdentHash(),
        excluded);
    if (floodfill) {
      std::uint32_t reply_token = kovri::core::Rand<std::uint32_t>();
      LogPrint(eLogInfo,
          "NetDb: publishing our RouterInfo to ",
          floodfill->GetIdentHashAbbreviation(),
          ". reply token=", reply_token);
      kovri::core::transports.SendMessage(
          floodfill->GetIdentHash(),
          CreateDatabaseStoreMsg(
              kovri::context.GetSharedRouterInfo(),
              reply_token));
      excluded.insert(floodfill->GetIdentHash());
    }
  }
}

std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter() const {
  return GetRandomRouter(
      [](std::shared_ptr<const RouterInfo> router)->bool {
      return !router->IsHidden();
    });
}

std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter(
    std::shared_ptr<const RouterInfo> compatible_with) const {
  return GetRandomRouter(
      [compatible_with](std::shared_ptr<const RouterInfo> router)->bool {
      return !router->IsHidden() && router != compatible_with &&
        router->IsCompatible(*compatible_with);
    });
}

std::shared_ptr<const RouterInfo> NetDb::GetRandomPeerTestRouter() const {
  return GetRandomRouter(
    [](std::shared_ptr<const RouterInfo> router)->bool {
      return !router->IsHidden() && router->IsPeerTesting();
    });
}

std::shared_ptr<const RouterInfo> NetDb::GetRandomIntroducer() const {
  return GetRandomRouter(
      [](std::shared_ptr<const RouterInfo> router)->bool {
      return !router->IsHidden() && router->IsIntroducer();
    });
}

std::shared_ptr<const RouterInfo> NetDb::GetHighBandwidthRandomRouter(
    std::shared_ptr<const RouterInfo> compatible_with) const {
  return GetRandomRouter(
    [compatible_with](std::shared_ptr<const RouterInfo> router)->bool {
      return !router->IsHidden() &&
      router != compatible_with &&
      router->IsCompatible(*compatible_with) &&
      (router->GetCaps() & RouterInfo::eHighBandwidth);
    });
}

template<typename Filter>
std::shared_ptr<const RouterInfo> NetDb::GetRandomRouter(
    Filter filter) const {

  // Lock RI's
  std::unique_lock<std::mutex> l(m_RouterInfosMutex);

  // Instead of using expensive map copying (in an attempt to shuffle),
  // we'll create a vector of pointers to map's key, randomize, then iterate
  // to ensure that a random RI will be selected for test-case
  std::vector<std::unique_ptr<IdentHash>> idents;

  // Save pointers to keys
  for (auto const& ri : m_RouterInfos)
    idents.push_back(std::make_unique<IdentHash>(ri.first));

  // Randomize they keys for selection
  kovri::core::Shuffle(idents.begin(), idents.end());

  // Use keys for test-case
  for (auto const& i : idents) {
    if (!m_RouterInfos.at(*i)->IsUnreachable() && filter(m_RouterInfos.at(*i)))
      return m_RouterInfos.at(*i);
  }

  // We don't have enough routers which fit criteria
  return nullptr;
}

void NetDb::PostI2NPMsg(
    std::shared_ptr<const I2NPMessage> msg) {
  if (msg)
    m_Queue.Put(msg);
}

std::shared_ptr<const RouterInfo> NetDb::GetClosestFloodfill(
    const IdentHash& destination,
    const std::set<IdentHash>& excluded) const {
  std::shared_ptr<const RouterInfo> r;
  XORMetric min_metric;
  IdentHash dest_key = CreateRoutingKey(destination);
  min_metric.SetMax();
  std::unique_lock<std::mutex> l(m_FloodfillsMutex);
  for (auto it : m_Floodfills) {
    if (!it->IsUnreachable()) {
      XORMetric m = dest_key ^ it->GetIdentHash();
      if (m < min_metric && !excluded.count(it->GetIdentHash())) {
        min_metric = m;
        r = it;
      }
    }
  }
  return r;
}

std::vector<IdentHash> NetDb::GetClosestFloodfills(
    const IdentHash& destination,
    std::size_t num,
    std::set<IdentHash>& excluded) const {
  struct Sorted {
    std::shared_ptr<const RouterInfo> r;
    XORMetric metric;
    bool operator<(const Sorted& other) const {
      return metric < other.metric;
    }
  };
  std::set<Sorted> sorted;
  IdentHash dest_key = CreateRoutingKey(destination); {
    std::unique_lock<std::mutex> l(m_FloodfillsMutex);
    for (auto it : m_Floodfills) {
      if (!it->IsUnreachable()) {
        XORMetric m = dest_key ^ it->GetIdentHash();
        if (sorted.size() < num) {
          sorted.insert({it, m});
        } else if (m < sorted.rbegin()->metric) {
          sorted.insert({it, m});
          sorted.erase(std::prev(sorted.end()));
        }
      }
    }
  }
  std::vector<IdentHash> res;
  std::size_t i = 0;
  for (auto it : sorted) {
    if (i < num) {
      auto& ident = it.r->GetIdentHash();
      if (!excluded.count(ident)) {
        res.push_back(ident);
        i++;
      }
    } else {
      break;
    }
  }
  return res;
}

std::shared_ptr<const RouterInfo> NetDb::GetClosestNonFloodfill(
    const IdentHash& destination,
    const std::set<IdentHash>& excluded) const {
  std::shared_ptr<const RouterInfo> r;
  XORMetric min_metric;
  IdentHash dest_key = CreateRoutingKey(destination);
  min_metric.SetMax();
  // must be called from NetDb thread only
  for (auto it : m_RouterInfos) {
    if (!it.second->IsFloodfill()) {
      XORMetric m = dest_key ^ it.first;
      if (m < min_metric && !excluded.count(it.first)) {
        min_metric = m;
        r = it.second;
      }
    }
  }
  return r;
}

void NetDb::ManageLeaseSets() {
  for (auto it = m_LeaseSets.begin(); it != m_LeaseSets.end();) {
    if (!it->second->HasNonExpiredLeases()) {  // all leases expired
      LogPrint(eLogInfo,
          "NetDb: LeaseSet ", it->second->GetIdentHash().ToBase64(), " expired");
      it = m_LeaseSets.erase(it);
    } else {
      it++;
    }
  }
}

}  // namespace core
}  // namespace kovri
