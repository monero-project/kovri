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

#include "net_db.h"

#include <boost/asio.hpp>

#include <string.h>

#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "garlic.h"
#include "i2np_protocol.h"
#include "router_context.h"
#include "crypto/rand.h"
#include "crypto/util/compression.h"
#include "transport/transports.h"
#include "tunnel/tunnel.h"
#include "util/base64.h"
#include "util/i2p_endian.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace data {

const char NetDb::m_NetDbPath[] = "netDb";

NetDb netdb;

NetDb::NetDb()
    : m_IsRunning(false),
      m_Thread(nullptr),
      m_Reseed(nullptr) {}

NetDb::~NetDb() {
  Stop();
  if (m_Reseed) {
    m_Reseed.reset(nullptr);
  }
}

bool NetDb::Start() {
  Load();
  if (m_RouterInfos.size() < 25) {  // reseed if # of router less than 50
    if (!Reseed()) {
      return false;
    }
  }
  m_IsRunning = true;
  m_Thread = std::make_unique<std::thread>(std::bind(&NetDb::Run, this));
  return true;
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
  uint32_t last_save = 0,
           last_publish = 0,
           last_exploratory = 0,
           last_manage_request = 0;
  while (m_IsRunning) {
    try {
      auto msg = m_Queue.GetNextWithTimeout(15000);  // 15 sec
      if (msg) {
        int numMsgs = 0;
        while (msg) {
          switch (msg->GetTypeID()) {
            case e_I2NPDatabaseStore:
              LogPrint(eLogDebug, "NetDb: DatabaseStore");
              HandleDatabaseStoreMsg(msg);
            break;
            case e_I2NPDatabaseSearchReply:
              LogPrint(eLogDebug, "NetDb: DatabaseSearchReply");
              HandleDatabaseSearchReplyMsg(msg);
            break;
            case e_I2NPDatabaseLookup:
              LogPrint(eLogDebug, "NetDb: DatabaseLookup");
              HandleDatabaseLookupMsg(msg);
            break;
            default:
              // TODO(unassigned): error handling
              LogPrint(eLogError,
                  "NetDb: unexpected message type ", msg->GetTypeID());
              // i2p::HandleI2NPMessage(msg);
          }
          if (numMsgs > 100)
            break;
          msg = m_Queue.Get();
          numMsgs++;
        }
      }
      if (!m_IsRunning)
        break;
      uint64_t ts = i2p::util::GetSecondsSinceEpoch();
      if (ts - last_manage_request >= 15) {  // manage requests every 15 seconds
        m_Requests.ManageRequests();
        last_manage_request = ts;
      }
      // save routers, manage leasesets and validate subscriptions every minute
      if (ts - last_save >= 60) {
        if (last_save) {
          SaveUpdated();
          ManageLeaseSets();
        }
        last_save = ts;
      }
      if (ts - last_publish >= 2400) {  // publish every 40 minutes
        Publish();
        last_publish = ts;
      }
      if (ts - last_exploratory >= 30) {  // exploratory every 30 seconds
        auto num_routers = m_RouterInfos.size();
        // TODO(anonimal): research these numbers
        if (num_routers < 2500 || ts - last_exploratory >= 90) {
          if (num_routers > 0) {
            num_routers = 800 / num_routers;
          }
          if (num_routers < 1)
            num_routers = 1;
          if (num_routers > 9)
            num_routers = 9;
          m_Requests.ManageRequests();
          Explore(num_routers);
          last_exploratory = ts;
        }
      }
    } catch(std::exception& ex) {
      LogPrint(eLogError, "NetDb::Run(): ", ex.what());
    }
  }
}

bool NetDb::AddRouterInfo(
    const uint8_t* buf,
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
    const uint8_t* buf,
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
    const uint8_t* buf,
    int len,
    std::shared_ptr<i2p::tunnel::InboundTunnel> from) {
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
    bool unreachable) {
  auto it = m_RouterInfos.find(ident);
  if (it != m_RouterInfos.end())
    return it->second->SetUnreachable(unreachable);
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
  const char* chars = i2p::util::GetBase64SubstitutionTable();  // 64 bytes
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

bool NetDb::Reseed() {
  if (m_Reseed == nullptr) {
    m_Reseed = std::make_unique<i2p::data::Reseed>(i2p::context.ReseedFrom());
    if (!m_Reseed->ReseedImpl()) {
      m_Reseed.reset(nullptr);
      LogPrint(eLogError, "NetDb: reseed failed");
      return false;
    }
  }
  return true;
}

void NetDb::Load() {
  boost::filesystem::path p(i2p::context.GetDataPath() / m_NetDbPath);
  if (!boost::filesystem::exists(p)) {
    // seems netDb doesn't exist yet
    if (!CreateNetDb(p))
      return;
  }
  // make sure we cleanup netDb from previous attempts
  m_RouterInfos.clear();
  m_Floodfills.clear();
  // load routers now
  uint64_t ts = i2p::util::GetMillisecondsSinceEpoch();
  int num_routers = 0;
  boost::filesystem::directory_iterator end;
  for (boost::filesystem::directory_iterator it(p); it != end; ++it) {
    if (boost::filesystem::is_directory(it->status())) {
      for (boost::filesystem::directory_iterator it1(it->path());
          it1 != end;
          ++it1) {
#if BOOST_VERSION > 10500
        const std::string& fullPath = it1->path().string();
#else
        const std::string& fullPath = it1->path();
#endif
        auto r = std::make_shared<RouterInfo>(fullPath);
        if (!r->IsUnreachable() &&
            (!r->UsesIntroducer() ||
             ts < r->GetTimestamp() + 3600 * 1000LL)) {  // 1 hour
          r->DeleteBuffer();
          r->ClearProperties();  // properties are not used for regular routers
          m_RouterInfos[r->GetIdentHash()] = r;
          if (r->IsFloodfill())
            m_Floodfills.push_back(r);
          num_routers++;
        } else {
          if (boost::filesystem::exists(fullPath))
            boost::filesystem::remove(fullPath);
        }
      }
    }
  }
  LogPrint(eLogInfo, "NetDb: ", num_routers, " routers loaded");
  LogPrint(eLogInfo, "NetDb: ", m_Floodfills.size(), " floodfills loaded");
}

void NetDb::SaveUpdated() {
  auto GetFilePath = [](
      const boost::filesystem::path& directory,
      const RouterInfo* routerInfo) {
    std::string s(routerInfo->GetIdentHashBase64());
    return directory / (std::string("r") + s[0]) / ("routerInfo-" + s + ".dat");
  };
  boost::filesystem::path fullDirectory(
      i2p::context.GetDataPath() / m_NetDbPath);
  int count = 0,
      deletedCount = 0;
  auto total = m_RouterInfos.size();
  uint64_t ts = i2p::util::GetMillisecondsSinceEpoch();
  for (auto it : m_RouterInfos) {
    if (it.second->IsUpdated()) {
      std::string f = GetFilePath(fullDirectory, it.second.get()).string();
      it.second->SaveToFile(f);
      it.second->SetUpdated(false);
      it.second->SetUnreachable(false);
      it.second->DeleteBuffer();
      count++;
    } else {
      // RouterInfo expires after 1 hour if it uses an introducer
      if (it.second->UsesIntroducer() &&
          ts > it.second->GetTimestamp() + 3600 * 1000LL) {  // 1 hour
        it.second->SetUnreachable(true);
      } else if (total > 75 && ts >
          (i2p::context.GetStartupTime() + 600) * 1000LL) {
        // ^ routers don't expire if less than 25
        // or uptime is less than 10 minutes
        if (i2p::context.IsFloodfill()) {
          if (ts > it.second->GetTimestamp() + 3600 * 1000LL) {
            it.second->SetUnreachable(true);
            total--;
          }
        } else if (total > 300) {
          // 30 hours
          if (ts > it.second->GetTimestamp() + 30 * 3600 * 1000LL) {
            it.second->SetUnreachable(true);
            total--;
          }
        } else if (total > 120) {
          // 72 hours
          if (ts > it.second->GetTimestamp() + 72 * 3600 * 1000LL) {
            it.second->SetUnreachable(true);
            total--;
          }
        }
      }
      if (it.second->IsUnreachable()) {
        total--;
        // delete RI file
        if (boost::filesystem::exists(
              GetFilePath(
                  fullDirectory,
                  it.second.get()))) {
          boost::filesystem::remove(
              GetFilePath(
                  fullDirectory,
                  it.second.get()));
          deletedCount++;
        }
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
  if (deletedCount > 0) {
    LogPrint(eLogInfo, "NetDb: ", deletedCount, " routers deleted");
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
    i2p::transport::transports.SendMessage(
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
  const uint8_t* buf = m->GetPayload();
  size_t len = m->GetSize();
  IdentHash ident(buf + DATABASE_STORE_KEY_OFFSET);
  if (ident.IsZero()) {
    LogPrint(eLogError, "NetDb: database store with zero ident, dropped");
    return;
  }
  uint32_t replyToken = bufbe32toh(buf + DATABASE_STORE_REPLY_TOKEN_OFFSET);
  size_t offset = DATABASE_STORE_HEADER_SIZE;
  if (replyToken) {
    auto deliveryStatus = CreateDeliveryStatusMsg(replyToken);
    uint32_t tunnelID = bufbe32toh(buf + offset);
    offset += 4;
    if (!tunnelID) {  // send response directly
      i2p::transport::transports.SendMessage(buf + offset, deliveryStatus);
    } else {
      auto pool = i2p::tunnel::tunnels.GetExploratoryPool();
      auto outbound = pool ? pool->GetNextOutboundTunnel() : nullptr;
      if (outbound)
        outbound->SendTunnelDataMsg(buf + offset, tunnelID, deliveryStatus);
      else
        LogPrint(eLogError,
            "NetDb: no outbound tunnels for DatabaseStore reply found");
    }
    offset += 32;
    if (context.IsFloodfill()) {
      // flood it
      auto flood_msg = ToSharedI2NPMessage(NewI2NPShortMessage());
      uint8_t* payload = flood_msg->GetPayload();
      memcpy(payload, buf, 33);  // key + type
      // zero reply token
      htobe32buf(payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0);
      memcpy(payload + DATABASE_STORE_HEADER_SIZE, buf + offset, len - offset);
      flood_msg->len += DATABASE_STORE_HEADER_SIZE + len -offset;
      flood_msg->FillI2NPMessageHeader(e_I2NPDatabaseStore);
      std::set<IdentHash> excluded;
      for (int i = 0; i < 3; i++) {
        auto floodfill = GetClosestFloodfill(ident, excluded);
        if (floodfill)
          i2p::transport::transports.SendMessage(
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
    size_t size = bufbe16toh(buf + offset);
    offset += 2;
    if (size > 2048 || size > len - offset) {
      LogPrint(eLogError,
          "NetDb: invalid RouterInfo length ", static_cast<int>(size));
      return;
    }
    try {
      i2p::crypto::util::Gunzip decompressor;
      decompressor.Put(buf + offset, size);
      uint8_t uncompressed[2048];
      size_t uncompressed_size = decompressor.MaxRetrievable();
      if (uncompressed_size <= 2048) {
        decompressor.Get(uncompressed, uncompressed_size);
        AddRouterInfo(ident, uncompressed, uncompressed_size);
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
  const uint8_t* buf = msg->GetPayload();
  char key[48];
  int l = i2p::util::ByteStreamToBase64(buf, 32, key, 48);
  key[l] = 0;
  int num = buf[32];  // num
  LogPrint(eLogInfo, "NetDb: DatabaseSearchReply for ", key, " num=", num);
  IdentHash ident(buf);
  auto dest = m_Requests.FindRequest(ident);
  if (dest) {
    bool delete_dest = true;
    if (num > 0) {
      auto pool = i2p::tunnel::tunnels.GetExploratoryPool();
      auto outbound = pool ? pool->GetNextOutboundTunnel() : nullptr;
      auto inbound = pool ? pool->GetNextInboundTunnel() : nullptr;
      if (!dest->IsExploratory()) {
        // reply to our destination. Try other floodfills
        if (outbound && inbound) {
          std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
          auto count = dest->GetExcludedPeers().size();
          std::size_t max_ff(7);
          if (count < max_ff) {
            auto nextFloodfill = GetClosestFloodfill(
                dest->GetDestination(),
                dest->GetExcludedPeers());
            if (nextFloodfill) {
              // tell floodfill about us
              msgs.push_back(
                  i2p::tunnel::TunnelMessageBlock {
                  i2p::tunnel::e_DeliveryTypeRouter,
                  nextFloodfill->GetIdentHash(),
                  0,
                  CreateDatabaseStoreMsg()
                  });
              // request destination
              LogPrint(eLogInfo, 
                  "NetDb: trying ", key,
                  " at ", count,
                  " floodfill ", nextFloodfill->GetIdentHash().ToBase64());
              auto msg = dest->CreateRequestMessage(nextFloodfill, inbound);
              msgs.push_back(
                  i2p::tunnel::TunnelMessageBlock {
                  i2p::tunnel::e_DeliveryTypeRouter,
                  nextFloodfill->GetIdentHash(),
                  0,
                  msg
                });
              delete_dest = false;
            }
          } else {
            LogPrint(eLogWarn,
                "NetDb: ", key, " was not found in ", max_ff, "floodfills");
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
        "NetDb: requested destination for ", key, " not found");
  }
  // try responses
  for (int i = 0; i < num; i++) {
    const uint8_t* router = buf + 33 + i * 32;
    char peer_hash[48];
    int l1 = i2p::util::ByteStreamToBase64(router, 32, peer_hash, 48);
    peer_hash[l1] = 0;
    LogPrint(eLogInfo, "NetDb: ", i, ": ", peer_hash);
    auto r = FindRouter(router);
    if (!r ||
        i2p::util::GetMillisecondsSinceEpoch() >
        r->GetTimestamp() + 3600 * 1000LL)  {
      // router with ident not found or too old (1 hour)
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
  const uint8_t* buf = msg->GetPayload();
  IdentHash ident(buf);
  if (ident.IsZero()) {
    LogPrint(eLogError, "NetDb: DatabaseLookup for zero ident. Ignored");
    return;
  }
  char key[48];
  int l = i2p::util::ByteStreamToBase64(buf, 32, key, 48);
  key[l] = 0;
  uint8_t flag = buf[64];
  LogPrint(eLogInfo, "NetDb: DatabaseLookup for ", key,
      " received flags=", static_cast<int>(flag));
  uint8_t lookupType = flag & DATABASE_LOOKUP_TYPE_FLAGS_MASK;
  const uint8_t* excluded = buf + 65;
  uint32_t reply_tunnel_ID = 0;
  if (flag & DATABASE_LOOKUP_DELIVERY_FLAG) {  // reply to tunnel
    reply_tunnel_ID = bufbe32toh(buf + 64);
    excluded += 4;
  }
  uint16_t num_excluded = bufbe16toh(excluded);
  excluded += 2;
  if (num_excluded > 512) {
    LogPrint(eLogWarn,
        "NetDb: number of excluded peers", num_excluded, " exceeds 512");
    num_excluded = 0;  // TODO(unassigned): ???
  }
  std::shared_ptr<I2NPMessage> reply_msg;
  if (lookupType == DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP) {
    LogPrint(eLogInfo,
        "NetDb: exploratory close to  ", key, " ", num_excluded, " excluded");
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
    if (lookupType == DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP  ||
        lookupType == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP) {
      auto router = FindRouter(ident);
      if (router) {
        LogPrint(eLogInfo, "NetDb: requested RouterInfo ", key, " found");
        router->LoadBuffer();
        if (router->GetBuffer())
          reply_msg = CreateDatabaseStoreMsg(router);
      }
    }
    if (!reply_msg && (lookupType == DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP  ||
          lookupType == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP)) {
      auto lease_set = FindLeaseSet(ident);
      if (lease_set) {  // we don't send back our LeaseSets
        LogPrint(eLogInfo, "NetDb: requested LeaseSet ", key, " found");
        reply_msg = CreateDatabaseStoreMsg(lease_set);
      }
    }
    if (!reply_msg) {
      LogPrint(eLogInfo,
          "NetDb: requested ", key, " not found. ", num_excluded, " excluded");
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
        const uint8_t* session_key = excluded;
        uint8_t num_tags = session_key[32];
        if (num_tags > 0)  {
          const uint8_t* sessionTag = session_key + 33;  // take first tag
          i2p::garlic::GarlicRoutingSession garlic(session_key, sessionTag);
          reply_msg = garlic.WrapSingleMessage(reply_msg);
        }
      }
      auto exploratory_pool = i2p::tunnel::tunnels.GetExploratoryPool();
      auto outbound =
        exploratory_pool ? exploratory_pool->GetNextOutboundTunnel() : nullptr;
      if (outbound)
        outbound->SendTunnelDataMsg(
            buf+32,
            reply_tunnel_ID,
            reply_msg);
      else
        i2p::transport::transports.SendMessage(
            buf+32,
            i2p::CreateTunnelGatewayMsg(
                reply_tunnel_ID,
                reply_msg));
    } else {
      i2p::transport::transports.SendMessage(buf+32, reply_msg);
    }
  }
}

void NetDb::Explore(
    int num_destinations) {
  // new requests
  auto exploratory_pool = i2p::tunnel::tunnels.GetExploratoryPool();
  auto outbound =
    exploratory_pool ? exploratory_pool->GetNextOutboundTunnel() : nullptr;
  auto inbound =
    exploratory_pool ? exploratory_pool->GetNextInboundTunnel() : nullptr;
  bool throughTunnels = outbound && inbound;
  uint8_t randomHash[32];
  std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
  std::set<const RouterInfo *> floodfills;
  // TODO(unassigned): docs
  LogPrint(eLogInfo, "NetDb: exploring new ", num_destinations, " routers");
  for (int i = 0; i < num_destinations; i++) {
    i2p::crypto::RandBytes(randomHash, 32);
    auto dest = m_Requests.CreateRequest(randomHash, true);  // exploratory
    if (!dest) {
      LogPrint(eLogWarn,
          "NetDb: exploratory destination was already requested");
      return;
    }
    auto floodfill = GetClosestFloodfill(randomHash, dest->GetExcludedPeers());
    if (floodfill &&
        !floodfills.count(floodfill.get())) {  // request floodfill only once
      floodfills.insert(floodfill.get());
      if (i2p::transport::transports.IsConnected(floodfill->GetIdentHash()))
        throughTunnels = false;
      if (throughTunnels) {
        msgs.push_back(
            i2p::tunnel::TunnelMessageBlock {
            i2p::tunnel::e_DeliveryTypeRouter,
            floodfill->GetIdentHash(),
            0,
            CreateDatabaseStoreMsg()  // tell floodfill about us
          });
        msgs.push_back(
            i2p::tunnel::TunnelMessageBlock  {
            i2p::tunnel::e_DeliveryTypeRouter,
            floodfill->GetIdentHash(),
            0,
            dest->CreateRequestMessage(
                floodfill,
                inbound)  // explore
          });
      } else {
        i2p::transport::transports.SendMessage(
            floodfill->GetIdentHash(),
            dest->CreateRequestMessage(
              floodfill->GetIdentHash()));
      }
    } else {
      m_Requests.RequestComplete(randomHash, nullptr);
    }
  }
  if (throughTunnels && msgs.size() > 0)
    outbound->SendTunnelDataMsg(msgs);
}

void NetDb::Publish() {
  std::set<IdentHash> excluded;  // TODO(unassigned): fill up later
  for (int i = 0; i < 2; i++) {
    auto floodfill = GetClosestFloodfill(
        i2p::context.GetRouterInfo().GetIdentHash(),
        excluded);
    if (floodfill) {
      uint32_t replyToken = i2p::crypto::Rand<uint32_t>();
      LogPrint(eLogInfo,
          "NetDb: publishing our RouterInfo to ",
          floodfill->GetIdentHashAbbreviation(),
          ". reply token=", replyToken);
      i2p::transport::transports.SendMessage(
          floodfill->GetIdentHash(),
          CreateDatabaseStoreMsg(
              i2p::context.GetSharedRouterInfo(),
              replyToken));
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
  return GetRandomRouter (
    [](std::shared_ptr<const RouterInfo> router)->bool {
      return !router->IsHidden() && router->IsIntroducer();
    });
}

std::shared_ptr<const RouterInfo> NetDb::GetHighBandwidthRandomRouter(
    std::shared_ptr<const RouterInfo> compatible_with) const {
  return GetRandomRouter (
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
  uint32_t ind = i2p::crypto::RandInRange<uint32_t>(0, m_RouterInfos.size() - 1);
  for (int j = 0; j < 2; j++) {
    uint32_t i = 0;
    std::unique_lock<std::mutex> l(m_RouterInfosMutex);
    for (auto it : m_RouterInfos) {
      if (i >= ind) {
        if (!it.second->IsUnreachable() && filter(it.second))
          return it.second;
      } else {
        i++;
      }
    }
    // we couldn't find anything, try second pass
    ind = 0;
  }
  return nullptr;  // seems we have too few routers
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
    size_t num,
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
  size_t i = 0;
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

}  // namespace data
}  // namespace i2p
