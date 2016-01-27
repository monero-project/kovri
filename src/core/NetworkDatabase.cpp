/**
 * Copyright (c) 2015-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "NetworkDatabase.h"

#include <boost/asio.hpp>

// TODO(unassigned): use util/GZIP.h ?
#include <cryptopp/gzip.h>

#include <string.h>

#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "Garlic.h"
#include "I2NPProtocol.h"
#include "RouterContext.h"
#include "crypto/Rand.h"
#include "transport/Transports.h"
#include "tunnel/Tunnel.h"
#include "util/Base64.h"
#include "util/I2PEndian.h"
#include "util/Log.h"
#include "util/Timestamp.h"

// TODO(anonimal): do not use namespace using-directives.
using namespace i2p::transport;

namespace i2p {
namespace data {

const char NetDb::m_NetDbPath[] = "netDb";

NetDb netdb;

NetDb::NetDb()
    : m_IsRunning(false),
      m_Thread(nullptr),
      m_Reseeder(nullptr) {}

NetDb::~NetDb() {
  Stop();
  if (m_Reseeder) {
    delete m_Reseeder;
    m_Reseeder = nullptr;
  }
}

bool NetDb::Start() {
  Load();
  if (m_RouterInfos.size() < 25) {  // reseed if # of router less than 50
    // try SU3 first
    if (!Reseed()) {
      // reseed failed
      LogPrint(eLogError, "Reseed failed");
      return false;
    }
  }
  m_IsRunning = true;
  m_Thread = new std::thread(std::bind(&NetDb::Run, this));
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
      delete m_Thread;
      m_Thread = nullptr;
    }
    m_LeaseSets.clear();
    m_Requests.Stop();
  }
}

void NetDb::Run() {
  uint32_t lastSave = 0,
           lastPublish = 0,
           lastExploratory = 0,
           lastManageRequest = 0;
  while (m_IsRunning) {
    try {
      auto msg = m_Queue.GetNextWithTimeout(15000);  // 15 sec
      if (msg) {
        int numMsgs = 0;
        while (msg) {
          switch (msg->GetTypeID()) {
            case e_I2NPDatabaseStore:
              LogPrint("DatabaseStore");
              HandleDatabaseStoreMsg(msg);
            break;
            case e_I2NPDatabaseSearchReply:
              LogPrint("DatabaseSearchReply");
              HandleDatabaseSearchReplyMsg(msg);
            break;
            case e_I2NPDatabaseLookup:
              LogPrint("DatabaseLookup");
              HandleDatabaseLookupMsg(msg);
            break;
            default:  // WTF?
              // TODO(unassigned): ???
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
      if (ts - lastManageRequest >= 15) {  // manage requests every 15 seconds
        m_Requests.ManageRequests();
        lastManageRequest = ts;
      }
      // save routers, manage leasesets and validate subscriptions every minute
      if (ts - lastSave >= 60) {
        if (lastSave) {
          SaveUpdated();
          ManageLeaseSets();
        }
        lastSave = ts;
      }
      if (ts - lastPublish >= 2400) {  // publish every 40 minutes
        Publish();
        lastPublish = ts;
      }
      if (ts - lastExploratory >= 30) {  // exploratory every 30 seconds
        auto numRouters = m_RouterInfos.size();
        // TODO(anonimal): research these numbers
        if (numRouters < 2500 || ts - lastExploratory >= 90) {
          if (numRouters > 0) {
            numRouters = 800 / numRouters;
          }
          if (numRouters < 1)
            numRouters = 1;
          if (numRouters > 9)
            numRouters = 9;
          m_Requests.ManageRequests();
          Explore(numRouters);
          lastExploratory = ts;
        }
      }
    } catch(std::exception& ex) {
      LogPrint("NetDb: ", ex.what());
    }
  }
}

void NetDb::AddRouterInfo(
    const uint8_t* buf,
    int len) {
  IdentityEx identity;
  if (identity.FromBuffer(buf, len))
    AddRouterInfo(identity.GetIdentHash(), buf, len);
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
      LogPrint("RouterInfo updated");
  } else {
    LogPrint("New RouterInfo added");
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
        LogPrint(eLogInfo, "LeaseSet updated");
      } else {
        LogPrint(eLogInfo, "LeaseSet update failed");
        m_LeaseSets.erase(it);
      }
    } else {
      auto leaseSet = std::make_shared<LeaseSet>(buf, len);
      if (leaseSet->IsValid()) {
        LogPrint(eLogInfo, "New LeaseSet added");
        m_LeaseSets[ident] = leaseSet;
      } else {
        LogPrint(eLogError, "New LeaseSet validation failed");
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
  LogPrint("Creating ", directory.string());
  if (!boost::filesystem::create_directory(directory)) {
    LogPrint("Failed to create ", directory.string());
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
  if (m_Reseeder == nullptr) {
    m_Reseeder = new Reseeder();
    if (!m_Reseeder->LoadSU3Certs()) {
      delete m_Reseeder;
      m_Reseeder = nullptr;
      LogPrint(eLogError, "Failed to load reseed certificates");
      // we need to die hard if this happens
      return false;
    }
  }
  int reseedRetries = 0;
  while (reseedRetries < 10) {
    int result = m_Reseeder->ReseedNowSU3();
    if (result <= 0)
      reseedRetries++;
    else
      break;
  }
  if (reseedRetries >= 10)
    LogPrint(eLogWarning, "Failed to reseed after 10 attempts");
  return reseedRetries < 10;
}

void NetDb::Load() {
  boost::filesystem::path p(
      i2p::util::filesystem::GetDataPath() / m_NetDbPath);
  if (!boost::filesystem::exists(p)) {
    // seems netDb doesn't exist yet
    if (!CreateNetDb(p)) return;
  }
  // make sure we cleanup netDb from previous attempts
  m_RouterInfos.clear();
  m_Floodfills.clear();

  // load routers now
  uint64_t ts = i2p::util::GetMillisecondsSinceEpoch();
  int numRouters = 0;
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
          numRouters++;
        } else {
          if (boost::filesystem::exists(fullPath))
            boost::filesystem::remove(fullPath);
        }
      }
    }
  }
  LogPrint(numRouters, " routers loaded");
  LogPrint(m_Floodfills.size(), " floodfills loaded");
}

void NetDb::SaveUpdated() {
  auto GetFilePath = [](
      const boost::filesystem::path& directory,
      const RouterInfo* routerInfo) {
    std::string s(routerInfo->GetIdentHashBase64());
    return directory / (std::string("r") + s[0]) / ("routerInfo-" + s + ".dat");
  };
  boost::filesystem::path fullDirectory(
      i2p::util::filesystem::GetDataPath() / m_NetDbPath);
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
    LogPrint(count, " new/updated routers saved");
  if (deletedCount > 0) {
    LogPrint(deletedCount, " routers deleted");
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
    RequestedDestination::RequestComplete requestComplete) {
  auto dest = m_Requests.CreateRequest(
      destination,
      false,
      requestComplete);  // non-exploratory
  if (!dest) {
    LogPrint(eLogWarning,
        "Destination ", destination.ToBase64(), " is requested already");
    return;
  }
  auto floodfill = GetClosestFloodfill(
      destination,
      dest->GetExcludedPeers());
  if (floodfill) {
    transports.SendMessage(
        floodfill->GetIdentHash(),
        dest->CreateRequestMessage(
          floodfill->GetIdentHash()));
  } else {
    LogPrint(eLogError, "No floodfills found");
    m_Requests.RequestComplete(destination, nullptr);
  }
}

void NetDb::HandleDatabaseStoreMsg(
    std::shared_ptr<const I2NPMessage> m) {
  const uint8_t* buf = m->GetPayload();
  size_t len = m->GetSize();
  IdentHash ident(buf + DATABASE_STORE_KEY_OFFSET);
  if (ident.IsZero()) {
    LogPrint(eLogError, "Database store with zero ident. Dropped");
    return;
  }
  uint32_t replyToken = bufbe32toh(buf + DATABASE_STORE_REPLY_TOKEN_OFFSET);
  size_t offset = DATABASE_STORE_HEADER_SIZE;
  if (replyToken) {
    auto deliveryStatus = CreateDeliveryStatusMsg(replyToken);
    uint32_t tunnelID = bufbe32toh(buf + offset);
    offset += 4;
    if (!tunnelID) {  // send response directly
      transports.SendMessage(buf + offset, deliveryStatus);
    } else {
      auto pool = i2p::tunnel::tunnels.GetExploratoryPool();
      auto outbound = pool ? pool->GetNextOutboundTunnel() : nullptr;
      if (outbound)
        outbound->SendTunnelDataMsg(buf + offset, tunnelID, deliveryStatus);
      else
        LogPrint(eLogError,
            "No outbound tunnels for DatabaseStore reply found");
    }
    offset += 32;
    if (context.IsFloodfill()) {
      // flood it
      auto floodMsg = ToSharedI2NPMessage(NewI2NPShortMessage());
      uint8_t* payload = floodMsg->GetPayload();
      memcpy(payload, buf, 33);  // key + type
      // zero reply token
      htobe32buf(payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0);
      memcpy(payload + DATABASE_STORE_HEADER_SIZE, buf + offset, len - offset);
      floodMsg->len += DATABASE_STORE_HEADER_SIZE + len -offset;
      floodMsg->FillI2NPMessageHeader(e_I2NPDatabaseStore);
      std::set<IdentHash> excluded;
      for (int i = 0; i < 3; i++) {
        auto floodfill = GetClosestFloodfill(ident, excluded);
        if (floodfill)
          transports.SendMessage(floodfill->GetIdentHash(), floodMsg);
      }
    }
  }
  if (buf[DATABASE_STORE_TYPE_OFFSET]) {  // type
    LogPrint("LeaseSet");
    AddLeaseSet(ident, buf + offset, len - offset, m->from);
  } else {
    LogPrint("RouterInfo");
    size_t size = bufbe16toh(buf + offset);
    offset += 2;
    if (size > 2048 || size > len - offset) {
      LogPrint("Invalid RouterInfo length ", static_cast<int>(size));
      return;
    } try {
      CryptoPP::Gunzip decompressor;
      decompressor.Put(buf + offset, size);
      decompressor.MessageEnd();
      uint8_t uncompressed[2048];
      size_t uncomressedSize = decompressor.MaxRetrievable();
      if (uncomressedSize <= 2048) {
        decompressor.Get(uncompressed, uncomressedSize);
        AddRouterInfo(ident, uncompressed, uncomressedSize);
      } else {
        LogPrint("Invalid RouterInfo uncompressed length ",
            static_cast<int>(uncomressedSize));
      }
    } catch (CryptoPP::Exception& ex) {
      LogPrint(eLogError, "DatabaseStore: ", ex.what());
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
  LogPrint("DatabaseSearchReply for ", key, " num=", num);
  IdentHash ident(buf);
  auto dest = m_Requests.FindRequest(ident);
  if (dest) {
    bool deleteDest = true;
    if (num > 0) {
      auto pool = i2p::tunnel::tunnels.GetExploratoryPool();
      auto outbound = pool ? pool->GetNextOutboundTunnel() : nullptr;
      auto inbound = pool ? pool->GetNextInboundTunnel() : nullptr;
      if (!dest->IsExploratory()) {
        // reply to our destination. Try other floodfills
        if (outbound && inbound) {
          std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
          auto count = dest->GetExcludedPeers().size();
          if (count < 7) {
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
              LogPrint("Try ", key,
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
              deleteDest = false;
            }
          } else {
            LogPrint(key, " was not found on 7 floodfills");
          }
          if (msgs.size() > 0)
            outbound->SendTunnelDataMsg(msgs);
        }
      }
      if (deleteDest)
        // no more requests for the destination. delete it
        m_Requests.RequestComplete(ident, nullptr);
    } else {
      // no more requests for destination possible. delete it
      m_Requests.RequestComplete(ident, nullptr);
    }
  } else {
    LogPrint("Requested destination for ", key, " not found");
  }
  // try responses
  for (int i = 0; i < num; i++) {
    const uint8_t* router = buf + 33 + i * 32;
    char peerHash[48];
    int l1 = i2p::util::ByteStreamToBase64(router, 32, peerHash, 48);
    peerHash[l1] = 0;
    LogPrint(i, ": ", peerHash);

    auto r = FindRouter(router);
    if (!r ||
        i2p::util::GetMillisecondsSinceEpoch() >
        r->GetTimestamp() + 3600 * 1000LL)  {
      // router with ident not found or too old (1 hour)
      LogPrint("Found new/outdated router. Requesting RouterInfo ...");
      RequestDestination(router);
    } else {
      LogPrint("Bayan");  // TODO(unassigned): English
    }
  }
}

void NetDb::HandleDatabaseLookupMsg(
    std::shared_ptr<const I2NPMessage> msg) {
  const uint8_t* buf = msg->GetPayload();
  IdentHash ident(buf);
  if (ident.IsZero()) {
    LogPrint(eLogError, "DatabaseLookup for zero ident. Ignored");
    return;
  }
  char key[48];
  int l = i2p::util::ByteStreamToBase64(buf, 32, key, 48);
  key[l] = 0;
  uint8_t flag = buf[64];
  LogPrint("DatabaseLookup for ", key,
      " received flags=", static_cast<int>(flag));
  uint8_t lookupType = flag & DATABASE_LOOKUP_TYPE_FLAGS_MASK;
  const uint8_t* excluded = buf + 65;
  uint32_t replyTunnelID = 0;
  if (flag & DATABASE_LOOKUP_DELIVERY_FLAG) {  // reply to tunnel
    replyTunnelID = bufbe32toh(buf + 64);
    excluded += 4;
  }
  uint16_t numExcluded = bufbe16toh(excluded);
  excluded += 2;
  if (numExcluded > 512) {
    LogPrint("Number of excluded peers", numExcluded, " exceeds 512");
    numExcluded = 0;  // TODO(unassigned): ???
  }
  std::shared_ptr<I2NPMessage> replyMsg;
  if (lookupType == DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP) {
    LogPrint("Exploratory close to  ", key, " ", numExcluded, " excluded");
    std::set<IdentHash> excludedRouters;
    for (int i = 0; i < numExcluded; i++) {
      excludedRouters.insert(excluded);
      excluded += 32;
    }
    std::vector<IdentHash> routers;
    for (int i = 0; i < 3; i++) {
      auto r = GetClosestNonFloodfill(ident, excludedRouters);
      if (r) {
        routers.push_back(r->GetIdentHash());
        excludedRouters.insert(r->GetIdentHash());
      }
    }
    replyMsg = CreateDatabaseSearchReply(ident, routers);
  } else {
    if (lookupType == DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP  ||
        lookupType == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP) {
      auto router = FindRouter(ident);
      if (router) {
        LogPrint("Requested RouterInfo ", key, " found");
        router->LoadBuffer();
        if (router->GetBuffer())
          replyMsg = CreateDatabaseStoreMsg(router);
      }
    }
    if (!replyMsg && (lookupType == DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP  ||
          lookupType == DATABASE_LOOKUP_TYPE_NORMAL_LOOKUP)) {
      auto leaseSet = FindLeaseSet(ident);
      if (leaseSet) {  // we don't send back our LeaseSets
        LogPrint("Requested LeaseSet ", key, " found");
        replyMsg = CreateDatabaseStoreMsg(leaseSet);
      }
    }
    if (!replyMsg) {
      LogPrint("Requested ", key, " not found. ", numExcluded, " excluded");
      std::set<IdentHash> excludedRouters;
      for (int i = 0; i < numExcluded; i++) {
        excludedRouters.insert(excluded);
        excluded += 32;
      }
      replyMsg = CreateDatabaseSearchReply(
          ident,
          GetClosestFloodfills(
            ident,
            3,
            excludedRouters));
    }
  }
  if (replyMsg) {
    if (replyTunnelID) {
      // encryption might be used though tunnel only
      if (flag & DATABASE_LOOKUP_ENCYPTION_FLAG) {  // encrypted reply requested
        const uint8_t * sessionKey = excluded;
        uint8_t numTags = sessionKey[32];
        if (numTags > 0)  {
          const uint8_t* sessionTag = sessionKey + 33;  // take first tag
          i2p::garlic::GarlicRoutingSession garlic(sessionKey, sessionTag);
          replyMsg = garlic.WrapSingleMessage(replyMsg);
        }
      }
      auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool();
      auto outbound =
        exploratoryPool ? exploratoryPool->GetNextOutboundTunnel() : nullptr;
      if (outbound)
        outbound->SendTunnelDataMsg(
            buf+32,
            replyTunnelID,
            replyMsg);
      else
        transports.SendMessage(
            buf+32,
            i2p::CreateTunnelGatewayMsg(
              replyTunnelID,
              replyMsg));
    } else {
      transports.SendMessage(buf+32, replyMsg);
    }
  }
}

void NetDb::Explore(
    int numDestinations) {
  // new requests
  auto exploratoryPool = i2p::tunnel::tunnels.GetExploratoryPool();
  auto outbound =
    exploratoryPool ? exploratoryPool->GetNextOutboundTunnel() : nullptr;
  auto inbound =
    exploratoryPool ? exploratoryPool->GetNextInboundTunnel() : nullptr;
  bool throughTunnels = outbound && inbound;

  uint8_t randomHash[32];
  std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
  std::set<const RouterInfo *> floodfills;
  // TODO(unassigned): docs
  LogPrint("Exploring new ", numDestinations, " routers ...");
  for (int i = 0; i < numDestinations; i++) {
    i2p::crypto::RandBytes(randomHash, 32);
    auto dest = m_Requests.CreateRequest(randomHash, true);  // exploratory
    if (!dest) {
      LogPrint(eLogWarning, "Exploratory destination is requested already");
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
      LogPrint("Publishing our RouterInfo to ",
          floodfill->GetIdentHashAbbreviation(),
          ". reply token=", replyToken);
      transports.SendMessage(
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
    std::shared_ptr<const RouterInfo> compatibleWith) const {
  return GetRandomRouter(
      [compatibleWith](std::shared_ptr<const RouterInfo> router)->bool {
      return !router->IsHidden() && router != compatibleWith &&
        router->IsCompatible(*compatibleWith);
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
    std::shared_ptr<const RouterInfo> compatibleWith) const {
  return GetRandomRouter (
    [compatibleWith](std::shared_ptr<const RouterInfo> router)->bool {
      return !router->IsHidden() &&
      router != compatibleWith &&
      router->IsCompatible(*compatibleWith) &&
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
  XORMetric minMetric;
  IdentHash destKey = CreateRoutingKey(destination);
  minMetric.SetMax();
  std::unique_lock<std::mutex> l(m_FloodfillsMutex);
  for (auto it : m_Floodfills) {
    if (!it->IsUnreachable()) {
      XORMetric m = destKey ^ it->GetIdentHash();
      if (m < minMetric && !excluded.count(it->GetIdentHash())) {
        minMetric = m;
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
    bool operator< (const Sorted& other) const {
      return metric < other.metric;
    }
  };
  std::set<Sorted> sorted;
  IdentHash destKey = CreateRoutingKey(destination); {
    std::unique_lock<std::mutex> l(m_FloodfillsMutex);
    for (auto it : m_Floodfills) {
      if (!it->IsUnreachable()) {
        XORMetric m = destKey ^ it->GetIdentHash();
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
  XORMetric minMetric;
  IdentHash destKey = CreateRoutingKey(destination);
  minMetric.SetMax();
  // must be called from NetDb thread only
  for (auto it : m_RouterInfos) {
    if (!it.second->IsFloodfill()) {
      XORMetric m = destKey ^ it.first;
      if (m < minMetric && !excluded.count(it.first)) {
        minMetric = m;
        r = it.second;
      }
    }
  }
  return r;
}

void NetDb::ManageLeaseSets() {
  for (auto it = m_LeaseSets.begin(); it != m_LeaseSets.end();) {
    if (!it->second->HasNonExpiredLeases()) {  // all leases expired
      LogPrint("LeaseSet ", it->second->GetIdentHash().ToBase64(), " expired");
      it = m_LeaseSets.erase(it);
    } else {
      it++;
    }
  }
}

}  // namespace data
}  // namespace i2p
