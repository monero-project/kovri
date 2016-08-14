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

#include "address_book.h"

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <map>
#include <memory>

#include "address_book_storage.h"
#include "destination.h"
#include "identity.h"
#include "net_db.h"
#include "crypto/rand.h"
#include "util/http.h"
#include "util/log.h"

namespace i2p {
namespace client {

// TODO(anonimal): brief narrative

void AddressBook::Start(
    std::shared_ptr<ClientDestination> local_destination) {
  m_SharedLocalDestination = local_destination;
  StartSubscriptions();
}

// TODO(anonimal): place inside Start(), this function isn't necessary
void AddressBook::StartSubscriptions() {
  // TODO(anonimal): why would we load subscriptions before ensuring we
  // have a shared local destination? Refactor this.
  LoadSubscriptions();
  if (!m_Subscriptions.size())
    return;
  if (m_SharedLocalDestination) {
    m_SubscriptionsUpdateTimer =
      std::make_unique<boost::asio::deadline_timer>(
          m_SharedLocalDestination->GetService());
    m_SubscriptionsUpdateTimer->expires_from_now(
        boost::posix_time::minutes(
            static_cast<std::uint16_t>(SubscriptionTimeout::InitialUpdate)));
    m_SubscriptionsUpdateTimer->async_wait(
        std::bind(
            &AddressBook::HandleSubscriptionsUpdateTimer,
            this,
            std::placeholders::_1));
  } else {
    LogPrint(eLogError,
        "AddressBook: ",
        "can't start subscriptions: missing shared local destination");
  }
}

// TODO(anonimal): refactor to spec
void AddressBook::LoadSubscriptions() {
  if (!m_Subscriptions.size()) {
    std::ifstream f(
        i2p::util::filesystem::GetFullPath("subscriptions.txt").c_str(),
        std::ofstream::in);  // in text mode
    if (f.is_open()) {
      std::string s;
      while (!f.eof()) {
        getline(f, s);
        if (!s.length())
          continue;  // skip empty line
        m_Subscriptions.push_back(std::make_unique<AddressBookSubscription>(*this, s));
      }
      LogPrint(eLogInfo,
          "AddressBook: ", m_Subscriptions.size(), " subscriptions loaded");
    } else {
      LogPrint(eLogWarn, "AddressBook: subscriptions.txt not found");
    }
  } else {
    LogPrint(eLogError, "AddressBook: subscriptions already loaded");
  }
}

// TODO(anonimal): rename to SubscriptionsUpdateTimer()
void AddressBook::HandleSubscriptionsUpdateTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    if (!m_SharedLocalDestination)
      return;  // TODO(unassigned): error handling
    if (m_IsLoaded && !m_IsDownloading &&
        m_SharedLocalDestination->IsReady()) {
      // pick random subscription
      // TODO(anonimal): why a random subscription?
      auto ind =
        i2p::crypto::RandInRange<std::size_t>(0, m_Subscriptions.size() - 1);
      m_IsDownloading = true;
      m_Subscriptions[ind]->CheckSubscription();
    } else {
      if (!m_IsLoaded)
        LoadHosts();
      // try it again later
      m_SubscriptionsUpdateTimer->expires_from_now(
          boost::posix_time::minutes(
              static_cast<std::uint16_t>(SubscriptionTimeout::InitialRetry)));
      m_SubscriptionsUpdateTimer->async_wait(
          std::bind(
              &AddressBook::HandleSubscriptionsUpdateTimer,
              this,
              std::placeholders::_1));
    }
  }
}

// TODO(anonimal): rename to RequestSubscriptions())
void AddressBookSubscription::CheckSubscription() {
  std::thread load_hosts(&AddressBookSubscription::Request, this);
  load_hosts.detach();  // TODO(unassigned): use join
}

// TODO(anonimal): see HTTP for notes on cpp-netlib refactor
// tl;dr, all HTTP-related code + stream handling should be refactored
void AddressBookSubscription::Request() {  // TODO(anonimal): rename to DownloadSubscriptions()
  LogPrint(eLogInfo,
      "AddressBookSubscription: downloading hosts from ", m_Link,
      " ETag: ", m_Etag,
      " Last-Modified: ", m_LastModified);
  bool success = false;
  i2p::util::http::URI uri;
  if (!uri.Parse(m_Link)) {
    LogPrint(eLogError, "AddressBookSubscription: invalid URI, request failed");
    return;
  }
  i2p::data::IdentHash ident;
  if (m_Book.GetIdentHash(uri.m_Host, ident) &&
      m_Book.GetSharedLocalDestination()) {
    std::condition_variable new_data_received;
    std::mutex new_data_received_mutex;
    auto lease_set = m_Book.GetSharedLocalDestination()->FindLeaseSet(ident);
    if (!lease_set) {
      std::unique_lock<std::mutex> l(new_data_received_mutex);
      m_Book.GetSharedLocalDestination()->RequestDestination(
          ident,
          [&new_data_received, &lease_set](std::shared_ptr<i2p::data::LeaseSet> ls) {
          lease_set = ls;
          new_data_received.notify_all();});
      if (new_data_received.wait_for(
              l,
              std::chrono::seconds(
                  static_cast<std::uint16_t>(SubscriptionTimeout::Request)))
          == std::cv_status::timeout)
        LogPrint(eLogError,
            "AddressBookSubscription: ",
            "subscription lease set request timeout expired");
    }
    if (lease_set) {
      std::stringstream request, response;
      // Standard header
      i2p::util::http::HTTP http;
      request << http.Header(uri.m_Path, uri.m_Host, "1.1");
      if (m_Etag.length () > 0)  // etag
        request << http.IF_NONE_MATCH
        << ": \"" << m_Etag << "\"\r\n";
      if (m_LastModified.length () > 0)  // if modified since
        request << http.IF_MODIFIED_SINCE
        << ": " << m_LastModified << "\r\n";
      request << "\r\n";  // end of header
      auto stream =
        m_Book.GetSharedLocalDestination()->CreateStream(
            lease_set,
            std::stoi(uri.m_Port));
      stream->Send(
          reinterpret_cast<const std::uint8_t *>(request.str().c_str()),
          request.str().length());
      std::array<std::uint8_t, 4096> buf;
      bool end = false;
      while (!end) {
        stream->AsyncReceive(
            boost::asio::buffer(
              buf.data(),
              buf.size()),
            [&](const boost::system::error_code& ecode,
              std::size_t bytes_transferred) {
                if (bytes_transferred)
                  response.write(
                      reinterpret_cast<char *>(buf.data()),
                      bytes_transferred);
                if (ecode == boost::asio::error::timed_out || !stream->IsOpen())
                  end = true;
                new_data_received.notify_all();
              },
            static_cast<std::uint16_t>(SubscriptionTimeout::Receive));
        std::unique_lock<std::mutex> l(new_data_received_mutex);
        if (new_data_received.wait_for(
                l,
                std::chrono::seconds(
                    static_cast<std::uint16_t>(SubscriptionTimeout::Request)))
            == std::cv_status::timeout)
          LogPrint(eLogError,
              "AddressBookSubscription: subscription timeout expired");
      }
      // process remaining buffer
      while (std::size_t len = stream->ReadSome(buf.data(), buf.size()))
        response.write(reinterpret_cast<char *>(buf.data()), len);
      // parse response
      std::string version;
      response >> version;  // HTTP version
      int status = 0;
      response >> status;  // status
      if (status == 200) {  // OK
        bool is_chunked = false;
        std::string header, status_message;
        std::getline(response, status_message);
        // read until new line meaning end of header
        while (!response.eof() && header != "\r") {
          std::getline(response, header);
          auto colon = header.find(':');
          if (colon != std::string::npos) {
            std::string field = header.substr(0, colon);
            header.resize(header.length() - 1);  // delete \r
            if (field == http.ETAG)
              m_Etag = header.substr(colon + 1);
            else if (field == http.LAST_MODIFIED)
              m_LastModified = header.substr(colon + 1);
            else if (field == http.TRANSFER_ENCODING)
              is_chunked =
                !header.compare(colon + 1, std::string::npos, "chunked");
          }
        }
        LogPrint(eLogInfo,
            "AddressBookSubscription: ", m_Link,
            " ETag: ", m_Etag,
            " Last-Modified: ", m_LastModified);
        if (!response.eof()) {
          success = true;
          if (!is_chunked) {
            m_Book.LoadHostsFromStream(response);
          } else {
            // merge chunks
            std::stringstream merged;
            http.MergeChunkedResponse(response, merged);
            m_Book.LoadHostsFromStream(merged);
          }
        }
      } else if (status == 304) {
        success = true;
        LogPrint(eLogInfo,
            "AddressBookSubscription: no updates from ", m_Link);
      } else {
        LogPrint(eLogWarn,
            "AddressBookSubscription: HTTP response ", status);
      }
    } else {
      LogPrint(eLogError,
          "AddressBookSubscription: address ", uri.m_Host, " not found");
    }
  } else {
    LogPrint(eLogError,
        "AddressBookSubscription: can't resolve ", uri.m_Host);
  }
  LogPrint(eLogInfo,
      "AddressBookSubscription: download complete ",
      success ? "Success" : "Failed");
  m_Book.DownloadComplete(success);
}

// TODO(anonimal): rename GetAddressIdentHash()
bool AddressBook::GetIdentHash(
    const std::string& address,
    i2p::data::IdentHash& ident) {
  auto pos = address.find(".b32.i2p");
  if (pos != std::string::npos) {
    i2p::util::Base32ToByteStream(address.c_str(), pos, ident, 32);
    return true;
  } else {
    pos = address.find(".i2p");
    if (pos != std::string::npos) {
      auto identHash = FindAddress(address);
      if (identHash) {
        ident = *identHash;
        return true;
      } else {
        return false;
      }
    }
  }
  // if not .b32 we assume full base64 address
  // TODO(anonimal): we shouldn't *assume* it's base64!
  i2p::data::IdentityEx dest;
  if (!dest.FromBase64(address))
    return false;
  ident = dest.GetIdentHash();
  return true;
}

// TODO(anonimal): rename FindLoadedAddress()
std::unique_ptr<const i2p::data::IdentHash> AddressBook::FindAddress(
    const std::string& address) {
  if (!m_IsLoaded)
    LoadHosts();
  if (m_IsLoaded) {
    auto it = m_Addresses.find(address);
    if (it != m_Addresses.end()) {
      return std::make_unique<const i2p::data::IdentHash>(it->second);
    }
  }
  return nullptr;
}

// TODO(anonimal): rename SubscriptionsDownloadComplete()
void AddressBook::DownloadComplete(
    bool success) {
  m_IsDownloading = false;
  if (m_SubscriptionsUpdateTimer) {
    m_SubscriptionsUpdateTimer->expires_from_now(
        boost::posix_time::minutes(
            success ?
            static_cast<std::uint16_t>(SubscriptionTimeout::ContinuousUpdate) :
            static_cast<std::uint16_t>(SubscriptionTimeout::ContinuousRetry)));
    m_SubscriptionsUpdateTimer->async_wait(
        std::bind(
            &AddressBook::HandleSubscriptionsUpdateTimer,
            this,
            std::placeholders::_1));
  }
}

void AddressBook::LoadHosts() {
  if (!m_Storage)
     m_Storage = CreateStorage();
  if (m_Storage->Load(m_Addresses) > 0) {
    m_IsLoaded = true;
    return;
  }
  // try hosts.txt first
  std::ifstream f(
      i2p::util::filesystem::GetFullPath("hosts.txt").c_str(),
      std::ofstream::in);  // in text mode
  if (f.is_open()) {
    LoadHostsFromStream(f);  // TODO(anonimal): sanity check
    m_IsLoaded = true;  // TODO(anonimal): rename m_HostsAreSaved
  } else {
    // if not found download it from http://i2p-projekt.i2p/hosts.txt
    // TODO(anonimal): replace with monero addresses
    LogPrint(eLogInfo,
        "AddressBook: hosts.txt not found, ",
        "attempting to download a default subscription");
    if (!m_IsDownloading) {
      m_IsDownloading = true;
      if (!m_DefaultSubscription)
        m_DefaultSubscription =
          std::make_unique<AddressBookSubscription>(
              *this,
              SubscriptionDownloadAddress.data());
      m_DefaultSubscription->CheckSubscription();
    }
  }
}

// TODO(anonimal): refactor to GetNewStorageInstance() and define inline
std::unique_ptr<AddressBookStorage> AddressBook::CreateStorage() {
  return std::make_unique<AddressBookFilesystemStorage>();
}

// TODO(anonimal): should return false on failure
// TODO(anonimal): rename SaveHostsFromStream()
void AddressBook::LoadHostsFromStream(
    std::istream& f) {
  std::unique_lock<std::mutex> l(m_AddressBookMutex);
  std::size_t num_addresses = 0;
  std::string s;
  while (!f.eof()) {
    getline(f, s);
    if (!s.length())
      continue;  // skip empty line
    std::size_t pos = s.find('=');
    if (pos != std::string::npos) {
      std::string name = s.substr(0, pos++);
      std::string addr = s.substr(pos);
      i2p::data::IdentityEx ident;
      if (ident.FromBase64(addr)) {
        m_Addresses[name] = ident.GetIdentHash();
        m_Storage->AddAddress(ident);
        num_addresses++;
      } else {
        LogPrint(eLogError,
            "AddressBook: malformed address ", addr, " for ", name);
      }
    }
  }
  LogPrint(eLogInfo,
      "AddressBook: ", num_addresses, " addresses processed");
  if (num_addresses > 0) {
    m_IsLoaded = true;
    m_Storage->Save(m_Addresses);
  }
}

// Used only by HTTP Proxy
void AddressBook::InsertAddress(
    const std::string& address,
    const std::string& base64) {
  i2p::data::IdentityEx ident;
  ident.FromBase64(base64);
  if (!m_Storage)
     m_Storage = CreateStorage();
  m_Storage->AddAddress(ident);
  m_Addresses[address] = ident.GetIdentHash();
  LogPrint(eLogInfo,
      "AddressBook: ", address, "->",
      ToAddress(ident.GetIdentHash()), " added");
}

void AddressBook::Stop() {
  StopSubscriptions();  // TODO(anonimal): remove, this isn't necessary
  if (m_SubscriptionsUpdateTimer) {
    m_SubscriptionsUpdateTimer.reset(nullptr);
  }
  if (m_IsDownloading) {
    LogPrint(eLogInfo,
        "AddressBook: subscription is downloading, waiting for termination");
    for (std::size_t i = 0; i < 30; i++) {
      if (!m_IsDownloading) {
        LogPrint(eLogInfo, "AddressBook: subscription download complete");
        break;
      }
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    LogPrint(eLogError, "AddressBook: subscription download hangs");
    m_IsDownloading = false;
  }
  if (m_Storage) {
    m_Storage->Save(m_Addresses);
    m_Storage.reset(nullptr);
  }
  if (m_DefaultSubscription) {
    m_DefaultSubscription.reset(nullptr);
  }
  m_Subscriptions.clear();
}

// TODO(anonimal): place inside Stop(), this function isn't necessary
void AddressBook::StopSubscriptions() {
  if (m_SubscriptionsUpdateTimer)
    m_SubscriptionsUpdateTimer->cancel();
}

/*
// TODO(unassigned): currently unused
void AddressBook::InsertAddress(
    const i2p::data::IdentityEx& address) {
  if (!m_Storage)
    m_Storage = CreateStorage();
  m_Storage->AddAddress(address);
}

// TODO(unassigned): currently unused
bool AddressBook::GetAddress(
    const std::string& address,
    i2p::data::IdentityEx& identity) {
  if (!m_Storage)
    m_Storage = CreateStorage();
  i2p::data::IdentHash ident;
  if (!GetIdentHash(address, ident)) return false;
  return m_Storage->GetAddress(ident, identity);
}
*/

}  // namespace client
}  // namespace i2p
