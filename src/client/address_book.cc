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

/**
 * VOCABULARY:
 *
 * Publisher:
 *   Entity that publishes a 'subscription'; usually from their website
 *
 * Subscription:
 *   Text file containing a list of TLD .i2p hosts paired with base64 address
 *   (see I2P naming and address book specification)
 *
 * Subscriber:
 *   Entity that subscribes (downloads + processes) a publisher's subscription
 *
 * NARRATIVE:
 *
 * 1. A trusted publisher publishes a subscription
 * 2. Subscription contains spec-defined host=base64 pairing; one host per line
 * 3. Kovri checks if we have a list of publishers; if not, uses default
 * 4. Kovri hooks its subscriber to into an asio timer that regularly
 *    updates a subscription (only downloads new subscription if Etag is set)
 * 5. If available, kovri loads default packaged subscription before downloading
 * 6. Kovri's subscriber checks if downloads subscription/updated subscription
 * 7. Kovri saves subscription to storage
 * 8. Kovri repeats download ad infinitum with a timer based on specified constants
 */

void AddressBook::Start(
    std::shared_ptr<ClientDestination> local_destination) {
  // We need tunnels so we can download in-net
  if (!local_destination) {
    LogPrint(eLogError,
      "AddressBook: won't start: we need a client destination");
    return;
  } else {
    m_SharedLocalDestination = local_destination;
    // Load publishers for us to subscribe to
    LoadPublishers();
    m_SubscriberUpdateTimer =
      std::make_unique<boost::asio::deadline_timer>(
          m_SharedLocalDestination->GetService());
    m_SubscriberUpdateTimer->expires_from_now(
        boost::posix_time::minutes(
            static_cast<std::uint16_t>(SubscriberTimeout::InitialUpdate)));
    m_SubscriberUpdateTimer->async_wait(
        std::bind(
            &AddressBook::SubscriberUpdateTimer,
            this,
            std::placeholders::_1));
  }
}

void AddressBook::LoadPublishers() {
  // TODO(unassigned): this is a one-shot: we won't be able to
  // edit publisher's file manually with any effect after router start
  if (m_Subscribers.empty()) {
    auto publishers = GetDefaultPublishersFilename();
    LogPrint(eLogInfo, "AddressBook: loading publisher file ", publishers);
    std::ifstream file(
        i2p::util::filesystem::GetFullPath(publishers),
        std::ofstream::in);
    if (file.is_open()) {
      std::string publisher;
      while (!file.eof()) {
        getline(file, publisher);
        if (!publisher.length())
          continue;  // skip empty line
        // Perform sanity test for valid URI
        i2p::util::http::HTTP http(publisher);
        if (!http.GetURI().is_valid()) {
          LogPrint(eLogWarn,
              "AddressBook: invalid/malformed publisher address, skipping");
          continue;
        }
        m_Subscribers.push_back(
            std::make_unique<AddressBookSubscriber>(*this, publisher));
      }
      LogPrint(eLogInfo,
          "AddressBook: ", m_Subscribers.size(), " publishers loaded");
    } else {
      LogPrint(eLogWarn,
          "AddressBook: ", publishers, " not found; we'll use default publisher");
      // TODO(anonimal): create default publisher file if file is missing
    }
  } else {
    LogPrint(eLogError, "AddressBook: publisher(s) already loaded");
  }
}

void AddressBook::SubscriberUpdateTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    if (m_SubscriptionIsLoaded
        && !m_SubscriberIsDownloading
        && m_SharedLocalDestination->IsReady()) {
      // Pick a random subscription if subscriptions count is > 0
      // At first this may look questionable but, by this point,
      // we're guaranteed to have at least one subscriber
      auto publisher =
        i2p::crypto::RandInRange<std::size_t>(0, m_Subscribers.size() - 1);
      m_SubscriberIsDownloading = true;
      m_Subscribers.at(publisher)->DownloadSubscription();
    } else {
      if (!m_SubscriptionIsLoaded) {
        // If subscription not available, will attempt download with subscriber
        LoadSubscriptionFromPublisher();
      }
      // Try again after timeout
      m_SubscriberUpdateTimer->expires_from_now(
          boost::posix_time::minutes(
              static_cast<std::uint16_t>(SubscriberTimeout::InitialRetry)));
      m_SubscriberUpdateTimer->async_wait(
          std::bind(
              &AddressBook::SubscriberUpdateTimer,
              this,
              std::placeholders::_1));
    }
  } else {
    LogPrint(eLogError,
        "AddressBook: SubscriberUpdateTimer() exception: ", ecode.message());
  }
}

void AddressBook::LoadSubscriptionFromPublisher() {
  // First, ensure we have a storage instance ready
  if (!m_Storage)
    m_Storage = GetNewStorageInstance();
  // If so, see if we have addresses from subscription already saved
  if (m_Storage->Load(m_Addresses)) {
    // If so, we don't need to download from a publisher
    m_SubscriptionIsLoaded = true;
    return;
  }
  // If available, load default subscription from file
  auto filename = GetDefaultSubscriptionFilename();
  std::ifstream file(
      i2p::util::filesystem::GetFullPath(filename),
      std::ofstream::in);
  LogPrint(eLogInfo, "AddressBook: loading subscription ", filename);
  if (file.is_open()) {  // Open subscription, validate, and save to storage
    m_SubscriptionFileIsReady = true;
    if (!ValidateSubscriptionThenSaveToStorage(file))
      LogPrint(eLogWarn,
          "AddressBook: invalid host in ", filename, ", not loading");
  } else {  // Use default publisher and download
    LogPrint(eLogWarn, "AddressBook: ", filename, " not found");
    if (!m_SubscriberIsDownloading) {
      if (m_Subscribers.empty()) {
        auto publisher = GetDefaultPublisherURI();
        LogPrint(eLogWarn, "AddressBook: using default publisher ", publisher);
        m_Subscribers.push_back(
            std::make_unique<AddressBookSubscriber>(*this, publisher));
      }
      m_SubscriberIsDownloading = true;
      m_Subscribers.front()->DownloadSubscription();
    } else {
      LogPrint(eLogWarn, "AddressBook: subscriber is downloading");
    }
  }
}

void AddressBookSubscriber::DownloadSubscription() {
  std::thread download(&AddressBookSubscriber::DownloadSubscriptionImpl, this);
  download.detach();  // TODO(anonimal): use join
}

void AddressBookSubscriber::DownloadSubscriptionImpl() {
  LogPrint(eLogInfo,
      "AddressBookSubscriber: downloading subscription ", m_HTTP.GetURI().string(),
      " ETag: ", m_HTTP.GetPreviousETag(),
      " Last-Modified: ", m_HTTP.GetPreviousLastModified());
  bool download_result = m_HTTP.Download();
  if (download_result) {
    std::stringstream stream(m_HTTP.GetDownloadedContents());
    if (!m_Book.ValidateSubscriptionThenSaveToStorage(stream)) {
      // Error during validation or storage, download again later
      download_result = false;
    }
  }
  m_Book.HostsDownloadComplete(download_result);
}

void AddressBook::HostsDownloadComplete(
    bool success) {
  m_SubscriberIsDownloading = false;
  if (m_SubscriberUpdateTimer) {
    m_SubscriberUpdateTimer->expires_from_now(
        boost::posix_time::minutes(
            success ?
            static_cast<std::uint16_t>(SubscriberTimeout::ContinuousUpdate) :
            static_cast<std::uint16_t>(SubscriberTimeout::ContinuousRetry)));
    m_SubscriberUpdateTimer->async_wait(
        std::bind(
            &AddressBook::SubscriberUpdateTimer,
            this,
            std::placeholders::_1));
  }
}

// TODO(unassigned): extend this to append new hosts (when other subscriptions are used)
bool AddressBook::ValidateSubscriptionThenSaveToStorage(
    std::istream& stream) {
  // Save to subscription file if file does not exist or we have fresh download
  std::unique_lock<std::mutex> lock(m_AddressBookMutex);
  std::ofstream file;
  if (!m_SubscriptionFileIsReady) {
    file.open(
        i2p::util::filesystem::GetFullPath(GetDefaultSubscriptionFilename()),
        std::ofstream::out);
    m_SubscriptionFileIsReady = true;
  }
  // Host per line and total number of host addresses
  std::string host;
  std::size_t num_addresses = 0;
  // Read through stream, add to address book
  while (!stream.eof()) {
    getline(stream, host);
    if (!host.length())
      continue;  // skip empty line
    // File ready, write/overwrite to disk
    if (m_SubscriptionFileIsReady)
      file << host << std::endl;
    // Parse host from address, save to address book
    std::size_t pos = host.find('=');
    if (pos != std::string::npos) {
      std::string name = host.substr(0, pos++);
      std::string addr = host.substr(pos);
      i2p::data::IdentityEx ident;
      if (ident.FromBase64(addr)) {
        m_Addresses[name] = ident.GetIdentHash();
        m_Storage->AddAddress(ident);
        num_addresses++;
      } else {
        LogPrint(eLogError,
            "AddressBook: malformed address ", addr, " for ", name);
        m_SubscriptionIsLoaded = false;
      }
    }
  }
  LogPrint(eLogInfo, "AddressBook: ", num_addresses, " addresses processed");
  if (num_addresses) {
    // Save list of hosts within subscription to a catalog file
    m_Storage->Save(m_Addresses);
    m_SubscriptionIsLoaded = true;
  }
  m_SubscriptionFileIsReady = false;  // Reset for fresh download
  return m_SubscriptionIsLoaded;
}

// For in-net download only
bool AddressBook::CheckAddressIdentHashFound(
    const std::string& address,
    i2p::data::IdentHash& ident) {
  auto pos = address.find(".b32.i2p");
  if (pos != std::string::npos) {
    if (!i2p::util::Base32ToByteStream(address.c_str(), pos, ident, 32)) {
      LogPrint(eLogError, "AddressBook: invalid base32 address");
      return false;
    }
    return true;
  } else {
    pos = address.find(".i2p");
    if (pos != std::string::npos) {
      auto ident_hash = GetLoadedAddressIdentHash(address);
      if (ident_hash) {
        ident = *ident_hash;
        return true;
      } else {
        return false;
      }
    }
  }
  // If not .b32, test for full base64 address
  i2p::data::IdentityEx dest;
  if (!dest.FromBase64(address))
    return false;  // Invalid base64 address
  ident = dest.GetIdentHash();
  return true;
}

// For in-net download only
std::unique_ptr<const i2p::data::IdentHash> AddressBook::GetLoadedAddressIdentHash(
    const std::string& address) {
  if (!m_SubscriptionIsLoaded)
    LoadSubscriptionFromPublisher();
  if (m_SubscriptionIsLoaded) {
    auto it = m_Addresses.find(address);
    if (it != m_Addresses.end()) {
      return std::make_unique<const i2p::data::IdentHash>(it->second);
    }
  }
  return nullptr;
}

// Used only by HTTP Proxy
void AddressBook::InsertAddressIntoStorage(
    const std::string& address,
    const std::string& base64) {
  i2p::data::IdentityEx ident;
  ident.FromBase64(base64);
  if (!m_Storage)
    m_Storage = GetNewStorageInstance();
  m_Storage->AddAddress(ident);
  m_Addresses[address] = ident.GetIdentHash();
  LogPrint(eLogInfo,
      "AddressBook: ", address, "->",
      GetB32AddressFromIdentHash(ident.GetIdentHash()), " added");
}

void AddressBook::Stop() {
  // Kill subscriber timer
  if (m_SubscriberUpdateTimer) {
    m_SubscriberUpdateTimer->cancel();
    m_SubscriberUpdateTimer.reset(nullptr);
  }
  // Finish downloading
  if (m_SubscriberIsDownloading) {
    LogPrint(eLogInfo,
        "AddressBook: subscription is downloading, waiting for termination");
    for (std::size_t seconds = 0;
         seconds < static_cast<std::uint16_t>(i2p::util::http::Timeout::Receive);
         seconds++) {
      if (!m_SubscriberIsDownloading) {
        LogPrint(eLogInfo, "AddressBook: subscription download complete");
        break;
      }
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    LogPrint(eLogError, "AddressBook: subscription download hangs");
    m_SubscriberIsDownloading = false;
  }
  // Save addresses to storage
  if (m_Storage) {
    m_Storage->Save(m_Addresses);
    m_Storage.reset(nullptr);
  }
  m_Subscribers.clear();
}

/*
// TODO(unassigned): currently unused
void AddressBook::InsertAddress(
    const i2p::data::IdentityEx& address) {
  if (!m_Storage)
    m_Storage = GetNewStorageInstance();
  m_Storage->AddAddress(address);
}

// TODO(unassigned): currently unused
bool AddressBook::GetAddress(
    const std::string& address,
    i2p::data::IdentityEx& identity) {
  if (!m_Storage)
    m_Storage = GetNewStorageInstance();
  i2p::data::IdentHash ident;
  if (!GetAddressIdentHash(address, ident)) return false;
  return m_Storage->GetAddress(ident, identity);
}
*/

}  // namespace client
}  // namespace i2p
