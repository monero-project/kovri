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
 * 6. Kovri's subscriber checks if publisher is in-net or clearnet then downloads
 *    subscription/updated subscription
 * 7. Kovri saves subscription to storage
 * 8. Kovri repeats download ad infinitum on a timer using specified constants
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
  if (!m_Subscribers.size()) {
    auto filename = GetDefaultPublishersFilename();
    std::ifstream file(
        i2p::util::filesystem::GetFullPath(filename),
        std::ofstream::in);  // in text mode
    if (file.is_open()) {
      std::string address;
      while (!file.eof()) {
        getline(file, address);
        if (!address.length())
          continue;  // skip empty line
        // Perform sanity test for valid URI
        i2p::util::http::URI uri;
        if (!uri.Parse(address)) {
          LogPrint(eLogWarn,
              "AddressBook: invalid/malformed publisher address, skipping");
          continue;
        }
        m_Subscribers.push_back(
            std::make_unique<AddressBookSubscriber>(*this, address));
      }
      LogPrint(eLogInfo,
          "AddressBook: ", m_Subscribers.size(), " publishers loaded");
    } else {
      LogPrint(eLogWarn,
          "AddressBook: ", filename, " not found; using default publisher");
      m_Subscribers.push_back(
          std::make_unique<AddressBookSubscriber>(*this, GetDefaultPublisherURI()));
    }
  } else {
    LogPrint(eLogError, "AddressBook: publishers already loaded");
  }
}

void AddressBook::SubscriberUpdateTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    // If hosts are saved + we're not currently downloading + are fully online
    if (m_HostsAreLoaded && !m_SubscriberIsDownloading &&
        m_SharedLocalDestination->IsReady()) {
      // Pick a random subscription if user has multiple publishers
      auto publisher =
        i2p::crypto::RandInRange<std::size_t>(0, m_Subscribers.size() - 1);
      m_SubscriberIsDownloading = true;
      m_Subscribers[publisher]->DownloadSubscription();
    } else {
      if (!m_HostsAreLoaded) {
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

void AddressBookSubscriber::DownloadSubscription() {
  std::thread download(&AddressBookSubscriber::DownloadSubscriptionImpl, this);
  download.detach();  // TODO(anonimal): use join
}

// TODO(anonimal): see HTTP for notes on cpp-netlib refactor
// tl;dr, all HTTP-related code + stream handling should be refactored
void AddressBookSubscriber::DownloadSubscriptionImpl() {
  LogPrint(eLogInfo,
      "AddressBookSubscriber: downloading hosts from ", m_URI,
      " ETag: ", m_Etag,
      " Last-Modified: ", m_LastModified);
  bool success = false;
  i2p::util::http::URI uri;
  // TODO(anonimal): implement check to see if URI is in-net or clearnet,
  // and then implement download appropriately
  // If in-net, translate address to ident hash, find lease-set, and download
  // TODO(unassigned): we need to abstract this download process. See #168.
  i2p::data::IdentHash ident;
  if (m_Book.CheckAddressIdentHashFound(uri.m_Host, ident) &&
      m_Book.GetSharedLocalDestination()) {
    std::condition_variable new_data_received;
    std::mutex new_data_received_mutex;
    auto lease_set = m_Book.GetSharedLocalDestination()->FindLeaseSet(ident);
    if (!lease_set) {
      std::unique_lock<std::mutex> lock(new_data_received_mutex);
      m_Book.GetSharedLocalDestination()->RequestDestination(
          ident,
          [&new_data_received, &lease_set](
              std::shared_ptr<i2p::data::LeaseSet> ls) {
            lease_set = ls;
            new_data_received.notify_all();
          });
      if (new_data_received.wait_for(
              lock,
              std::chrono::seconds(
                  static_cast<std::uint16_t>(SubscriberTimeout::Request)))
          == std::cv_status::timeout)
        LogPrint(eLogError,
            "AddressBookSubscriber: ",
            "subscription lease set request timeout expired");
    }
    // Lease-set found, download in-net subscription from publisher
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
      bool end_of_data = false;
      while (!end_of_data) {
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
                  end_of_data = true;
                new_data_received.notify_all();
              },
            static_cast<std::uint16_t>(SubscriberTimeout::Receive));
        std::unique_lock<std::mutex> lock(new_data_received_mutex);
        if (new_data_received.wait_for(
                lock,
                std::chrono::seconds(
                    static_cast<std::uint16_t>(SubscriberTimeout::Request)))
            == std::cv_status::timeout)
          LogPrint(eLogError,
              "AddressBookSubscriber: subscription timeout expired");
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
            "AddressBookSubscriber: ", m_URI,
            " ETag: ", m_Etag,
            " Last-Modified: ", m_LastModified);
        if (!response.eof()) {
          success = true;
          if (!is_chunked) {
            m_Book.ValidateSubscriptionThenSaveToStorage(response);
          } else {
            // merge chunks
            std::stringstream merged;
            http.MergeChunkedResponse(response, merged);
            m_Book.ValidateSubscriptionThenSaveToStorage(merged);
          }
        }
      } else if (status == 304) {
        success = true;
        LogPrint(eLogInfo,
            "AddressBookSubscriber: no updates from ", m_URI);
      } else {
        LogPrint(eLogWarn,
            "AddressBookSubscriber: HTTP response ", status);
      }
    } else {
      LogPrint(eLogError,
          "AddressBookSubscriber: address ", uri.m_Host, " not found");
    }
  } else {
    LogPrint(eLogError,
        "AddressBookSubscriber: can't resolve ", uri.m_Host);
  }
  LogPrint(eLogInfo,
      "AddressBookSubscriber: download complete ",
      success ? "Success" : "Failed");
  m_Book.HostsDownloadComplete(success);
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
  if (!m_HostsAreLoaded)
    LoadSubscriptionFromPublisher();
  if (m_HostsAreLoaded) {
    auto it = m_Addresses.find(address);
    if (it != m_Addresses.end()) {
      return std::make_unique<const i2p::data::IdentHash>(it->second);
    }
  }
  return nullptr;
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

void AddressBook::LoadSubscriptionFromPublisher() {
  // First, ensure we have a storage instance ready
  if (!m_Storage)
     m_Storage = GetNewStorageInstance();
  // If so, see if we have hosts available
  if (m_Storage->Load(m_Addresses) > 0) {
    // If so, we don't need to download from a publisher
    m_HostsAreLoaded = true;
    return;
  }
  // If available, load default subscription from file
  auto filename = GetDefaultSubscriptionFilename();
  std::ifstream file(
      i2p::util::filesystem::GetFullPath(filename),
      std::ofstream::in);
  if (file.is_open()) {
    if (!ValidateSubscriptionThenSaveToStorage(file)) {
      LogPrint(eLogWarn, "AddressBook: invalid host in subscription");
      m_HostsAreLoaded = false;
    }
    m_HostsAreLoaded = true;
  } else {
    // If file not found, download from default address
    LogPrint(eLogInfo,
        "AddressBook: ", filename, " not found, ",
        "attempting to download a subscription from default publisher");
    if (!m_SubscriberIsDownloading) {
      m_SubscriberIsDownloading = true;
      if (!m_DefaultSubscriber)
        m_DefaultSubscriber =
          std::make_unique<AddressBookSubscriber>(
              *this,
              GetDefaultPublisherURI());
      m_DefaultSubscriber->DownloadSubscription();
    }
  }
}

bool AddressBook::ValidateSubscriptionThenSaveToStorage(
    std::istream& stream) {
  std::unique_lock<std::mutex> lock(m_AddressBookMutex);
  std::size_t num_addresses = 0;
  std::string host;
  while (!stream.eof()) {
    getline(stream, host);
    if (!host.length())
      continue;  // skip empty line
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
	return false;
      }
    }
  }
  LogPrint(eLogInfo,
      "AddressBook: ", num_addresses, " addresses processed");
  if (num_addresses > 0) {
    m_Storage->Save(m_Addresses);
    m_HostsAreLoaded = true;
  }
  return true;
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
         seconds < static_cast<std::uint16_t>(SubscriberTimeout::Receive);
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
  // Save addressses to storage
  if (m_Storage) {
    m_Storage->Save(m_Addresses);
    m_Storage.reset(nullptr);
  }
  // Kill subscriber
  if (m_DefaultSubscriber) {
    m_DefaultSubscriber.reset(nullptr);
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
