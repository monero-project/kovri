/**                                                                                           //
 * Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
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

#include "client/address_book/impl.h"

#include <boost/algorithm/string/trim.hpp>
#include <boost/asio.hpp>
#include <boost/network/uri.hpp>

#include <array>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <utility>

#include "core/crypto/rand.h"

#include "core/router/net_db/impl.h"

namespace kovri {
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
    LOG(error)
      << "AddressBook: won't start: we need a client destination";
    return;
  }
  LOG(info) << "AddressBook: starting service";
  m_SharedLocalDestination = local_destination;
  m_SubscriberUpdateTimer =
    std::make_unique<boost::asio::deadline_timer>(
        m_SharedLocalDestination->GetService());
  m_SubscriberUpdateTimer->expires_from_now(
      boost::posix_time::minutes{static_cast<long>(SubscriberTimeout::InitialUpdate)});
  m_SubscriberUpdateTimer->async_wait(
      std::bind(
          &AddressBook::SubscriberUpdateTimer,
          this,
          std::placeholders::_1));
}

void AddressBook::SubscriberUpdateTimer(
    const boost::system::error_code& ecode) {
  LOG(debug) << "AddressBook: begin " << __func__;
  if (ecode) {
    if (ecode != boost::asio::error::operation_aborted)
      LOG(error) << "AddressBook: " << __func__ << ": '" << ecode.message()
                 << "'";
    return;
  }
  // Load publishers (see below about multiple publishers)
  LoadPublishers();
  // If ready, download new subscription (see #337 for multiple subscriptions)
  if (m_SubscriptionIsLoaded
      && !m_SubscriberIsDownloading
      && m_SharedLocalDestination->IsReady()) {
    LOG(debug) << "AddressBook: ready to download new subscription";
    DownloadSubscription();
  } else {
    if (!m_SubscriptionIsLoaded) {
      // If subscription not available, will attempt download with subscriber
      LoadSubscriptionFromPublisher();
    }
    // Try again after timeout
    m_SubscriberUpdateTimer->expires_from_now(
        boost::posix_time::minutes{static_cast<long>(SubscriberTimeout::InitialRetry)});
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
  // References #337
  if (m_PublishersLoaded) {
    LOG(debug) << "AddressBook: publisher(s) already loaded";
    return;
  }
  auto publishers = GetDefaultPublishersFilename();
  LOG(info) << "AddressBook: loading publisher file " << publishers;
  std::ifstream file((core::GetPath(core::Path::AddressBook) / publishers).string());
  if (file) {
    // Publisher URI
    std::string publisher;
    // Validate publisher URI
    boost::network::uri::uri uri;
    // Read in publishers, line by line
    while (std::getline(file, publisher)) {
      // If found, clear whitespace before and after publisher (on the line)
      publisher.erase(
          std::remove_if(
              publisher.begin(),
              publisher.end(),
              [](char whitespace) { return std::isspace(whitespace); }),
          publisher.end());
      // If found, skip empty line
      if (!publisher.length())
        continue;
      // Perform URI sanity test
      if (!uri.string().empty())
        uri = boost::network::uri::uri();
      uri.append(publisher);
      if (!uri.is_valid())
        {
          LOG(warning)
              << "AddressBook: invalid/malformed publisher URI, skipping";
          continue;
        }
      // Save publisher to subscriber
      m_Subscribers.push_back(
          std::make_unique<AddressBookSubscriber>(*this, publisher));
    }
    LOG(info)
      << "AddressBook: " << m_Subscribers.size() << " publishers loaded";
  } else {
    auto publisher = GetDefaultPublisherURI();
    LOG(warning)
      << "AddressBook: " << publishers << " unavailable; using " << publisher;
    m_Subscribers.push_back(
        std::make_unique<AddressBookSubscriber>(*this, publisher));
    // TODO(anonimal): create default publisher file if file is missing
  }
  m_PublishersLoaded = true;
}

void AddressBook::LoadSubscriptionFromPublisher() {
  // Ensure subscriber is loaded with publisher(s) before service "starts"
  // (Note: look at how client tunnels start)
  if (!m_PublishersLoaded)
    LoadPublishers();
  // Ensure we have a storage instance ready
  if (!m_Storage) {
    LOG(debug) << "AddressBook: creating new storage instance";
    m_Storage = GetNewStorageInstance();
  }
  // If so, see if we have addresses from subscription already saved
  // TODO(anonimal): in order to load new fresh subscriptions,
  // we need to remove and/or work around this block and m_SubscriptionIsLoaded
  if (m_Storage->Load(m_Addresses)) {
    // If so, we don't need to download from a publisher
    LOG(debug) << "AddressBook: subscription is already loaded";
    m_SubscriptionIsLoaded = true;
    return;
  }
  // If available, load default subscription from file
  auto filename = GetDefaultSubscriptionFilename();
  std::ifstream file((core::GetPath(core::Path::AddressBook) / filename).string());
  LOG(info) << "AddressBook: loading subscription " << filename;
  if (file) {  // Open subscription, validate, and save to storage
    if (!SaveSubscription(file, SubscriptionType::Default))
      LOG(warning) << "AddressBook: could not load subscription " << filename;
  } else {  // Use default publisher and download
    LOG(warning) << "AddressBook: " << filename << " not found";
    if (!m_SubscriberIsDownloading) {
      LOG(debug) << "AddressBook: subscriber not downloading, downloading";
      DownloadSubscription();
    } else {
      LOG(warning) << "AddressBook: subscriber is downloading";
    }
  }
}

void AddressBook::DownloadSubscription() {
  // Get number of available publishers (guaranteed > 0)
  auto publisher_count = m_Subscribers.size();
  LOG(debug)
    << "AddressBook: picking random subscription from total publisher count: "
    << publisher_count;
  // Pick a random publisher to subscribe from
  // TODO(oneiric): download all subscriptions not already stored
  auto publisher = kovri::core::RandInRange32(0, publisher_count - 1);
  m_SubscriberIsDownloading = true;
  try {
    m_Subscribers.at(publisher)->DownloadSubscription();
  } catch (const std::exception& ex) {
    LOG(error) << "AddressBook: download subscription exception: " << ex.what();
  } catch (...) {
    LOG(error) << "AddressBook: download subscription unknown exception";
  }
  // Ensure false here if exception occured before subscriber completed download
  m_SubscriberIsDownloading = false;
}

void AddressBookSubscriber::DownloadSubscription() {
  // TODO(unassigned): exception handling
  LOG(debug) << "AddressBookSubscriber: creating thread for download";
  std::thread download(&AddressBookSubscriber::DownloadSubscriptionImpl, this);
  download.join();
}

void AddressBookSubscriber::DownloadSubscriptionImpl() {
  // TODO(anonimal): ensure thread safety
  LOG(info)
    << "AddressBookSubscriber: downloading subscription "
    << m_HTTP.GetURI().string()
    << " ETag: " << m_HTTP.GetPreviousETag()
    << " Last-Modified: " << m_HTTP.GetPreviousLastModified();
  bool download_result = m_HTTP.Download();
  if (download_result) {
      auto sub = m_HTTP.GetURI().string() == m_Book.GetDefaultPublisherURI()
                     ? AddressBook::SubscriptionType::Default
                     : AddressBook::SubscriptionType::User;
      std::stringstream stream(m_HTTP.GetDownloadedContents());
      if (!m_Book.SaveSubscription(stream, sub))
        {
          // Error during validation or storage, download again later
          download_result = false;
        }
  }
  m_Book.HostsDownloadComplete(download_result);
}

void AddressBook::HostsDownloadComplete(
    bool success) {
  LOG(debug) << "AddressBook: subscription download complete";
  if (m_SubscriberUpdateTimer) {
    m_SubscriberUpdateTimer->expires_from_now(
        boost::posix_time::minutes{
        static_cast<long>(
            success
            ? SubscriberTimeout::ContinuousUpdate
            : SubscriberTimeout::ContinuousRetry)});
    m_SubscriberUpdateTimer->async_wait(
        std::bind(
            &AddressBook::SubscriberUpdateTimer,
            this,
            std::placeholders::_1));
  }
}

// TODO(unassigned): extend this to append new hosts (when other subscriptions are used)
bool AddressBook::SaveSubscription(std::istream& stream, SubscriptionType sub)
{
  std::unique_lock<std::mutex> lock(m_AddressBookMutex);
  m_SubscriptionIsLoaded = false;  // TODO(anonimal): see TODO for multiple subscriptions
  try {
    auto addresses = ValidateSubscription(stream);
    if (!addresses.empty()) {
      LOG(debug) << "AddressBook: processing " << addresses.size() << " addresses";
      // Stream may be a file or downloaded stream.
      // Regardless, we want to write/overwrite the subscription file.
      // Save hosts and matching identities
      m_Storage->SaveSubscription(addresses, sub);
      for (auto const& address : addresses) {
        const std::string& host = address.first;
        const auto& ident = address.second;
        try
          {
            // Only stores subscription lines for addresses not already loaded
            InsertAddress(host, ident.GetIdentHash(), sub);
            m_Storage->AddAddress(ident);
          }
        catch (...)
          {
            m_Exception.Dispatch(__func__);
            continue;
          }
      }
      // Save a *list* of hosts within subscription to a catalog (CSV) file
      m_Storage->Save(m_Addresses);
      m_SubscriptionIsLoaded = true;
    }
  } catch (...) {
    m_Exception.Dispatch(__func__);
  }
  return m_SubscriptionIsLoaded;
}

// TODO(anonimal): unit-test

const std::map<std::string, kovri::core::IdentityEx>
AddressBook::ValidateSubscription(std::istream& stream) {
  LOG(debug) << "AddressBook: validating subscription";
  // Map host to address identity
  std::map<std::string, kovri::core::IdentityEx> addresses;
  // To ensure valid Hostname=Base64Address
  std::string line;
  // To ensure valid hostname
  // Note: uncomment if this regexp fails on some locales (to not rely on [a-z])
  //const std::string alpha = "abcdefghijklmnopqrstuvwxyz";
  // TODO(unassigned): expand when we want to venture beyond the .i2p TLD
  // TODO(unassigned): IDN ccTLDs support?
  // TODO(unassigned): investigate alternatives to regex (maybe Boost.Spirit?)
  std::regex regex("(?=^.{1,253}$)(^(((?!-)[a-zA-Z0-9-]{1,63})|((?!-)[a-zA-Z0-9-]{1,63}\\.)+[a-zA-Z]+[(i2p)]{2,63})$)");
  try {
    // Read through stream, add to address book
    while (std::getline(stream, line)) {
      // Skip empty / too large lines
      if (line.empty() || line.size() > AddressBookSize::SubscriptionLine)
        continue;
      // Trim whitespace before and after line
      boost::trim(line);
      // Parse Hostname=Base64Address from line
      kovri::core::IdentityEx ident;
      std::size_t pos = line.find('=');
      if (pos != std::string::npos) {
        const std::string host = line.substr(0, pos++);
        const std::string addr = line.substr(pos);
        // Ensure only valid lines
        try
          {
            if (host.empty() || !std::regex_search(host, regex))
              throw std::runtime_error("AddressBook: invalid hostname");
            ident.FromBase64(addr);
          }
        catch (...)
          {
            m_Exception.Dispatch(__func__);
            LOG(warning) << "AddressBook: malformed address, skipping";
            continue;
          }
        addresses[host] = ident;  // Host is valid, save
      }
    }
  } catch (const std::exception& ex) {
    LOG(error) << "AddressBook: exception during validation: ", ex.what();
    addresses.clear();
  } catch (...) {
    throw std::runtime_error("AddressBook: unknown exception during validation");
  }
  return addresses;
}

// For in-net download only
bool AddressBook::CheckAddressIdentHashFound(
    const std::string& address,
    kovri::core::IdentHash& ident) {
  auto pos = address.find(".b32.i2p");
  if (pos != std::string::npos)
    {
      try
        {
          ident.FromBase32(address.substr(0, pos));
        }
      catch (...)
        {
          core::Exception ex;
          ex.Dispatch("AddressBook: invalid Base32 address");
          return false;
        }
      return true;
    }
  else {
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
  kovri::core::IdentityEx dest;
  try
    {
      dest.FromBase64(address);
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      return false;
    }
  ident = dest.GetIdentHash();
  return true;
}

// For in-net download only
std::unique_ptr<const kovri::core::IdentHash> AddressBook::GetLoadedAddressIdentHash(
    const std::string& address) {
  if (!m_SubscriptionIsLoaded)
    LoadSubscriptionFromPublisher();
  if (m_SubscriptionIsLoaded) {
    auto it = m_Addresses.find(address);
    if (it != m_Addresses.end()) {
      return std::make_unique<const kovri::core::IdentHash>(
          std::get<kovri::core::IdentHash>(it->second));
    }
  }
  return nullptr;
}

// TODO(unassigned): return bool
void AddressBook::InsertAddress(
    const std::string& host,
    const kovri::core::IdentHash& address,
    SubscriptionType source)
{
  try
  {
    // Ensure address book only inserts unique entries
    if (!m_Addresses.empty())
      {
        // TODO(unassigned): these throws should instead log warning and return bool
        auto host_search = m_Addresses.find(host);
        if (host_search != m_Addresses.end())
          throw std::runtime_error("AddressBook: host already loaded");
        for (const auto& entry : m_Addresses)
          if (std::get<kovri::core::IdentHash>(entry.second) == address)
            throw std::runtime_error("AddressBook: address already loaded");
      }
    m_Addresses[host] = std::make_pair(address, source);
  }
  catch (...)
  {
    m_Exception.Dispatch(__func__);
    throw;
  }
}

// Used only by HTTP Proxy
void AddressBook::InsertAddressIntoStorage(
    const std::string& address,
    const std::string& base64)
{
  try
    {
      kovri::core::IdentityEx ident;
      ident.FromBase64(base64);
      const auto& ident_hash = ident.GetIdentHash();
      InsertAddress(address, ident_hash, SubscriptionType::User);
      if (!m_Storage)
        m_Storage = GetNewStorageInstance();
      m_Storage->AddAddress(ident);
      LOG(info) << "AddressBook: " << address << "->"
                << kovri::core::GetB32Address(ident_hash)
                << " added";
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }
}

void AddressBook::Stop() {
  // Kill subscriber timer
  if (m_SubscriberUpdateTimer) {
    m_SubscriberUpdateTimer->cancel();
    m_SubscriberUpdateTimer.reset(nullptr);
  }
  // Finish downloading
  if (m_SubscriberIsDownloading) {
    LOG(info)
      << "AddressBook: subscription is downloading, waiting for termination";
    for (std::size_t seconds = 0;
         seconds < static_cast<std::uint16_t>(kovri::client::Timeout::Receive);
         seconds++) {
      if (!m_SubscriberIsDownloading) {
        LOG(info) << "AddressBook: subscription download complete";
        break;
      }
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    LOG(error) << "AddressBook: subscription download hangs";
    m_SubscriberIsDownloading = false;
  }
  // Save addresses to storage
  if (m_Storage) {
    m_Storage->Save(m_Addresses);
    m_Storage.reset(nullptr);
  }
  m_Subscribers.clear();
}

BookEntry::BookEntry(
    const std::string& host,
    const kovri::core::IdentHash& address) try : m_Host(host),
                                                 m_Address(address)
  {
    if (m_Host.empty())
      throw std::invalid_argument("AddressBook: empty entry hostname");
  }
catch (...)
  {
    kovri::core::Exception ex(__func__);
    ex.Dispatch();
    throw;
  }

BookEntry::BookEntry(
    const std::string& host,
    const std::string& address) try : m_Host(host)
  {
    if (m_Host.empty())
      throw std::invalid_argument("AddressBook: empty entry hostname");
    core::IdentityEx ident;
    ident.FromBase64(address);
    m_Address = ident.GetIdentHash();
  }
catch (...)
  {
    kovri::core::Exception ex(__func__);
    ex.Dispatch();
    throw;
  }

BookEntry::BookEntry(const std::string& subscription_line) try
  {
    if (subscription_line.empty())
      throw std::invalid_argument("AddressBook: empty subscription line");
    std::size_t pos = subscription_line.find('=');
    if (pos == std::string::npos)
      throw std::runtime_error("AddressBook: invalid subscription line");
    m_Host = subscription_line.substr(0, pos++);
    if (m_Host.empty())
      throw std::runtime_error("AddressBook: empty entry hostname");
    core::IdentityEx ident;
    ident.FromBase64(subscription_line.substr(pos));
    m_Address = ident.GetIdentHash();
  }
catch (...)
  {
    kovri::core::Exception ex(__func__);
    ex.Dispatch();
    throw;
  }

const std::string& BookEntry::get_host() const noexcept
{
  return m_Host;
}

const core::IdentHash& BookEntry::get_address() const noexcept
{
  return m_Address;
}
/*
// TODO(unassigned): currently unused
void AddressBook::InsertAddress(
    const kovri::core::IdentityEx& address) {
  if (!m_Storage)
    m_Storage = GetNewStorageInstance();
  m_Storage->AddAddress(address);
}

// TODO(unassigned): currently unused
bool AddressBook::GetAddress(
    const std::string& address,
    kovri::core::IdentityEx& identity) {
  if (!m_Storage)
    m_Storage = GetNewStorageInstance();
  kovri::core::IdentHash ident;
  if (!GetAddressIdentHash(address, ident)) return false;
  return m_Storage->GetAddress(ident, identity);
}
*/

}  // namespace client
}  // namespace kovri
