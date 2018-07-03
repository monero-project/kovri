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

#ifndef SRC_CLIENT_ADDRESS_BOOK_IMPL_H_
#define SRC_CLIENT_ADDRESS_BOOK_IMPL_H_

#include <boost/asio/deadline_timer.hpp>

#include <atomic>
#include <cstdint>
#include <iosfwd>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "client/address_book/storage.h"
#include "client/destination.h"
#include "client/util/http.h"

#include "core/router/identity.h"
#include "core/router/context.h"

#include "core/util/exception.h"
#include "core/util/filesystem.h"
#include "core/util/log.h"

namespace kovri {
namespace client {

class AddressBookSubscriber;
/// @class BookEntry
/// @brief Container for Address Book entry
class BookEntry
{
 public:
  /// @brief Create address book entry from a hostname & identity hash
  /// @param host Kovri hostname
  /// @param address Kovri identity hash
  /// @throw std::invalid_argument on empty hostname
  BookEntry(const std::string& host, const kovri::core::IdentHash& address);

  /// @brief Create address book entry from a host & base64-encoded address
  /// @param host Kovri hostname
  /// @param address Base64-encoded Kovri address
  /// @throw std::invalid_argument on empty hostname
  /// @throw std::runtime_error on malformed or empty address
  BookEntry(const std::string& host, const std::string& address);

  /// @brief Create address book entry from a subscription line
  /// @param subscription_line Line from a subscription file (host=address format)
  /// @throw std::invalid_argument on empty subscription line
  /// @throw std::runtime_error on empty hostname
  /// @throw std::runtime_error on malformed subscription line
  /// @throw std::runtime_error on malformed address
  explicit BookEntry(const std::string& subscription_line);

  /// @brief Accessor for host data member
  const std::string& get_host() const noexcept;

  /// @brief Accessor for address data member
  const core::IdentHash& get_address() const noexcept;

 private:
  std::string m_Host;  ///< Human-readable Kovri hostname
  core::IdentHash m_Address;  ///< Kovri identity hash
};
/// @class AddressBook
/// @brief Address book implementation
class AddressBook : public AddressBookDefaults {
 public:
  /// @brief Initializes defaults for address book implementation
  AddressBook()
      : m_Exception(__func__),
        m_SharedLocalDestination(nullptr),
        m_Storage(nullptr),
        m_SubscriberUpdateTimer(nullptr),
        m_SubscriptionIsLoaded(false),
        m_PublishersLoaded(false),
        m_SubscriberIsDownloading(false) {}

  /// @brief Starts address book fetching and processing of spec-related files
  /// @param local_destination Shared pointer to destination instance used to
  ///   generate lease set and tunnel pool for downloading new subscription(s)
  void Start(
      std::shared_ptr<ClientDestination> local_destination);

  /// @brief Stops and handles cleanup for address book
  /// @details Stops timers, finishes downloading if in progress, saves
  ///   addresses in memory to disk, cleans up memory
  void Stop();

  /// @brief Checks identity hash derived from .b32.i2p address
  /// @return True if identity hash was found
  /// @param address Const reference to .b32.i2p address
  /// @param ident Reference to identity hash
  /// @notes If identity hash is found point @param ident to found hash
  /// @notes Used for in-net downloads only
  bool CheckAddressIdentHashFound(
      const std::string& address,
      kovri::core::IdentHash& ident);

  /// @brief Finds address within loaded subscriptions
  /// @returns Unique pointer to identity hash of loaded address
  /// @param address Const reference to address
  /// @notes Used for in-net downloads only
  std::unique_ptr<const kovri::core::IdentHash> GetLoadedAddressIdentHash(
      const std::string& address);

  /// @brief Used for destination to fetch subscription(s) from publisher(s)
  /// @return Shared pointer to client destination
  std::shared_ptr<ClientDestination> GetSharedLocalDestination() const {
    return m_SharedLocalDestination;
  }

  /// @brief Insert address into in-memory storage
  /// @param host Human-readable hostname to insert
  /// @param address Hash of address to insert
  /// @param source Subscription type for where to store the entry
  /// @throw std::runtime_error if host already loaded into memory
  /// @throw std::runtime_error if address already loaded into memory
  void InsertAddress(
      const std::string& host,
      const kovri::core::IdentHash& address,
      SubscriptionType source);

  /// @brief Inserts address into address book from HTTP Proxy jump service
  /// @param address Const reference to human-readable address
  /// @param base64 Const reference to Base64 address
  // TODO(oneiric): remove after separating HTTP Proxy from Address Book
  void InsertAddressIntoStorage(
      const std::string& address,
      const std::string& base64);

  /// @brief Creates new address book filesystem storage instance
  /// @return Unique pointer to address book filesystem storage instance
  std::unique_ptr<AddressBookStorage> GetNewStorageInstance() {
    return std::make_unique<AddressBookStorage>();
  }

  /// @brief Wrapper function for subscriber download
  void DownloadSubscription();

  /// @brief Saves subscription to address book
  /// @details Saves to subscription file if file does not exist or we have fresh download
  /// @param stream Reference to file stream of hosts (subscription)
  /// @param file_name Optional filename to write to (used for multiple subscriptions)
  /// @return True if subscription was successfully loaded
  /// @warning Must validate before saving
  bool SaveSubscription(
      std::istream& stream,
      std::string file_name = "");

  /// @brief Validates subscription, saves hosts to file
  /// @param stream Stream to process
  /// @return Vector of paired hostname to identity
  const std::map<std::string, kovri::core::IdentityEx>
  ValidateSubscription(std::istream& stream);

  /// @brief Sets the download state as complete and resets timer as needed
  /// @details Resets update timer according to the state of completed download
  /// @param success True if successful download, false if not
  /// @notes If download was successful, reset the with regular update timeout.
  ///   If not, reset timer with more frequent update timeout.
  void HostsDownloadComplete(
      bool success);

  /// @brief Returns identity hash's .b32.i2p address
  /// @param ident Const reference to identity hash
  /// @return Identity hash's .b32.i2p address
  std::string GetB32AddressFromIdentHash(
      const kovri::core::IdentHash& ident) {
    return GetB32Address(ident);
  }

  /**
  // TODO(unassigned): currently unused
  std::string ToAddress(
      const kovri::core::IdentityEx& ident) {
    return ToAddress(ident.GetAddressIdentHash());
  }

  // TODO(unassigned): currently unused
  void InsertAddress(
      const kovri::core::IdentityEx& address);

  // TODO(unassigned): currently unused
  bool GetAddress(
      const std::string& address,
      kovri::core::IdentityEx& identity);
  **/

 private:
  /// @brief Loads list of publishers addresses
  /// @details If not loaded, loads from file (if available)
  ///   and instantiates an address book subscriber instance
  void LoadPublishers();

  /// @brief Implements subscriber update timer
  /// @param ecode Const reference to boost error code
  /// @details If publishers are available, download subscription (hosts.txt).
  ///   Otherwise, retry request for subscription (hosts.txt) until downloaded
  void SubscriberUpdateTimer(
      const boost::system::error_code& ecode);

  /// @brief Loads hosts file (subscription)
  /// @details If not on filesystem, downloads subscription from a publisher
  void LoadSubscriptionFromPublisher();

  /**
  // TODO(unassigned): currently unused
  /// @brief Creates new instance of storage for address book
  /// @return Unique pointer to interface for address book storage
  std::unique_ptr<AddressBookStorage> CreateStorage();
  **/

  /// @brief Stop subscription process
  /// @details Cancels update requests to publishers
  void StopSubscribing();

 private:
  /// @brief Exception handler
  core::Exception m_Exception;

  /// @var m_SharedLocalDestination
  /// @brief Shared pointer to client destination instance
  /// @notes Needed for fetching subscriptions in-net
  std::shared_ptr<ClientDestination> m_SharedLocalDestination;

  /// @var m_AddressBookMutex
  /// @brief Mutex for address book implementation when loading hosts from file
  std::mutex m_AddressBookMutex;

  /// @var m_Addresses
  /// @brief Map of human readable addresses to identity hashes and subscription source
  AddressMap m_Addresses;

  /// @var m_Storage
  /// @brief Unique pointer to address book storage implementation
  std::unique_ptr<AddressBookStorage> m_Storage;

  /// @var m_Subscribers
  /// @brief Vector of unique pointers to respective subscriber implementation
  std::vector<std::unique_ptr<AddressBookSubscriber>> m_Subscribers;

  /// @var m_SubscriberUpdateTimer
  /// @brief Unique pointer to Boost.Asio deadline_timer
  /// @details Handles all timer-related needs for subscription fetching
  std::unique_ptr<boost::asio::deadline_timer> m_SubscriberUpdateTimer;

  /// @var m_SubscriptionIsLoaded
  /// @brief Are hosts loaded into memory?
  std::atomic<bool> m_SubscriptionIsLoaded;

  /// @var m_PublishersLoaded
  /// @brief Subscriber has publisher loaded, ready for subscription download
  std::atomic<bool> m_PublishersLoaded;

  /// @var m_SubscriberIsDownloading
  /// @brief Are subscriptions in the process of being downloaded?
  std::atomic<bool> m_SubscriberIsDownloading;
};

/// @class AddressBookSubscriber
/// @brief Handles fetching of hosts subscription from publisher
class AddressBookSubscriber {
 public:
  /// @brief Initializes defaults for address book subscription implementation
  AddressBookSubscriber(
      AddressBook& book,
      const std::string& uri)
      : m_Book(book),
        m_HTTP(uri) {}

  /// @brief Instantiates thread that fetches in-net subscriptions
  void DownloadSubscription();

 private:
  /// @brief Implementation for downloading subscription (hosts.txt)
  /// @warning Must be run in separate thread
  void DownloadSubscriptionImpl();

  /// @var m_Book
  /// @brief Reference to address book implementation
  AddressBook& m_Book;

  /// @var m_HTTP
  /// @brief HTTP instance for subscribing to publisher
  HTTP m_HTTP;
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_ADDRESS_BOOK_IMPL_H_
