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

#ifndef SRC_CLIENT_ADDRESS_BOOK_H_
#define SRC_CLIENT_ADDRESS_BOOK_H_

#include <boost/asio.hpp>

#include <atomic>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "address_book_storage.h"
#include "identity.h"
#include "core/util/filesystem.h"
#include "destination.h"
#include "router_context.h"
#include "util/base64.h"
#include "util/log.h"

namespace i2p {
namespace client {

// TODO(unassigned): replace with Monero's b32 subscription service
const std::string SubscriptionDownloadAddress("https://downloads.getmonero.org/kovri/hosts.txt");

/// @enum SubscriptionTimeout
/// @brief Constants used for timeout intervals when fetching subscriptions
/// @notes Scoped to prevent namespace pollution (otherwise, purely stylistic)
enum struct SubscriptionTimeout : std::uint16_t {
  // Minutes
  InitialUpdate = 3,
  InitialRetry = 1,
  ContinuousUpdate = 720,  // 12 hours
  ContinuousRetry = 5,
  // Seconds
  Request = 60,
  Receive = 30,
};

class AddressBookSubscription;
/// @class AddressBook
/// @brief Address book implementation
class AddressBook {
 public:
  /// @brief Initializes defaults for address book implementation
  AddressBook()
      : m_Storage(nullptr),
        m_DefaultSubscription(nullptr),
        m_SubscriptionsUpdateTimer(nullptr),
        m_SharedLocalDestination(nullptr),
        m_IsLoaded(false),
        m_IsDownloading(false) {}

  /// @brief Stops address book implementation
  ~AddressBook() {
    Stop();
  }

  /// @brief Starts address book fetching and processing of subscriptions
  /// @param local_destination Shared pointer to destination instance used to
  ///   generate lease set and tunnel pool for downloading new subscriptions
  void Start(
      std::shared_ptr<ClientDestination> local_destination);

  /// @brief Stops and handles cleanup for address book
  /// @details Stops timers, finishes downloading if in progress, saves
  ///   addresses in memory to disk, cleans up memory
  void Stop();

  /// @brief Gets identity hash from .b32.i2p address
  /// @return True if identity hash was found
  /// @param address Reference to .b32.i2p address
  /// @param ident Reference to identity hash
  /// @notes If identity hash is found point @param ident to found hash
  bool GetIdentHash(
      const std::string& address,
      i2p::data::IdentHash& ident);

  /// @brief Finds address within loaded subscriptions
  /// @returns Unique pointer to identity hash of address
  /// @param address Reference to address
  std::unique_ptr<const i2p::data::IdentHash> FindAddress(
      const std::string& address);

  /// @brief Used for destination to fetch subscriptions
  /// @return Shared pointer to client destination
  std::shared_ptr<ClientDestination> GetSharedLocalDestination() const {
    return m_SharedLocalDestination;
  }

  /// @brief Inserts address into address book from HTTP Proxy jump service
  /// @param address Reference to human-readable address
  /// @param base64 Reference to Base64 address
  void InsertAddress(
      const std::string& address,
      const std::string& base64);

  /// @brief Loads hosts from stream into address book
  /// @param f Reference to file stream of hosts
  void LoadHostsFromStream(
      std::istream& f);

  /// @brief Sets the download state as complete and resets timer as needed
  /// @details Resets update timer according to the state of completed download
  /// @param success True if successful download, false if not
  /// @notes If download was successful, reset the with regular update timeout.
  ///   If not, reset timer with more frequent update timeout.
  void DownloadComplete(
      bool success);

  /// @brief Returns identity hash's .b32.i2p address
  /// @param ident Reference to identity hash
  /// @return Identity hash's .b32.i2p address
  std::string ToAddress(
      const i2p::data::IdentHash& ident) {
    return GetB32Address(ident);
  }

  /**
  // TODO(unassigned): currently unused
  std::string ToAddress(
      const i2p::data::IdentityEx& ident) {
    return ToAddress(ident.GetIdentHash());
  }

  // TODO(unassigned): currently unused
  void InsertAddress(
      const i2p::data::IdentityEx& address);

  // TODO(unassigned): currently unused
  bool GetAddress(
      const std::string& address,
      i2p::data::IdentityEx& identity);
  **/

 private:
  /// @brief Starts the subscription process
  /// @details Calls to load subscriptions, parent "poller" for fetching
  ///   in-net subscriptions
  void StartSubscriptions();

  /// @brief Loads subscriptions
  /// @details If not loaded, loads from file (if available)
  ///   and instantiates an address book subscription instance
  void LoadSubscriptions();

  /// @brief Implements subscription update timer
  /// @param ecode Reference to boost error code
  /// @details If subscriptions are available, load hosts into memory,
  ///   otherwise retry request for subscriptions until they are downloaded
  void HandleSubscriptionsUpdateTimer(
      const boost::system::error_code& ecode);

  /// @brief Loads hosts.txt
  /// @details If not on filesystem, downloads from subscription address(es)
  void LoadHosts();

  /// @brief Creates new instance of storage for address book
  /// @return Unique pointer to interface for address book storage
  std::unique_ptr<AddressBookStorage> CreateStorage();

  /// @brief Stop subscription process
  /// @details Cancels subscription updates
  void StopSubscriptions();

 private:
  /// @var m_AddressBookMutex
  /// @brief Mutex for address book implementation when loading hosts from file
  std::mutex m_AddressBookMutex;

  /// @var m_Addresses
  /// @brief Map of human readable addresses to identity hashes
  std::map<std::string, i2p::data::IdentHash> m_Addresses;

  /// @var m_Storage
  /// @brief Unique pointer to address book storage implementation
  std::unique_ptr<AddressBookStorage> m_Storage;

  /// @var m_Subscriptions
  /// @brief Vector of unique pointers to respective subscription implementation
  std::vector<std::unique_ptr<AddressBookSubscription>> m_Subscriptions;

  /// @var m_DefaultSubscription
  /// @brief Unique pointer to address book subscription implementation
  /// @notes Used if we don't have any subscription addresses yet
  std::unique_ptr<AddressBookSubscription> m_DefaultSubscription;

  /// @var m_SubscriptionsUpdateTimer
  /// @brief Unique pointer to Boost.Asio deadline_timer
  /// @details Handles all timer-related needs for subscription fetching
  std::unique_ptr<boost::asio::deadline_timer> m_SubscriptionsUpdateTimer;

  /// @var m_SharedLocalDestination
  /// @brief Shared pointer to client destination instance
  /// @notes Needed for fetching subscriptions in-net
  std::shared_ptr<ClientDestination> m_SharedLocalDestination;

  /// @var m_IsLoaded
  /// @brief Are hosts loaded into memory?
  std::atomic<bool> m_IsLoaded;

  /// @var m_IsDownloading
  /// @brief Are subscriptions in the process downloading?
  std::atomic<bool> m_IsDownloading;
};

/// @class AddressBookSubscription
/// @brief Handles fetching of hosts.txt subscriptions
class AddressBookSubscription {
 public:
  /// @brief Initializes defaults for address book subscription implementation
  AddressBookSubscription(
      AddressBook& book,
      const std::string& link)
      : m_Book(book),
        m_Link(link) {}

  /// @brief Instantiates thread that fetches in-net subscriptions
  void CheckSubscription();

 private:
  /// @warning Must be run in separate thread
  void Request();

 private:
  /// @var m_Book
  /// @brief Reference to address book implementation
  AddressBook& m_Book;
  // Used for HTTP request  // TODO(anonimal): remove when refactored with cpp-netlib
  std::string m_Link, m_Etag, m_LastModified;
};

}  // namespace client
}  // namespace i2p

#endif  // SRC_CLIENT_ADDRESS_BOOK_H_
