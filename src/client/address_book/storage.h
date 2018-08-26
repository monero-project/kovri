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

#ifndef SRC_CLIENT_ADDRESS_BOOK_STORAGE_H_
#define SRC_CLIENT_ADDRESS_BOOK_STORAGE_H_

#include <boost/filesystem.hpp>

#include <cstdint>
#include <iosfwd>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/router/identity.h"
#include "core/router/context.h"

#include "core/util/filesystem.h"
#include "core/util/log.h"

namespace kovri {
namespace client {

/// @class AddressBookDefaults
/// @brief Default string constants used throughout address book
struct AddressBookDefaults {
  /// @enum Subscription
  /// @brief Subscription type for where to load/save subscription addresses
  /// @notes Scoped to prevent namespace pollution (otherwise, purely stylistic)
  enum struct SubscriptionType
  {
    Default,
    User,
    Private,
  };

  /// @alias AddressMap
  /// @brief Maps human-readable hostname to an identity hash and subscription type
  /// @details Intended for user-convenience, readability, mapping to/from database entries, and potential subscription feed support
  /// @notes For subscription feed details, see I2P proposal 112
  using AddressMap =
      std::map<std::string, std::pair<core::IdentHash, SubscriptionType> >;

  /// @enum AddressBookSize
  enum AddressBookSize : std::uint16_t {
    /// @brief Line in subscription file
    /// @Note Arbitrary amount, should never need to exceed this amount
    //SubscriptionLine = 782,  // TODO(unassigned): review and confirm: 253 for domain name + 1 ("=") + maximum b64 size of identity (528?)
    SubscriptionLine = 800,  // Until the above is confirmed, give a little wiggle room
  };

  /// @enum SubscriberTimeout
  /// @brief Constants used for timeout intervals when fetching subscriptions
  /// @notes Scoped to prevent namespace pollution (otherwise, purely stylistic)
  enum SubscriberTimeout : std::uint16_t {
    // Minutes
    InitialUpdate = 3,
    InitialRetry = 1,
    ContinuousUpdate = 720,  // 12 hours
    ContinuousRetry = 5,
  };

  /// @brief Gets default publishers filename
  /// @return Default publishers filename
  /// @notes A publishers file holds a list of publisher addresses
  ///   of whom publish 'subscriptions' that contain a list of hosts to .b32.i2p
  std::string GetDefaultPublishersFilename() const {
    return "publishers.txt";
  }

  /// @brief Gets default publisher URI
  /// @return Default publishers URI
  /// @notes A default publisher is used if no publishers file is available
  std::string GetDefaultPublisherURI() const {
    // TODO(unassigned): replace with Monero's b32 publisher service
    return "https://downloads.getmonero.org/kovri/hosts.txt";
    // Below is only used for testing in-net download (this is *not* our default subscription)
    //return "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt";
  }

  /// @brief Gets default subscription filename
  /// @return Default subscription filename
  /// @notes Filename used by publishers when they publish a 'subscription'
  std::string GetDefaultSubscriptionFilename() const {
    return "hosts.txt";
  }

  std::string GetSubscriptionFilename(const SubscriptionType sub) const {
    switch(sub)
    {
      case SubscriptionType::Default:
        return "hosts.txt";
      case SubscriptionType::User:
        return "user_hosts.txt";
      case SubscriptionType::Private:
        return "private_hosts.txt";
      default:
        LOG(error) << __func__ << ": unknown subscription type";
        return "";
    }
  }

  /// @brief Gets addresses file (file list of saved addresses)
  /// @return Default addresses filename
  /// @notes Currently only used to verify that addresses have indeed been saved
  std::string GetDefaultAddressesFilename() const {
    return "addresses.csv";
  }
};

/// @class AddressBookStorage
/// @brief All filesystem-related members
class AddressBookStorage : public AddressBookDefaults {
 public:
  /// @details Gets/Sets address book path/directory
  /// @notes Creates directory if not available
  AddressBookStorage();

  /// @brief Gets b32 identity from storage and puts into identity buffer
  /// @return True if b32 identity is in filesystem and valid
  /// @param ident Const reference to identity hash from filesystem
  /// @param address Reference to identity address buffer
  bool GetAddress(
      const kovri::core::IdentHash& ident,
      kovri::core::IdentityEx& address) const;

  /// @brief Adds identity to address book storage
  /// @param address Const reference to identity address buffer
  void AddAddress(
      const kovri::core::IdentityEx& address);

  /**
  // TODO(unassigned): currently unused
  /// @brief Removes .b32 address filename from filesystem
  /// @param ident Reference to identity hash to be removed
  void RemoveAddress(
      const kovri::core::IdentHash& ident);
  **/

  /// @brief Loads subscriptions from file into memory
  /// @return Number of subscriptions loaded
  /// @param addresses Reference to map of human-readable addresses to hashes
  std::size_t Load(AddressMap& addresses);

  /// @brief Saves subscriptions to file in CSV format to verify addresses loaded
  /// @return Number of addresses saved
  /// @param addresses Const reference to map of human-readable address to b32 hashes of address
  std::size_t Save(const AddressMap& addresses);

  /// @brief Saves subscriptions to file in hosts.txt format
  /// @return Number of addresses saved
  /// @param addresses Const reference to map of human-readable address to full router identity
  std::size_t SaveSubscription(
      const std::map<std::string, kovri::core::IdentityEx>& addresses,
      SubscriptionType sub);

 private:
  /// @return Address book path with appended addresses location
  boost::filesystem::path GetAddressesPath() const {
    return core::GetPath(core::Path::AddressBook) / "addresses";
  }
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_ADDRESS_BOOK_STORAGE_H_
