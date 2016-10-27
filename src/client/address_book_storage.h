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
  /// @brief Pathname of address book within KOVRI_DATA_DIR
  /// @return Pathname for address book storage
  std::string GetDefaultPathname() const {
    return "addressbook";
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
  std::size_t Load(
      std::map<std::string, kovri::core::IdentHash>& addresses);

  /// @brief Saves subscriptions to file in CSV format to verify addresses loaded
  /// @return Number of addresses saved
  /// @param addresses Const reference to map of human-readable address to b32 hashes of address
  std::size_t Save(
      const std::map<std::string, kovri::core::IdentHash>& addresses);

 private:
  /// @brief Gets data path and appends address book's path
  /// @return Boost.Filesystem path of address book path
  boost::filesystem::path GetAddressBookPath() const {
    return kovri::context.GetDataPath() / GetDefaultPathname();
  }
};

}  // namespace client
}  // namespace kovri

#endif  // SRC_CLIENT_ADDRESSBOOK_STORAGE_H_
