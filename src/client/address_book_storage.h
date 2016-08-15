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
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

#include "identity.h"
#include "core/util/filesystem.h"
#include "router_context.h"
#include "util/base64.h"
#include "util/log.h"

namespace i2p {
namespace client {

/// @var AddressBookDefaults
/// @brief Default string constants used throughout address book
const std::unordered_map<std::string, std::string> AddressBookDefaults = {
    { "Pathname", "addressbook" },
    { "SubscriptionFilename", "hosts.txt" },
    // TODO(anonimal): "addresses" is confusing and so is its real purpose
    // (currently only used to verify that addresses have indeed been saved)
    { "AddressesFilename", "addresses.csv" },
    { "PublisherFilename", "publishers.txt" },
    // TODO(unassigned): replace with Monero's b32 publisher service
    { "PublisherURI", "https://downloads.getmonero.org/kovri/hosts.txt" },
};

/// @class AddressBookStorage
/// @brief Interface for address book storage
class AddressBookStorage {
 public:
  virtual ~AddressBookStorage() {}

  virtual bool GetAddress(
      const i2p::data::IdentHash& ident,
      i2p::data::IdentityEx& address) const = 0;

  virtual void AddAddress(
      const i2p::data::IdentityEx& address) = 0;

  /**
  // TODO(unassigned): currently unused
  virtual void RemoveAddress(
      const i2p::data::IdentHash& ident) = 0;
  **/

  virtual std::size_t Load(
      std::map<std::string, i2p::data::IdentHash>& addresses) = 0;

  virtual std::size_t Save(
      const std::map<std::string, i2p::data::IdentHash>& addresses) = 0;
};

/// @class AddressBookFilesystemStorage
/// @brief All filesystem-related address book member functions
class AddressBookFilesystemStorage : public AddressBookStorage {
 public:
  /// @details Gets/Sets address book path/directory
  /// @notes Creates directory if not available
  AddressBookFilesystemStorage();

  /// @brief Gets b32 identity from storage and puts into identity buffer
  /// @return True if b32 identity is in filesystem and valid
  /// @param ident Const reference to identity hash from filesystem
  /// @param address Reference to identity address buffer
  bool GetAddress(
      const i2p::data::IdentHash& ident,
      i2p::data::IdentityEx& address) const;

  /// @brief Adds identity to address book storage
  /// @param address Const reference to identity address buffer
  void AddAddress(
      const i2p::data::IdentityEx& address);

  /**
  // TODO(unassigned): currently unused
  /// @brief Removes .b32 address filename from filesystem
  /// @param ident Reference to identity hash to be removed
  void RemoveAddress(
      const i2p::data::IdentHash& ident);
  **/

  /// @brief Loads subscriptions from file into memory
  /// @return Number of subscriptions loaded
  /// @param addresses Reference to map of human-readable addresses to hashes
  std::size_t Load(
      std::map<std::string, i2p::data::IdentHash>& addresses);

  /// @brief Saves subscriptions to file in CSV format // TODO(anonimal): why CSV?
  /// @return Number of subscriptions saved
  /// @param addresses Const reference to map of human-readable address to b32 hashes of address
  std::size_t Save(
      const std::map<std::string, i2p::data::IdentHash>& addresses);

 private:
  /// @brief Gets addresses filename (file list of saved addresses)
  /// @return Const reference to addresses filename
  const std::string& GetAddressesFilename() {
    return (GetAddressBookPath() / AddressBookDefaults.at("AddressesFilename")).string();
  }

  /// @brief Gets data path and appends address book's path
  /// @return Boost.Filesystem path of address book path
  boost::filesystem::path GetAddressBookPath() const {
    return i2p::context.GetDataPath() / AddressBookDefaults.at("Pathname");
  }
};

}  // namespace client
}  // namespace i2p

#endif  // SRC_CLIENT_ADDRESSBOOK_STORAGE_H_
