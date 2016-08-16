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

#include <string.h>

#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "identity.h"
#include "core/util/filesystem.h"
#include "util/base64.h"
#include "util/log.h"

namespace i2p {
namespace client {

const char DEFAULT_SUBSCRIPTION_ADDRESS[] =
  "http://udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p/hosts.txt";
const int INITIAL_SUBSCRIPTION_UPDATE_TIMEOUT = 3;  // in minutes
const int INITIAL_SUBSCRIPTION_RETRY_TIMEOUT = 1;  // in minutes
const int CONTINIOUS_SUBSCRIPTION_UPDATE_TIMEOUT = 720;  // in minutes (12 hours)
const int CONTINIOUS_SUBSCRIPTION_RETRY_TIMEOUT = 5;  // in minutes
const int SUBSCRIPTION_REQUEST_TIMEOUT = 60;  // in second

inline std::string GetB32Address(
    const i2p::data::IdentHash& ident) {
  return ident.ToBase32().append(".b32.i2p");
}

// interface for storage
class AddressBookStorage {
 public:
  virtual ~AddressBookStorage() {}

  virtual bool GetAddress(
      const i2p::data::IdentHash& ident,
      i2p::data::IdentityEx& address) const = 0;

  virtual void AddAddress(
      const i2p::data::IdentityEx& address) = 0;

  virtual void RemoveAddress(
      const i2p::data::IdentHash& ident) = 0;

  virtual int Load(
      std::map<std::string,
      i2p::data::IdentHash>& addresses) = 0;

  virtual int Save(
      const std::map<std::string, i2p::data::IdentHash>& addresses) = 0;
};

class ClientDestination;
class AddressBookSubscription;
class AddressBook {
 public:
  AddressBook();
  ~AddressBook();

  void Start(
      std::shared_ptr<ClientDestination> local_destination);

  void Stop();

  bool GetIdentHash(
      const std::string& address,
      i2p::data::IdentHash& ident);

  bool GetAddress(
      const std::string& address,
      i2p::data::IdentityEx& identity);

  std::unique_ptr<const i2p::data::IdentHash> FindAddress(
      const std::string& address);

  std::shared_ptr<ClientDestination> GetSharedLocalDestination() const;

  // for jump service
  void InsertAddress(
      const std::string& address,
      const std::string& base64);

  void InsertAddress(
      const i2p::data::IdentityEx& address);

  void LoadHostsFromStream(
      std::istream& f);

  void DownloadComplete(
      bool success);

  // This method returns the ".b32.i2p" address
  std::string ToAddress(
      const i2p::data::IdentHash& ident) {
    return GetB32Address(ident);
  }

  std::string ToAddress(
      const i2p::data::IdentityEx& ident) {
    return ToAddress(ident.GetIdentHash());
  }

 private:
  void StartSubscriptions();
  void StopSubscriptions();

  std::unique_ptr<AddressBookStorage> CreateStorage();
  void LoadHosts();
  void LoadSubscriptions();

  void HandleSubscriptionsUpdateTimer(
      const boost::system::error_code& ecode);

 private:
  std::mutex m_AddressBookMutex;
  std::map<std::string, i2p::data::IdentHash>  m_Addresses;
  std::unique_ptr<AddressBookStorage> m_Storage;
  volatile bool m_IsLoaded, m_IsDownloading;
  std::vector<std::unique_ptr<AddressBookSubscription>> m_Subscriptions;

  // in case if we don't know any addresses yet
  std::unique_ptr<AddressBookSubscription> m_DefaultSubscription;

  std::unique_ptr<boost::asio::deadline_timer> m_SubscriptionsUpdateTimer;
  std::shared_ptr<ClientDestination> m_SharedLocalDestination;
};

class AddressBookSubscription {
 public:
  AddressBookSubscription(
      AddressBook& book,
      const std::string& link);

  void CheckSubscription();

 private:
  void Request();

 private:
  AddressBook& m_Book;
  std::string m_Link, m_Etag, m_LastModified;
};

}  // namespace client
}  // namespace i2p

#endif  // SRC_CLIENT_ADDRESS_BOOK_H_
