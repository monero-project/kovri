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

#include <inttypes.h>
#include <string.h>
#include <string>

#include <chrono>
#include <condition_variable>
#include <fstream>
#include <map>
#include <memory>

#include "destination.h"
#include "identity.h"
#include "net_db.h"
#include "crypto/rand.h"
#include "util/http.h"
#include "util/log.h"

namespace i2p {
namespace client {

class AddressBookFilesystemStorage : public AddressBookStorage {
 public:
  AddressBookFilesystemStorage();

  bool GetAddress(
      const i2p::data::IdentHash& ident,
      i2p::data::IdentityEx& address) const;

  void AddAddress(
      const i2p::data::IdentityEx& address);

  void RemoveAddress(
      const i2p::data::IdentHash& ident);

  int Load(
      std::map<std::string,
      i2p::data::IdentHash>& addresses);

  int Save(
      const std::map<std::string, i2p::data::IdentHash>& addresses);

 private:
  boost::filesystem::path GetPath() const {
    return i2p::context.GetDataPath() / "addressbook";
  }
};

AddressBookFilesystemStorage::AddressBookFilesystemStorage() {
  auto path = GetPath();
  if (!boost::filesystem::exists(path)) {
    // Create directory is necessary
    if (!boost::filesystem::create_directory(path))
      LogPrint(eLogError,
          "AddressBookFilesystemStorage: failed to create addressbook directory");
  }
}

bool AddressBookFilesystemStorage::GetAddress(
    const i2p::data::IdentHash& ident,
    i2p::data::IdentityEx& address) const {
  auto filename = GetPath() / (ident.ToBase32() + ".b32");
  std::ifstream f(filename.string(), std::ifstream::binary);
  if (f.is_open()) {
    f.seekg(0, std::ios::end);
    size_t len = f.tellg();
    if (len < i2p::data::DEFAULT_IDENTITY_SIZE) {
      LogPrint(eLogError,
          "AddressBookFilesystemStorage: file ", filename, " is too short. ", len);
      return false;
    }
    f.seekg(0, std::ios::beg);
    auto buf = std::make_unique<std::uint8_t[]>(len);
    f.read(reinterpret_cast<char *>(buf.get()), len);
    address.FromBuffer(buf.get(), len);
    return true;
  } else {
    return false;
  }
}

void AddressBookFilesystemStorage::AddAddress(
    const i2p::data::IdentityEx& address) {
  auto filename = GetPath() / (address.GetIdentHash().ToBase32() + ".b32");
  std::ofstream f(filename.string(), std::ofstream::binary | std::ofstream::out);
  if (f.is_open()) {
    size_t len = address.GetFullLen();
    auto buf = std::make_unique<std::uint8_t[]>(len);
    address.ToBuffer(buf.get(), len);
    f.write(reinterpret_cast<char *>(buf.get()), len);
  } else {
    LogPrint(eLogError,
        "AddressBookFilesystemStorage: can't open file ", filename);
  }
}

void AddressBookFilesystemStorage::RemoveAddress(
    const i2p::data::IdentHash& ident) {
  auto filename = GetPath() / (ident.ToBase32() + ".b32");
  if (boost::filesystem::exists(filename))
    boost::filesystem::remove(filename);
}

int AddressBookFilesystemStorage::Load(
    std::map<std::string, i2p::data::IdentHash>& addresses) {
  int num = 0;
  auto filename = GetPath() / "addresses.csv";
  std::ifstream f(filename.string(), std::ofstream::in);  // in text mode
  if (f.is_open()) {
    addresses.clear();
    while (!f.eof()) {
      std::string s;
      getline(f, s);
      if (!s.length())
        continue;  // skip empty line
      size_t pos = s.find(',');
      if (pos != std::string::npos) {
        std::string name = s.substr(0, pos++);
        std::string addr = s.substr(pos);
        i2p::data::IdentHash ident;
        ident.FromBase32(addr);
        addresses[name] = ident;
        num++;
      }
    }
    LogPrint(eLogInfo,
        "AddressBookFilesystemStorage: ", num, " addresses loaded");
  } else {
    LogPrint(eLogWarn,
        "AddressBookFilesystemStorage: ", filename, " not found");
  }
  return num;
}

int AddressBookFilesystemStorage::Save(
    const std::map<std::string, i2p::data::IdentHash>& addresses) {
  int num = 0;
  auto filename = GetPath() / "addresses.csv";
  std::ofstream f(filename.string(), std::ofstream::out);  // in text mode
  if (f.is_open()) {
    for (auto it : addresses) {
      f << it.first << "," << it.second.ToBase32() << std::endl;
      num++;
    }
    LogPrint(eLogInfo, "AddressBookFilesystemStorage: ", num, " addresses saved");
  } else {
    LogPrint(eLogError, "AddressBookFilesystemStorage: can't open file ", filename);
  }
  return num;
}

//---------------------------------------------------------------------

AddressBook::AddressBook()
    : m_Storage(nullptr),
      m_IsLoaded(false),
      m_IsDownloading(false),
      m_DefaultSubscription(nullptr),
      m_SubscriptionsUpdateTimer(nullptr),
      m_SharedLocalDestination(nullptr) {}

AddressBook::~AddressBook() {
  Stop();
}

void AddressBook::Start(
    std::shared_ptr<ClientDestination> local_destination) {
  m_SharedLocalDestination = local_destination;
  StartSubscriptions();
}

void AddressBook::Stop() {
  StopSubscriptions();
  if (m_SubscriptionsUpdateTimer) {
    m_SubscriptionsUpdateTimer.reset(nullptr);
  }
  if (m_IsDownloading) {
    LogPrint(eLogInfo,
        "AddressBook: subscription is downloading, waiting for termination");
    for (int i = 0; i < 30; i++) {
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

std::unique_ptr<AddressBookStorage> AddressBook::CreateStorage() {
  return std::make_unique<AddressBookFilesystemStorage>();
}

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
  // TODO(unassigned): we shouldn't *assume* it's base64!
  i2p::data::IdentityEx dest;
  if (!dest.FromBase64(address))
    return false;
  ident = dest.GetIdentHash();
  return true;
}

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

std::shared_ptr<ClientDestination> AddressBook::GetSharedLocalDestination() const {
  return m_SharedLocalDestination;
}

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

void AddressBook::InsertAddress(
    const i2p::data::IdentityEx& address) {
  if (!m_Storage)
    m_Storage = CreateStorage();
  m_Storage->AddAddress(address);
}

bool AddressBook::GetAddress(
    const std::string& address,
    i2p::data::IdentityEx& identity) {
  if (!m_Storage)
    m_Storage = CreateStorage();
  i2p::data::IdentHash ident;
  if (!GetIdentHash(address, ident)) return false;
  return m_Storage->GetAddress(ident, identity);
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
    LoadHostsFromStream(f);
    m_IsLoaded = true;
  } else {
    // if not found download it from http://i2p-projekt.i2p/hosts.txt
    LogPrint(eLogInfo,
        "AddressBook: hosts.txt not found, ",
        "attempting to download a default subscription");
    if (!m_IsDownloading) {
      m_IsDownloading = true;
      if (!m_DefaultSubscription)
        m_DefaultSubscription =
          std::make_unique<AddressBookSubscription>(*this, DEFAULT_SUBSCRIPTION_ADDRESS);
      m_DefaultSubscription->CheckSubscription();
    }
  }
}

void AddressBook::LoadHostsFromStream(
    std::istream& f) {
  std::unique_lock<std::mutex> l(m_AddressBookMutex);
  int num_addresses = 0;
  std::string s;
  while (!f.eof()) {
    getline(f, s);
    if (!s.length())
      continue;  // skip empty line
    size_t pos = s.find('=');
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

void AddressBook::DownloadComplete(
    bool success) {
  m_IsDownloading = false;
  if (m_SubscriptionsUpdateTimer) {
    m_SubscriptionsUpdateTimer->expires_from_now(
        boost::posix_time::minutes(
            success ?
            CONTINIOUS_SUBSCRIPTION_UPDATE_TIMEOUT :
            CONTINIOUS_SUBSCRIPTION_RETRY_TIMEOUT));
    m_SubscriptionsUpdateTimer->async_wait(
        std::bind(
            &AddressBook::HandleSubscriptionsUpdateTimer,
            this,
            std::placeholders::_1));
  }
}

void AddressBook::StartSubscriptions() {
  LoadSubscriptions();
  if (!m_Subscriptions.size()) return;

  if (m_SharedLocalDestination) {
    m_SubscriptionsUpdateTimer =
      std::make_unique<boost::asio::deadline_timer>(
          m_SharedLocalDestination->GetService());
    m_SubscriptionsUpdateTimer->expires_from_now(
        boost::posix_time::minutes(
            INITIAL_SUBSCRIPTION_UPDATE_TIMEOUT));
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

void AddressBook::StopSubscriptions() {
  if (m_SubscriptionsUpdateTimer)
    m_SubscriptionsUpdateTimer->cancel();
}

void AddressBook::HandleSubscriptionsUpdateTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    if (!m_SharedLocalDestination)
      return;  // TODO(unassigned): error handling
    if (m_IsLoaded && !m_IsDownloading &&
        m_SharedLocalDestination->IsReady()) {
      // pick random subscription
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
              INITIAL_SUBSCRIPTION_RETRY_TIMEOUT));
      m_SubscriptionsUpdateTimer->async_wait(
          std::bind(
              &AddressBook::HandleSubscriptionsUpdateTimer,
              this,
              std::placeholders::_1));
    }
  }
}

AddressBookSubscription::AddressBookSubscription(
    AddressBook& book,
    const std::string& link)
    : m_Book(book),
      m_Link(link) {}

void AddressBookSubscription::CheckSubscription() {
  std::thread load_hosts(&AddressBookSubscription::Request, this);
  load_hosts.detach();  // TODO(unassigned): use join
}

// TODO(anonimal): see HTTP for notes on cpp-netlib refactor
// tl;dr, all HTTP-related code + stream handling should be refactored
void AddressBookSubscription::Request() {
  // must be run in separate thread
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
                  SUBSCRIPTION_REQUEST_TIMEOUT)) == std::cv_status::timeout)
        LogPrint(eLogError,
            "AddressBookSubscription: ",
            "subscription LeseseSet request timeout expired");
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
      stream->Send((uint8_t *)request.str().c_str(),
          request.str().length());
      uint8_t buf[4096];
      bool end = false;
      while (!end) {
        stream->AsyncReceive(
            boost::asio::buffer(
              buf,
              4096),
            [&](const boost::system::error_code& ecode,
              std::size_t bytes_transferred) {
                if (bytes_transferred)
                  response.write(
                      reinterpret_cast<char *>(buf),
                      bytes_transferred);
                if (ecode == boost::asio::error::timed_out || !stream->IsOpen())
                  end = true;
                new_data_received.notify_all();
              },
            30);  // wait for 30 seconds
        std::unique_lock<std::mutex> l(new_data_received_mutex);
        if (new_data_received.wait_for(
                l,
                std::chrono::seconds(
                    SUBSCRIPTION_REQUEST_TIMEOUT)) == std::cv_status::timeout)
          LogPrint(eLogError,
              "AddressBookSubscription: subscription timeout expired");
      }
      // process remaining buffer
      while (size_t len = stream->ReadSome(buf, 4096))
        response.write(reinterpret_cast<char *>(buf), len);
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

}  // namespace client
}  // namespace i2p

