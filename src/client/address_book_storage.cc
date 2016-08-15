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

#include "address_book_storage.h"

#include <boost/filesystem.hpp>

#include <fstream>
#include <map>
#include <memory>
#include <string>

#include "identity.h"
#include "util/log.h"

namespace i2p {
namespace client {

AddressBookFilesystemStorage::AddressBookFilesystemStorage() {
  auto path = GetAddressBookPath();
  if (!boost::filesystem::exists(path)) {
    if (!boost::filesystem::create_directory(path))
      LogPrint(eLogError,
          "AddressBookFilesystemStorage: failed to create addressbook directory");
  }
}

bool AddressBookFilesystemStorage::GetAddress(
    const i2p::data::IdentHash& ident,
    i2p::data::IdentityEx& address) const {
  auto filename = GetAddressBookPath() / (ident.ToBase32() + ".b32");
  std::ifstream file(filename.string(), std::ifstream::binary);
  if (file.is_open()) {
    file.seekg(0, std::ios::end);
    std::size_t len = file.tellg();
    if (len < i2p::data::DEFAULT_IDENTITY_SIZE) {
      LogPrint(eLogError,
          "AddressBookFilesystemStorage: file ", filename, " is too short. ", len);
      return false;
    }
    file.seekg(0, std::ios::beg);
    auto buf = std::make_unique<std::uint8_t[]>(len);
    file.read(reinterpret_cast<char *>(buf.get()), len);
    address.FromBuffer(buf.get(), len);  // TODO(anonimal): test return for sanity
    return true;
  } else {
    return false;
  }
}

void AddressBookFilesystemStorage::AddAddress(
    const i2p::data::IdentityEx& address) {
  auto filename = GetAddressBookPath() / (address.GetIdentHash().ToBase32() + ".b32");
  std::ofstream file(filename.string(), std::ofstream::binary | std::ofstream::out);
  if (file.is_open()) {
    std::size_t len = address.GetFullLen();
    auto buf = std::make_unique<std::uint8_t[]>(len);
    address.ToBuffer(buf.get(), len); // TODO(anonimal): test return for sanity
    file.write(reinterpret_cast<char *>(buf.get()), len);
  } else {
    LogPrint(eLogError,
        "AddressBookFilesystemStorage: can't open file ", filename);
  }
}

/**
// TODO(unassigned): currently unused
void AddressBookFilesystemStorage::RemoveAddress(
    const i2p::data::IdentHash& ident) {
  auto filename = GetPath() / (ident.ToBase32() + ".b32");
  if (boost::filesystem::exists(filename))
    boost::filesystem::remove(filename);
}
**/

std::size_t AddressBookFilesystemStorage::Load(
    std::map<std::string, i2p::data::IdentHash>& addresses) {
  std::size_t num = 0;
  auto filename = GetAddressesFilename();
  std::ifstream file(filename, std::ofstream::in);
  if (file.is_open()) {
    addresses.clear();
    while (!file.eof()) {
      std::string host;
      getline(file, host);
      if (!host.length())
        continue;  // skip empty line
      std::size_t pos = host.find(',');
      if (pos != std::string::npos) {
        std::string name = host.substr(0, pos++);
        std::string addr = host.substr(pos);
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

std::size_t AddressBookFilesystemStorage::Save(
    const std::map<std::string, i2p::data::IdentHash>& addresses) {
  std::size_t num = 0;
  auto filename = GetAddressesFilename();
  std::ofstream file(filename, std::ofstream::out);
  if (file.is_open()) {
    for (auto it : addresses) {
      file << it.first << "," << it.second.ToBase32() << std::endl;
      num++;
    }
    LogPrint(eLogInfo, "AddressBookFilesystemStorage: ", num, " addresses saved");
  } else {
    LogPrint(eLogError, "AddressBookFilesystemStorage: can't open file ", filename);
  }
  return num;
}

}  // namespace client
}  // namespace i2p
