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

#include "client/address_book/storage.h"

#include <fstream>

namespace kovri {
namespace client {

AddressBookStorage::AddressBookStorage() {
  kovri::core::EnsurePath(GetAddressesPath());
}

bool AddressBookStorage::GetAddress(
    const kovri::core::IdentHash& ident,
    kovri::core::IdentityEx& address) const {
  auto filename = GetAddressesPath() / (ident.ToBase32() + ".b32");
  std::ifstream file(filename.string(), std::ifstream::binary);
  if (!file)
    return false;
  file.seekg(0, std::ios::end);
  const std::size_t len = file.tellg();
  if (len < kovri::core::DEFAULT_IDENTITY_SIZE) {
    LOG(error)
      << "AddressBookStorage: file " << filename << " is too short. " << len;
    return false;
  }
  file.seekg(0, std::ios::beg);
  auto buf = std::make_unique<std::uint8_t[]>(len);
  file.read(reinterpret_cast<char *>(buf.get()), len);
  // For sanity, the validity of identity length is incumbent upon the parent caller.
  // For now, we only care about returning success for an open/available file
  // TODO(unassigned): triple check that this is the case
  address.FromBuffer(buf.get(), len);
  return true;
}

void AddressBookStorage::AddAddress(const kovri::core::IdentityEx& address)
{
  auto filename =
      GetAddressesPath() / (address.GetIdentHash().ToBase32() + ".b32");
  kovri::core::OutputFileStream file(filename.string(), std::ofstream::binary);
  if (!file.Good())
    throw std::runtime_error("failed to open file for address writing");
  const std::size_t len = address.GetFullLen();
  std::vector<std::uint8_t> buf(len);
  address.ToBuffer(buf.data(), buf.size());
  if (!file.Write(buf.data(), buf.size()))
    throw std::runtime_error("failed to write address file");
}

/**
// TODO(unassigned): currently unused
void AddressBookStorage::RemoveAddress(
    const kovri::core::IdentHash& ident) {
  auto filename = GetPath() / (ident.ToBase32() + ".b32");
  if (boost::filesystem::exists(filename))
    boost::filesystem::remove(filename);
}
**/

std::size_t AddressBookStorage::Load(AddressMap& addresses)
{
  std::size_t num = 0;
  // TODO(oneiric): generalize to multiple subscription files see #337
  auto filename = core::GetPath(core::Path::AddressBook) / GetDefaultAddressesFilename();
  std::ifstream file(filename.string());
  if (!file) {
    LOG(warning) << "AddressBookStorage: " << filename << " not found";
  } else {
    addresses.clear();
    std::string host;
    while (std::getline(file, host)) {
      // TODO(anonimal): how much more hardening do we want?
      if (!host.length())
        continue;  // skip empty line
      // TODO(anonimal): use new CSV utility after it's expanded?
      std::size_t pos = host.find(',');
      if (pos != std::string::npos) {
        std::string name = host.substr(0, pos++);
        std::string addr = host.substr(pos);
        kovri::core::IdentHash ident;
        if (!addr.empty())
          {
            ident.FromBase32(addr);
            addresses[name] = std::make_pair(ident, SubscriptionType::Default);
            num++;
          }
      }
    }
    LOG(debug) << "AddressBookStorage: " << num << " addresses loaded";
  }
  return num;
}

std::size_t AddressBookStorage::Save(const AddressMap& addresses)
{
  std::size_t num = 0;
  // TODO(oneiric): generalize to multiple subscription files see #337
  auto filename = core::GetPath(core::Path::AddressBook)/ GetDefaultAddressesFilename();
  std::ofstream file(filename.string(), std::ofstream::out);
  if (!file) {
    LOG(error) << "AddressBookStorage: can't open file " << filename;
  } else {
    for (auto const& it : addresses) {
      if (std::get<SubscriptionType>(it.second) == SubscriptionType::Default)
        {
          file << it.first << ","
               << std::get<kovri::core::IdentHash>(it.second).ToBase32()
               << std::endl;
          num++;
        }
    }
    LOG(info) << "AddressBookStorage: " << num << " addresses saved";
  }
  return num;
}

}  // namespace client
}  // namespace kovri
