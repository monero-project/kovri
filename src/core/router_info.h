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

#ifndef SRC_CORE_ROUTER_INFO_H_
#define SRC_CORE_ROUTER_INFO_H_

#include <boost/asio.hpp>

#include <inttypes.h>

#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "identity.h"
#include "profiling.h"

namespace i2p {
namespace data {

const char CAPS_FLAG_FLOODFILL = 'f';
const char CAPS_FLAG_HIDDEN = 'H';
const char CAPS_FLAG_REACHABLE = 'R';
const char CAPS_FLAG_UNREACHABLE = 'U';
const char CAPS_FLAG_LOW_BANDWIDTH1 = 'K';
const char CAPS_FLAG_LOW_BANDWIDTH2 = 'L';
const char CAPS_FLAG_HIGH_BANDWIDTH1 = 'M';
const char CAPS_FLAG_HIGH_BANDWIDTH2 = 'N';
const char CAPS_FLAG_HIGH_BANDWIDTH3 = 'O';
const char CAPS_FLAG_HIGH_BANDWIDTH4 = 'P';
const char CAPS_FLAG_UNLIMITED_BANDWIDTH = 'X';

const char CAPS_FLAG_SSU_TESTING = 'B';
const char CAPS_FLAG_SSU_INTRODUCER = 'C';

const int MAX_RI_BUFFER_SIZE = 2048;

class RouterInfo : public RoutingDestination {
 public:
  enum SupportedTranports {
    eNTCPV4 = 0x01,
    eNTCPV6 = 0x02,
    eSSUV4 = 0x04,
    eSSUV6 = 0x08
  };

  enum Caps {
    eFloodfill = 0x01,
    eUnlimitedBandwidth = 0x02,
    eHighBandwidth = 0x04,
    eReachable = 0x08,
    eSSUTesting = 0x10,
    eSSUIntroducer = 0x20,
    eHidden = 0x40,
    eUnreachable = 0x80
  };

  enum TransportStyle {
    eTransportUnknown = 0,
    eTransportNTCP,
    eTransportSSU
  };

  struct Introducer {
    boost::asio::ip::address host;
    int port;
    Tag<32> key;
    uint32_t tag;
  };

  struct Address {
    TransportStyle transport_style;
    boost::asio::ip::address host;
    std::string address_string;
    int port, mtu;
    uint64_t date;
    uint8_t cost;
    // SSU only
    Tag<32> key;  // intro key for SSU
    std::vector<Introducer> introducers;
    bool IsCompatible(
        const boost::asio::ip::address& other) const {
      return (host.is_v4() && other.is_v4()) ||
        (host.is_v6() && other.is_v6());
    }
  };

  RouterInfo();

  ~RouterInfo();

  RouterInfo(
      const std::string& full_path);

  RouterInfo(
      const RouterInfo&) = default;

  RouterInfo(
      const uint8_t* buf,
      int len);

  RouterInfo& operator=(const RouterInfo&) = default;

  const IdentityEx& GetRouterIdentity() const {
    return m_RouterIdentity;
  }

  void SetRouterIdentity(
      const IdentityEx& identity);

  std::string GetIdentHashBase64() const {
    return GetIdentHash().ToBase64();
  }

  std::string GetIdentHashAbbreviation() const {
    return GetIdentHash().ToBase64().substr(0, 4);
  }

  uint64_t GetTimestamp() const {
    return m_Timestamp;
  }

  std::vector<Address>& GetAddresses() {
    return m_Addresses;
  }

  const Address* GetNTCPAddress(
      bool v4only = true) const;

  const Address* GetSSUAddress(
      bool v4only = true) const;

  const Address* GetSSUV6Address() const;

  void AddNTCPAddress(
      const std::string& host,
      int port);

  void AddSSUAddress(
      const std::string& host,
      int port,
      const uint8_t* key,
      int mtu = 0);

  bool AddIntroducer(
      const Address* address,
      uint32_t tag);

  bool RemoveIntroducer(
      const boost::asio::ip::udp::endpoint& e);

  void SetProperty(  // called from RouterContext only
      const std::string& key,
      const std::string& value);

  void DeleteProperty(  // called from RouterContext only
      const std::string& key);

  void ClearProperties() {
    m_Properties.clear();
  }

  bool IsFloodfill() const;

  bool IsNTCP(
      bool v4only = true) const;

  bool IsSSU(
      bool v4only = true) const;

  bool IsV6() const;

  void EnableV6();

  void DisableV6();

  bool IsCompatible(
      const RouterInfo& other) const {
    return m_SupportedTransports & other.m_SupportedTransports;
  }

  bool UsesIntroducer() const;

  bool IsIntroducer() const {
    return m_Caps & eSSUIntroducer;
  }

  bool IsPeerTesting() const {
    return m_Caps & eSSUTesting;
  }

  bool IsHidden() const {
    return m_Caps & eHidden;
  }

  bool IsHighBandwidth() const {
    return m_Caps & RouterInfo::eHighBandwidth;
  }

  uint8_t GetCaps() const {
    return m_Caps;
  }

  void SetCaps(
      uint8_t caps);

  void SetCaps(
      const char* caps);

  void SetUnreachable(bool unreachable) {
    m_IsUnreachable = unreachable;
  }

  bool IsUnreachable() const {
    return m_IsUnreachable;
  }

  const uint8_t* GetBuffer() const {
    auto buf = m_Buffer.get();
    return buf;
  }

  const uint8_t* LoadBuffer();  // load if necessary

  int GetBufferLen() const {
    return m_BufferLen;
  }

  void CreateBuffer(
      const PrivateKeys& privateKeys);

  bool IsUpdated() const {
    return m_IsUpdated;
  }

  void SetUpdated(
      bool updated) {
    m_IsUpdated = updated;
  }

  void SaveToFile(
      const std::string& full_path);

  std::shared_ptr<RouterProfile> GetProfile() const;

  void SaveProfile() {
    if (m_Profile)
      m_Profile->Save();
  }

  void Update(
      const uint8_t* buf,
      int len);

  void DeleteBuffer() {
    m_Buffer.reset(nullptr);
  }

  // implements RoutingDestination
  const IdentHash& GetIdentHash() const {
    return m_RouterIdentity.GetIdentHash();
  }

  const uint8_t* GetEncryptionPublicKey() const {
    return m_RouterIdentity.GetStandardIdentity().public_key;
  }

  bool IsDestination() const {
    return false;
  }

 private:
  bool LoadFile();

  void ReadFromFile();

  void ReadFromStream(
      std::istream& s);

  void ReadFromBuffer(
      bool verify_signature);

  void WriteToStream(
      std::ostream& s);

  size_t ReadString(
      char* str,
      std::istream& s);

  void WriteString(
      const std::string& str,
      std::ostream& s);

  void ExtractCaps(
      const char* value);

  const Address* GetAddress(
      TransportStyle s,
      bool v4only,
      bool v6only = false) const;

  void UpdateCapsProperty();

 private:
  std::string m_FullPath;
  IdentityEx m_RouterIdentity;
  std::unique_ptr<std::uint8_t[]> m_Buffer;
  int m_BufferLen;
  uint64_t m_Timestamp;
  std::vector<Address> m_Addresses;
  std::map<std::string, std::string> m_Properties;
  bool m_IsUpdated, m_IsUnreachable;
  uint8_t m_SupportedTransports, m_Caps;
  mutable std::shared_ptr<RouterProfile> m_Profile;
};

}  // namespace data
}  // namespace i2p

#endif  // SRC_CORE_ROUTER_INFO_H_
