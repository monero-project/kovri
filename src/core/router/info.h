/**                                                                                           //
 * Copyright (c) 2013-2017, The Kovri I2P Router Project                                      //
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

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/router/identity.h"
#include "core/router/profiling.h"

#include "core/util/filesystem.h"

namespace kovri {
namespace core {

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
  /// @enum Transport
  /// @brief Transport type(s) within RI
  enum Transport : std::uint8_t
  {
    NTCP,
    SSU,
    Unknown,
  };

  /// @enum SupportedTransport
  /// @brief Transport and IP version that *our* router will use for peer
  enum SupportedTransport : std::uint8_t
  {
    NTCPv4 = 0x01,
    NTCPv6 = 0x02,
    SSUv4 = 0x04,
    SSUv6 = 0x08,
  };

  /// @enum Caps
  /// @brief RI capabilities
  enum Caps : std::uint8_t
  {
    Floodfill = 0x01,
    UnlimitedBandwidth = 0x02,
    HighBandwidth = 0x04,
    Reachable = 0x08,
    SSUTesting = 0x10,
    SSUIntroducer = 0x20,
    Hidden = 0x40,
    Unreachable = 0x80,
  };

  struct Introducer {
    boost::asio::ip::address host;
    std::uint16_t port{};
    Tag<32> key;
    std::uint32_t tag{};

    /// @brief Human readable description of this struct
    /// @param prefix for tabulations
    /// @returns human readable string
    std::string GetDescription(const std::string& tabs = std::string()) const;
  };

  struct Address {
    Transport transport;
    boost::asio::ip::address host;
    std::string address;
    std::uint16_t port{}, mtu{};
    std::uint64_t date{};
    std::uint8_t cost{};
    // SSU only
    Tag<32> key;  // intro key for SSU
    std::vector<Introducer> introducers;
    bool IsCompatible(
        const boost::asio::ip::address& other) const {
      return (host.is_v4() && other.is_v4()) ||
        (host.is_v6() && other.is_v6());
    }

    /// @brief Human readable description of this struct
    /// @param prefix for tabulations
    /// @returns human readable string
    std::string GetDescription(const std::string& tabs = std::string()) const;
  };

  /// @enum Trait
  /// @brief RI traits
  enum struct Trait : std::uint8_t
  {
    NTCP,
    SSU,
    Host,
    Port,
    MTU,
    Key,
    Caps,
    // Introducer
    IntroHost,
    IntroPort,
    IntroTag,
    IntroKey,
    // Demarcation
    Delimiter,
    Terminator,
    // Unknown trait
    Unknown,
  };

  /// @return String value of given enumerated RI trait
  /// @param trait key used for RI trait string value
  const std::string GetTrait(Trait trait) const noexcept
  {
    switch (trait)
      {
        case Trait::NTCP:
          return "NTCP";
        case Trait::SSU:
          return "SSU";
        case Trait::Host:
          return "host";
        case Trait::Port:
          return "port";
        case Trait::MTU:
          return "mtu";
        case Trait::Key:
          return "key";
        case Trait::Caps:
          return "caps";
        // Introducer
        case Trait::IntroHost:
          return "ihost";
        case Trait::IntroPort:
          return "iport";
        case Trait::IntroTag:
          return "itag";
        case Trait::IntroKey:
          return "ikey";
        // Demarcation
        case Trait::Delimiter:
          return "=";
        case Trait::Terminator:
          return ";";
        case Trait::Unknown:  // TODO(anonimal): review
        default:
          return "";
      }
  }

  /// @return Enumerated key trait
  /// @param value String value of potential trait given
  Trait GetTrait(const std::string& value) const noexcept
  {
    if (value == GetTrait(Trait::NTCP))
      return Trait::NTCP;
    else if (value == GetTrait(Trait::SSU))
      return Trait::SSU;
    else if (value == GetTrait(Trait::Host))
      return Trait::Host;
    else if (value == GetTrait(Trait::Port))
      return Trait::Port;
    else if (value == GetTrait(Trait::MTU))
      return Trait::MTU;
    else if (value == GetTrait(Trait::Key))
      return Trait::Key;
    else if (value == GetTrait(Trait::Caps))
      return Trait::Caps;
    // Introducer
    else if (value == GetTrait(Trait::IntroHost))
      return Trait::IntroHost;
    else if (value == GetTrait(Trait::IntroPort))
      return Trait::IntroPort;
    else if (value == GetTrait(Trait::IntroTag))
      return Trait::IntroTag;
    else if (value == GetTrait(Trait::IntroKey))
      return Trait::IntroKey;
    // Demarcation
    else if (value == GetTrait(Trait::Delimiter))
      return Trait::Delimiter;
    else if (value == GetTrait(Trait::Terminator))
      return Trait::Terminator;
    // Unknown
    else
      return Trait::Unknown;  // TODO(anonimal): review
  }

  RouterInfo();

  ~RouterInfo();

  RouterInfo(
      const std::string& full_path);

  RouterInfo(
      const RouterInfo&) = default;

  RouterInfo(
      const std::uint8_t* buf,
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

  std::uint64_t GetTimestamp() const {
    return m_Timestamp;
  }

  std::vector<Address>& GetAddresses() {
    return m_Addresses;
  }

  const std::vector<Address>& GetAddresses() const {
    return m_Addresses;
  }

  const Address* GetNTCPAddress(
      bool v4only = true) const;

  const Address* GetSSUAddress(
      bool v4only = true) const;

  const Address* GetSSUV6Address() const;

  void AddNTCPAddress(
      const std::string& host,
      std::uint16_t port);

  void AddSSUAddress(
      const std::string& host,
      std::uint16_t port,
      const std::uint8_t* key,
      std::uint16_t mtu = 0);

  bool AddIntroducer(
      const Address* address,
      std::uint32_t tag);

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
    return m_Caps & Caps::SSUIntroducer;
  }

  bool IsPeerTesting() const {
    return m_Caps & Caps::SSUTesting;
  }

  bool IsHidden() const {
    return m_Caps & Caps::Hidden;
  }

  bool IsHighBandwidth() const {
    return m_Caps & Caps::HighBandwidth;
  }

  std::uint8_t GetCaps() const {
    return m_Caps;
  }

  void SetCaps(
      std::uint8_t caps);

  void SetCaps(
      const char* caps);

  void SetUnreachable(bool unreachable) {
    m_IsUnreachable = unreachable;
  }

  bool IsUnreachable() const {
    return m_IsUnreachable;
  }

  const std::uint8_t* GetBuffer() const {
    auto buf = m_Buffer.get();
    return buf;
  }

  const std::uint8_t* LoadBuffer();  // load if necessary

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
      const std::uint8_t* buf,
      int len);

  void DeleteBuffer() {
    m_Buffer.reset(nullptr);
  }

  // implements RoutingDestination
  const IdentHash& GetIdentHash() const {
    return m_RouterIdentity.GetIdentHash();
  }

  const std::uint8_t* GetEncryptionPublicKey() const {
    return m_RouterIdentity.GetStandardIdentity().public_key;
  }

  bool IsDestination() const {
    return false;
  }

  /// @brief Human readable description of this struct
  /// @param prefix for tabulations
  /// @returns human readable string
  std::string GetDescription(const std::string& tabs = std::string()) const;

 private:
  bool LoadFile();

  void ReadFromFile();

  void ReadFromBuffer(
      bool verify_signature);

  void ParseRouterInfo(const std::string& router_info);

  void WriteToStream(
      std::ostream& s);

  void WriteString(
      const std::string& str,
      std::ostream& s);

  void ExtractCaps(
      const char* value);

  const Address* GetAddress(
      Transport s,
      bool v4only,
      bool v6only = false) const;

  void UpdateCapsProperty();

 private:
  std::string m_FullPath;
  IdentityEx m_RouterIdentity;
  std::unique_ptr<std::uint8_t[]> m_Buffer;
  int m_BufferLen;
  std::uint64_t m_Timestamp;
  std::vector<Address> m_Addresses;
  std::map<std::string, std::string> m_Properties;
  bool m_IsUpdated, m_IsUnreachable;
  std::uint8_t m_SupportedTransports, m_Caps;
  mutable std::shared_ptr<RouterProfile> m_Profile;
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_INFO_H_
