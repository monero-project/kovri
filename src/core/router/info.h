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

  /// @enum Cap
  /// @brief RI capabilities
  enum Cap : std::uint8_t
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

  /// @enum CapFlag
  /// @brief Flags used for RI capabilities
  enum struct CapFlag : std::uint8_t
  {
    Floodfill,
    Hidden,
    Reachable,
    Unreachable,
    LowBandwidth1,
    LowBandwidth2,
    HighBandwidth1,
    HighBandwidth2,
    HighBandwidth3,
    HighBandwidth4,
    UnlimitedBandwidth,
    SSUTesting,
    SSUIntroducer,
    Unknown,
  };

  /// @return Char flag of given enumerated caps flag
  /// @param flag Flag enum used for caps char flag
  char GetTrait(CapFlag flag) const noexcept
  {
    switch (flag)
      {
        case CapFlag::Floodfill:
          return 'f';  // Floodfill

        case CapFlag::Hidden:
          return 'H';  // Hidden

        case CapFlag::Reachable:
          return 'R';  // Reachable

        case CapFlag::Unreachable:
          return 'U';  // Unreachable

        case CapFlag::LowBandwidth1:
          return 'K';  // Under 12 KBps shared bandwidth

        case CapFlag::LowBandwidth2:
          return 'L';  // 12 - 48 KBps shared bandwidth

        case CapFlag::HighBandwidth1:
          return 'M';  // 48 - 64 KBps shared bandwidth

        case CapFlag::HighBandwidth2:
          return 'N';  // 64 - 128 KBps shared bandwidth

        case CapFlag::HighBandwidth3:
          return 'O';  // 128 - 256 KBps shared bandwidth

        case CapFlag::HighBandwidth4:
          return 'P';  // 256 - 2000 KBps shared bandwidth

        case CapFlag::UnlimitedBandwidth:
          return 'X';  // Over 2000 KBps shared bandwidth

        case CapFlag::SSUTesting:
          return 'B';  // Willing and able to participate in peer tests (as Bob or Charlie)

        case CapFlag::SSUIntroducer:
          return 'C';  // Willing and able to serve as an introducer (serving as Bob for an otherwise unreachable Alice)

        case CapFlag::Unknown:
        default:
          return ' ';  // TODO(anonimal): review
      }
  }

  /// @return Enumerated caps flag
  /// @param value Char value of potential caps flag given
  CapFlag GetTrait(const char& value) const noexcept
  {
    if (value == GetTrait(CapFlag::Floodfill))
      return CapFlag::Floodfill;

    else if (value == GetTrait(CapFlag::Hidden))
      return CapFlag::Hidden;

    else if (value == GetTrait(CapFlag::Reachable))
      return CapFlag::Reachable;

    else if (value == GetTrait(CapFlag::Unreachable))
      return CapFlag::Unreachable;

    else if (value == GetTrait(CapFlag::LowBandwidth1))
      return CapFlag::LowBandwidth1;

    else if (value == GetTrait(CapFlag::LowBandwidth2))
      return CapFlag::LowBandwidth2;

    else if (value == GetTrait(CapFlag::HighBandwidth1))
      return CapFlag::HighBandwidth1;

    else if (value == GetTrait(CapFlag::HighBandwidth2))
      return CapFlag::HighBandwidth2;

    else if (value == GetTrait(CapFlag::HighBandwidth3))
      return CapFlag::HighBandwidth3;

    else if (value == GetTrait(CapFlag::HighBandwidth4))
      return CapFlag::HighBandwidth4;

    else if (value == GetTrait(CapFlag::UnlimitedBandwidth))
      return CapFlag::UnlimitedBandwidth;

    else if (value == GetTrait(CapFlag::SSUTesting))
      return CapFlag::SSUTesting;

    else if (value == GetTrait(CapFlag::SSUIntroducer))
      return CapFlag::SSUIntroducer;

    else
      return CapFlag::Unknown;  // TODO(anonimal): review
  }

  struct Introducer {
    boost::asio::ip::address host;
    std::uint16_t port{};
    Tag<32> key;
    std::uint32_t tag{};
  };

  /// @brief Human readable description of Introducer members
  /// @param introducer Introducer class to get description from
  /// @param tabs Prefix for tabulations
  /// @returns human readable string
  const std::string GetDescription(
      const Introducer& introducer,
      const std::string& tabs = std::string()) const;

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
  };

  /// @brief Human readable description of Address members
  /// @param address Address class to get description from
  /// @param tabs Prefix for tabulations
  /// @returns human readable string
  const std::string GetDescription(
      const Address& address,
      const std::string& tabs = std::string()) const;

  /// @enum Trait
  /// @brief RI traits
  enum struct Trait : std::uint8_t
  {
    // Address-specific
    NTCP,
    SSU,
    Host,
    Port,
    MTU,
    Key,
    Caps,
    Cost,
    Date,
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
        // Address-specific
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
        case Trait::Cost:
          return "cost";
        case Trait::Date:
          return "date";
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
    // Address-specific
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
    else if (value == GetTrait(Trait::Cost))
      return Trait::Cost;
    else if (value == GetTrait(Trait::Date))
      return Trait::Date;
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
      const std::uint8_t* buf,
      int len);

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

  void SetTimestamp(std::uint64_t timestamp) noexcept
  {
    m_Timestamp = timestamp;
  }

  std::uint64_t GetTimestamp() const noexcept
  {
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

  void SetOption(
      const std::string& key,
      const std::string& value);

  void DeleteOption(
      const std::string& key);

  void ClearOptions() {
    m_Options.clear();
  }

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

  bool HasCap(Cap cap) const
  {
    bool has_cap = m_Caps & cap;
    LOG(debug) << "RouterInfo: " << __func__ << ": " << has_cap;
    return has_cap;
  }

  std::uint8_t GetCaps() const {
    return m_Caps;
  }

  void SetCaps(
      std::uint8_t caps);

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

  const std::map<std::string, std::string>& GetOptions() const noexcept
  {
    return m_Options;
  }

  // TODO(anonimal): really?...
  bool IsDestination() const {
    return false;
  }

  /// @brief Human readable description of this struct
  /// @param prefix for tabulations
  /// @returns human readable string
  const std::string GetDescription(
      const std::string& tabs = std::string()) const;

 private:
  bool LoadFile();

  void ReadFromFile();

  void ReadFromBuffer(
      bool verify_signature);

  /// @brief Parses complete RI
  void ParseRouterInfo(const std::string& router_info);

  /// @brief Creates populated RI stream
  /// @param router_info RI stream to write to
  /// @param private_keys Keys to write/sign with
  void CreateRouterInfo(
      core::StringStream& router_info,
      const PrivateKeys& private_keys);

  void SetCaps(const std::string& caps);

  /// @return Capabilities flags in string form
  const std::string GetCapsFlags() const;

  const Address* GetAddress(
      Transport s,
      bool v4only,
      bool v6only = false) const;

 private:
  std::string m_FullPath;
  IdentityEx m_RouterIdentity;
  std::unique_ptr<std::uint8_t[]> m_Buffer;
  int m_BufferLen;
  std::uint64_t m_Timestamp;
  std::vector<Address> m_Addresses;
  std::map<std::string, std::string> m_Options;
  bool m_IsUpdated, m_IsUnreachable;
  std::uint8_t m_SupportedTransports, m_Caps;
  mutable std::shared_ptr<RouterProfile> m_Profile;
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_INFO_H_
