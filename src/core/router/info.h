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
#include <tuple>
#include <vector>

#include "core/crypto/signature.h"

#include "core/router/identity.h"
#include "core/router/profiling.h"

#include "core/util/exception.h"
#include "core/util/filesystem.h"

namespace kovri {
namespace core {

struct RouterInfoTraits
{
  /// @enum Interval
  /// @brief RI intervals
  enum Interval { Update = 1800 };  // 30 minutes

  /// @enum Size
  /// @brief Router Info size constants
  enum Size : std::uint16_t
  {
    MinBuffer = core::DSA_SIGNATURE_LENGTH,  // TODO(unassigned): see #498
    MaxBuffer = 2048,  // TODO(anonimal): review if arbitrary
    // TODO(unassigned): algorithm to dynamically determine cost
    NTCPCost = 10,  // NTCP *should* have priority over SSU
    SSUCost = 5,
  };

  /// @enum PortRange
  /// @brief Min and Max public port
  /// @note See i2p.i2p/router/java/src/net/i2p/router/transport/udp/UDPEndpoint.java
  enum PortRange : std::uint16_t
  {
    MinPort = 9111,
    MaxPort = 30777,
  };

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

  /// @enum Trait
  /// @brief RI traits
  enum struct Trait : std::uint8_t
  {
    // File-specific
    InfoFile,
    KeyFile,

    // Option-specific
    RouterVersion,
    LeaseSets,
    Routers,
    NetID,

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
        // File names
        case Trait::InfoFile:
          return "router.info";

        case Trait::KeyFile:
          return "router.key";

        // Option-specific
        case Trait::RouterVersion:
          return "router.version";

        case Trait::LeaseSets:
          return "netdb.knownLeaseSets";

        case Trait::Routers:
          return "netdb.knownRouters";

        case Trait::NetID:
          return "netId";

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

  /// @return String value of given transport
  /// @param transport Enumerated transport
  const std::string GetTrait(Transport transport) const noexcept
  {
    switch (transport)
      {
        case Transport::NTCP:
          return GetTrait(Trait::NTCP);

        case Transport::SSU:
          return GetTrait(Trait::SSU);

        default:
          return GetTrait(Trait::Unknown);
      }
  }

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
};

class RouterInfo : public RouterInfoTraits, public RoutingDestination
{
 public:
  RouterInfo();
  ~RouterInfo();

  /// @brief Create RI with standard defaults
  /// @param point Local hostname/ip address + port
  /// @param has_transport Supports NTCP, SSU
  /// @param keys Privkeys which generate identity
  /// @param caps RI capabilities
  RouterInfo(
      const core::PrivateKeys& keys,
      const std::pair<std::string, std::uint16_t>& point,
      const std::pair<bool, bool>& has_transport,  // TODO(anonimal): refactor as bitwise SupportedTransport?
      const std::uint8_t caps = core::RouterInfo::Cap::Reachable);

  /// @brief Create RI from file
  /// @param path Full path to RI file
  RouterInfo(const std::string& path);

  /// @brief Create RI from buffer
  /// @param buf RI buffer
  /// @param len RI length
  RouterInfo(const std::uint8_t* buf, std::uint16_t len);

  /// @class Introducer
  struct Introducer
  {
    boost::asio::ip::address host;
    std::uint16_t port{};
    Tag<32> key;
    std::uint32_t tag{};
  };

  /// @class Address
  struct Address
  {
    Transport transport;
    boost::asio::ip::address host;
    std::string address;
    std::uint16_t port{}, mtu{};
    std::uint64_t date{};
    std::uint8_t cost{};
    // SSU only
    Tag<32> key{};  // Our intro key for SSU
    std::vector<Introducer> introducers;
    bool HasCompatibleHost(const boost::asio::ip::address& other) const noexcept
    {
      return (host.is_v4() && other.is_v4()) || (host.is_v6() && other.is_v6());
    }
  };

  /// @brief Adds/saves address + sets appropriate RI members
  /// @param point Supported transport / Host string / Port integral
  /// @param key Our intoducer key
  /// @param mtu Address MTU
  void AddAddress(
      const std::tuple<Transport, std::string, std::uint16_t>& point,
      const std::uint8_t* key = nullptr,
      const std::uint16_t mtu = 0);

  /// @brief Adds introducer to RI using SSU capable address object
  /// @param address SSU capable address
  /// @param tag Relay tag
  /// @return True if address is SSU capable and introducer was added
  bool AddIntroducer(const Address* address, std::uint32_t tag);

  /// @brief Removes introducer from RI address's introducer object
  /// @param endpoint Endpoint address of introducer
  /// @return True if introducer was found and erased
  bool RemoveIntroducer(const boost::asio::ip::udp::endpoint& endpoint);

  /// @brief Enable IPv6 for supported transports
  void EnableV6();

  /// @brief Disable IPv6 for supported transports
  void DisableV6();

  /// @brief Updates RI with new RI from buffer
  /// @param buf New RI buffer
  /// @param len New RI length
  void Update(const std::uint8_t* buf, std::uint16_t len);

  /// @brief Loads RI buffer (by reading) if buffer is not yet available
  /// @notes Required by NetDb
  /// TODO(anonimal): remove, refactor (buffer should be guaranteed upon object creation)
  const std::uint8_t* LoadBuffer();

  /// @brief Create RI and put into buffer
  /// @param private_keys Private keys used to derive signing key
  ///   (and subsequently sign the RI with)
  void CreateBuffer(const PrivateKeys& private_keys);

  /// @brief Save RI to file
  /// @param path Full RI path of file to save to
  void SaveToFile(const std::string& path);

  /// @brief Get RI profile
  /// @detail If profile does not exist, creates it
  // TODO(anonimal): not an ideal getter because of detail
  std::shared_ptr<RouterProfile> GetProfile() const;

  // TODO(anonimal): template address getter

  /// @return Address object capable of NTCP
  /// @param has_v6 Address should have v6 capability
  const Address* GetNTCPAddress(bool has_v6 = false) const;

  /// @return Address object capable of SSU
  /// @param has_v6 Address should have v6 capability
  const Address* GetSSUAddress(bool has_v6 = false) const;

 public:
  /// @return Pointer to RI buffer
  const std::uint8_t* GetBuffer() const
  {
    return m_Buffer.get();
  }

  /// @return RI buffer length
  std::uint16_t GetBufferLen() const noexcept
  {
    return m_BufferLen;
  }

  /// @brief Deletes RI buffer
  void DeleteBuffer()
  {
    m_Buffer.reset(nullptr);
  }

  /// @return RI's router identity
  const IdentityEx& GetRouterIdentity() const noexcept
  {
    return m_RouterIdentity;
  }

  /// @return RI's ident hash
  /// @notes implements RoutingDestination
  const IdentHash& GetIdentHash() const noexcept
  {
    return m_RouterIdentity.GetIdentHash();
  }

  /// @return Abbreviated ident hash in base64
  std::string GetIdentHashAbbreviation() const
  {
    return GetIdentHash().ToBase64().substr(0, 4);
  }

  /// @return RI's ident pubkey
  const std::uint8_t* GetEncryptionPublicKey() const noexcept
  {
    return m_RouterIdentity.GetStandardIdentity().public_key;
  }

  /// @brief Sets RI timestamp
  void SetTimestamp(std::uint64_t timestamp) noexcept
  {
    m_Timestamp = timestamp;
  }

  /// @return RI timestamp
  std::uint64_t GetTimestamp() const noexcept
  {
    return m_Timestamp;
  }

  /// @brief Sets RI capabilities *and* options
  /// @param caps capabiliti(es) to set
  void SetCaps(std::uint8_t caps);

  /// @return RI capabilities
  std::uint8_t GetCaps() const noexcept
  {
    return m_Caps;
  }

  /// @brief Set RI option(s)
  /// @details RI options consist of expected (required) options and additional options.
  ///   Required options include capability flags (in non-int form) and various router version information.
  ///   Additional options can include statistics and/or kovri-specific information if needed
  /// @param key Key type
  /// @param value Value type
  void SetOption(const std::string& key, const std::string& value)
  {
    m_Options[key] = value;
  }

  /// @brief Set essential (non-caps) default options for new RIs and when updating RIs
  void SetDefaultOptions();

  /// @return Mutable RI options
  std::map<std::string, std::string>& GetOptions() noexcept
  {
    return m_Options;
  }

  /// @return Immutable RI options
  const std::map<std::string, std::string>& GetOptions() const noexcept
  {
    return m_Options;
  }

  /// @brief Set if RI has been made unreachable
  /// @param updated True if unreachable
  void SetUnreachable(bool unreachable) noexcept
  {
    m_IsUnreachable = unreachable;
  }

  /// @brief Was RI made unreachable?
  /// @return True if reachable
  bool IsUnreachable() const noexcept
  {
    return m_IsUnreachable;
  }

  /// @brief Set if RI has been updated with new RI
  /// @param updated True if updated
  void SetUpdated(bool updated) noexcept
  {
    m_IsUpdated = updated;
  }

  /// @brief Was RI updated with new RI?
  /// @return True if updated
  bool IsUpdated() const noexcept
  {
    return m_IsUpdated;
  }

  /// @return Mutable RI addresses
  std::vector<Address>& GetAddresses() noexcept
  {
    return m_Addresses;
  }

  /// @return Immutable RI addresses
  const std::vector<Address>& GetAddresses() const noexcept
  {
    return m_Addresses;
  }

 public:
  /// @brief Does RI support given transport?
  /// @param transport Transport type(s)
  /// @return True if supports
  bool HasTransport(const std::uint8_t transport) const noexcept
  {
    return m_SupportedTransports & transport;
  }

  /// @brief Does RI support NTCP?
  /// @return True if supports
  bool HasNTCP(bool has_v6 = false) const noexcept
  {
    if (!has_v6)
      return HasTransport(SupportedTransport::NTCPv4);
    return HasTransport(
        (SupportedTransport::NTCPv4 | SupportedTransport::NTCPv6));
  }

  /// @brief Does RI support SSU?
  /// @return True if supports
  bool HasSSU(bool has_v6 = false) const noexcept
  {
    if (!has_v6)
      return HasTransport(SupportedTransport::SSUv4);
    return HasTransport(
        (SupportedTransport::SSUv4 | SupportedTransport::SSUv6));
  }

  /// @brief Does RI support IPv6?
  /// @return True if supports
  bool HasV6() const noexcept
  {
    return HasTransport(
        (SupportedTransport::NTCPv6 | SupportedTransport::SSUv6));
  }

  /// @brief Does RI have compatible transports with other RI?
  /// @param other Other RI to test compatability with
  /// @return True if compatible
  bool HasCompatibleTransports(const RouterInfo& other) const noexcept
  {
    return m_SupportedTransports & other.m_SupportedTransports;
  }

  /// @brief Does RI have given capabiliti(es)?
  /// @param cap Capabiliti(es)
  /// @return True if available
  bool HasCap(Cap cap) const noexcept
  {
    return m_Caps & cap;
  }

  /// @brief Router is unreachable, must use introducer
  /// @return True if uses introducer
  bool UsesIntroducer() const noexcept
  {
    return HasCap(Cap::Unreachable);
  }

  // TODO(anonimal): really?...
  bool IsDestination() const noexcept
  {
    return false;
  }

  /// @brief Save RI profile
  void SaveProfile()
  {
    if (m_Profile)
      m_Profile->Save();
  }

  /// @brief Human readable description of Introducer members
  /// @param introducer Introducer class to get description from
  /// @param tabs Prefix for tabulations
  /// @returns human readable string
  const std::string GetDescription(
      const Introducer& introducer,
      const std::string& tabs = std::string()) const;

  /// @brief Human readable description of Address members
  /// @param address Address class to get description from
  /// @param tabs Prefix for tabulations
  /// @returns human readable string
  const std::string GetDescription(
      const Address& address,
      const std::string& tabs = std::string()) const;

  /// @brief Human readable description of this struct
  /// @param prefix for tabulations
  /// @returns human readable string
  const std::string GetDescription(
      const std::string& tabs = std::string()) const;

 private:
  /// @brief Read RI from file
  /// @throws std::exception
  void ReadFromFile();

  /// @brief Read RI from byte stream buffer
  /// @param verify_signature True if we should verify RI signature against identity
  void ReadFromBuffer(bool verify_signature);

  /// @brief Parses complete RI
  /// @param router_info Object to write RI to
  void ParseRouterInfo(const std::string& router_info);

  /// @brief Set RI capabilities from string of caps flag(s)
  void SetCaps(const std::string& caps);

  /// @return Capabilities flags in string form
  const std::string GetCapsFlags() const;

  /// @brief Creates populated RI stream
  /// @param router_info RI stream to write to
  /// @param private_keys Keys to write/sign with
  void CreateRouterInfo(
      core::StringStream& router_info,
      const PrivateKeys& private_keys);

  /// @brief Return address object which uses given transport(s)
  /// @details Performs bitwise operations to determine if address contains given transport
  /// @param transports integer value of transport(s) (see enum)
  /// @return Address capable of given transport(s)
  const RouterInfo::Address* GetAddress(const std::uint8_t transports) const;

 private:
  core::Exception m_Exception;
  std::string m_Path;
  IdentityEx m_RouterIdentity;
  std::unique_ptr<std::uint8_t[]> m_Buffer;
  std::uint16_t m_BufferLen{};
  std::uint64_t m_Timestamp{};
  std::vector<Address> m_Addresses;
  std::map<std::string, std::string> m_Options;
  bool m_IsUpdated = false, m_IsUnreachable = false;
  std::uint8_t m_SupportedTransports{}, m_Caps{};
  mutable std::shared_ptr<RouterProfile> m_Profile;
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_INFO_H_
