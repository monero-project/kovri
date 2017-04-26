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

#include "core/router/info.h"

#include <boost/lexical_cast.hpp>

#include <stdio.h>
#include <string.h>

#include <fstream>
#include <tuple>

#include "core/router/context.h"

#include "core/util/base64.h"
#include "core/util/filesystem.h"
#include "core/util/i2p_endian.h"
#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri
{
namespace core
{

const std::string RouterInfo::GetDescription(
    const Introducer& introducer,
    const std::string& tabs) const
{
  std::stringstream ss;

  const std::string delimiter = GetTrait(Trait::Delimiter),
                    terminator = GetTrait(Trait::Terminator) + "\n";

  ss << tabs << GetTrait(Trait::IntroHost) << delimiter
     << introducer.host.to_string() << terminator

     << tabs << GetTrait(Trait::IntroPort) << delimiter
     << introducer.port << terminator

     << tabs << GetTrait(Trait::IntroKey) << delimiter
     << introducer.key.ToBase64() << terminator

     << tabs << GetTrait(Trait::IntroTag) << delimiter
     << introducer.tag << terminator;

  return ss.str();
}

// TODO(unassigned): though this was originally intended for the kovri utility binary,
//  we can expand reporting to include remaining POD types of the Address struct
const std::string RouterInfo::GetDescription(
    const Address& address,
    const std::string& tabs) const
{
  std::stringstream ss;

  const std::string delimiter = GetTrait(Trait::Delimiter),
                    terminator = GetTrait(Trait::Terminator) + "\n";

  ss << tabs << "Address transport: ";
  switch (address.transport)
    {
      case Transport::NTCP:
        ss << GetTrait(Trait::NTCP);
        break;
      case Transport::SSU:
        ss << GetTrait(Trait::SSU);
        break;
      case Transport::Unknown:
        ss << GetTrait(Trait::Unknown);
        return ss.str();
    }

  ss << "\n"
     << tabs << "\t" << GetTrait(Trait::Cost) << delimiter
     << static_cast<int>(address.cost) << terminator

     << tabs << "\t" << GetTrait(Trait::Cost) << delimiter
     << address.host.to_string() << terminator

     << tabs << "\t" << GetTrait(Trait::Port) << delimiter
     << address.port << terminator;

  if (address.transport == Transport::SSU)
    {
      ss << tabs << "\n\tIntroducers(" << address.introducers.size() << ")"
         << std::endl;
      for (const Introducer& introducer : address.introducers)
        ss << GetDescription(introducer, tabs + "\t\t") << std::endl;
    }

  return ss.str();
}

RouterInfo::RouterInfo()
    : m_Buffer(nullptr),
      m_BufferLen(0),
      m_Timestamp(0),
      m_IsUpdated(false),
      m_IsUnreachable(false),
      m_SupportedTransports(0),
      m_Caps(0) {}

RouterInfo::RouterInfo(
    const std::string& full_path)
    : m_FullPath(full_path),
      m_IsUpdated(false),
      m_IsUnreachable(false),
      m_SupportedTransports(0),
      m_Caps(0) {
  m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
  ReadFromFile();
}

RouterInfo::RouterInfo(
    const std::uint8_t* buf,
    int len)
    : m_IsUpdated(true),
      m_IsUnreachable(false),
      m_SupportedTransports(0),
      m_Caps(0) {
  if (len >= MAX_RI_BUFFER_SIZE)
    throw std::length_error(
        "RouterInfo: " + std::string(__func__) + ": buffer length too large");
  m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
  memcpy(m_Buffer.get(), buf, len);
  m_BufferLen = len;
  ReadFromBuffer(true);
}

RouterInfo::~RouterInfo() {}

void RouterInfo::Update(
    const std::uint8_t* buf,
    int len) {
  if (len >= MAX_RI_BUFFER_SIZE)
    throw std::length_error(
        "RouterInfo: " + std::string(__func__) + ": buffer length too large");
  if (!m_Buffer)
    m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
  m_IsUpdated = true;
  m_IsUnreachable = false;
  m_SupportedTransports = 0;
  m_Caps = 0;
  m_Addresses.clear();
  m_Options.clear();
  memcpy(m_Buffer.get(), buf, len);
  m_BufferLen = len;
  ReadFromBuffer(true);
  // don't delete buffer until saved to file
}

void RouterInfo::SetRouterIdentity(
    const IdentityEx& identity) {
  m_RouterIdentity = identity;
  m_Timestamp = kovri::core::GetMillisecondsSinceEpoch();
}

bool RouterInfo::LoadFile() {
  std::ifstream s(m_FullPath.c_str(), std::ifstream::binary);
  if (s.is_open()) {
    s.seekg(0, std::ios::end);
    m_BufferLen = s.tellg();
    if (m_BufferLen < 40 || m_BufferLen >= MAX_RI_BUFFER_SIZE)
      {
        LOG(error) << "RouterInfo: " << m_FullPath
                   << " is malformed. Length = " << m_BufferLen;
        return false;
      }
    s.seekg(0, std::ios::beg);
    if (!m_Buffer)
      m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
    s.read(reinterpret_cast<char *>(m_Buffer.get()), m_BufferLen);
  } else {
    LOG(error) << "RouterInfo: can't open file " << m_FullPath;
    return false;
  }
  return true;
}

void RouterInfo::ReadFromFile() {
  if (!LoadFile())
    throw std::runtime_error(
        "RouterInfo: " + std::string(__func__) + ": invalid file");
  ReadFromBuffer(false);
}

void RouterInfo::ReadFromBuffer(
    bool verify_signature) {
  std::size_t identity_len = m_RouterIdentity.FromBuffer(m_Buffer.get(), m_BufferLen);
  std::string str(
        reinterpret_cast<char *>(m_Buffer.get()) + identity_len,
        m_BufferLen - identity_len);
  ParseRouterInfo(str);
  if (verify_signature) {
    // verify signature
    int len = m_BufferLen - m_RouterIdentity.GetSignatureLen();
    if (!m_RouterIdentity.Verify(
          reinterpret_cast<std::uint8_t *>(m_Buffer.get()),
          len,
          reinterpret_cast<std::uint8_t *>(m_Buffer.get() + len))) {
      LOG(error) << "RouterInfo: signature verification failed";
      m_IsUnreachable = true;
    }
    m_RouterIdentity.DropVerifier();
  }
}

// TODO(anonimal): unit-test
// TODO(anonimal): we could possibly implement by tokenizing the string but this could be more work (i.e., when reading string from byte) or overhead than needed
void RouterInfo::ParseRouterInfo(const std::string& router_info)
{
  LOG(debug) << "RouterInfo: parsing";

  // Create RI stream
  core::StringStream stream(router_info);

  // For key/value pair
  std::string key, value;

  // RI sizes
  std::uint16_t read_size{}, given_size{}, remaining_size{};

  // Does RI have introducers
  bool has_introducers = false;

  // Get timestamp
  stream.Read(&m_Timestamp, sizeof(m_Timestamp));
  m_Timestamp = be64toh(m_Timestamp);
  LOG(debug) << "RouterInfo: timestamp = " << m_Timestamp;

  // Get number of IP addresses
  std::uint8_t num_addresses;
  stream.Read(&num_addresses, sizeof(num_addresses));
  LOG(debug) << "RouterInfo: number of addresses = "
             << static_cast<std::size_t>(num_addresses);

  // Process given addresses
  for (std::size_t i = 0; i < num_addresses; i++)
    {
      Address address;
      bool is_valid_address = true;

      // Read cost + date
      stream.Read(&address.cost, sizeof(address.cost));
      stream.Read(&address.date, sizeof(address.date));

      // Read/set transport
      std::string transport(stream.ReadStringFromByte());
      switch (GetTrait(transport))
        {
          case Trait::NTCP:
            address.transport = Transport::NTCP;
            break;
          case Trait::SSU:
            address.transport = Transport::SSU;
            break;
          default:
            address.transport = Transport::Unknown;
            break;
        }

      // Get the given size of remaining chunk
      stream.Read(&given_size, sizeof(given_size));
      given_size = be16toh(given_size);

      // Reset remaining size
      remaining_size = 0;
      while (remaining_size < given_size)
        {
          // Get key/value pair
          // TODO(anonimal): consider member for stream size read, replace tuple with pair
          std::tie(key, value, read_size) = stream.ReadKeyPair();
          remaining_size += read_size;

          // Get key / set members
          switch (GetTrait(key))
            {
              case Trait::Host:
                {
                  // Process host and transport
                  // TODO(unassigned): we process transport so we can resolve host. This seems like a hack.
                  boost::system::error_code ecode;
                  address.host =
                      boost::asio::ip::address::from_string(value, ecode);
                  if (ecode)
                    {
                      // Unresolved hosts return invalid argument. See TODO below
                      if (ecode != boost::asio::error::invalid_argument)
                        {
                          is_valid_address = false;
                          LOG(error) << "RouterInfo: " << __func__ << ": '"
                                     << ecode.message() << "'";
                        }
                      // Prepare for host resolution
                      switch (address.transport)
                        {
		          case Transport::NTCP:
                            // NTCP will (should be) resolved in transports
                            // TODO(unassigned): refactor. Though we will resolve host later, assigning values upon error is simply confusing.
                            m_SupportedTransports |= SupportedTransport::NTCPv4;
                            address.address = value;
                            break;
		          case Transport::SSU:
                            // TODO(unassigned): implement address resolver for SSU (then break from default case)
                            LOG(warning)
                                << "RouterInfo: unexpected SSU address "
                                << value;
                          default:
                            is_valid_address = false;
                        }
                      break;
                    }
                  // add supported protocol
                  if (address.host.is_v4())
                    m_SupportedTransports |=
                        (address.transport == Transport::NTCP)
                            ? SupportedTransport::NTCPv4
                            : SupportedTransport::SSUv4;
                  else
                    m_SupportedTransports |=
                        (address.transport == Transport::NTCP)
                            ? SupportedTransport::NTCPv6
                            : SupportedTransport::SSUv6;
                  break;
                }
              case Trait::Port:
                address.port = boost::lexical_cast<std::uint16_t>(value);
                break;
              case Trait::MTU:
                address.mtu = boost::lexical_cast<std::uint16_t>(value);
                break;
              case Trait::Key:
                kovri::core::Base64ToByteStream(
                    value.c_str(), value.size(), address.key, 32);
                break;
              case Trait::Caps:
                SetCaps(value);
                break;
              default:
                // Test for introducers
                // TODO(unassigned): this is faster than a regexp, let's try to do this better though
                if (key.front() == GetTrait(Trait::IntroHost).front())
                  {
                    has_introducers = true;

                    // Because of multiple introducers, get/set the introducer number
                    // TODO(unassigned): let's not implement like this, nor do this here
                    unsigned char index = key[key.size() - 1] - '0';
                    if (index >= address.introducers.size())
                      address.introducers.resize(index + 1);
                    Introducer& introducer = address.introducers.at(index);

                    // Drop number count from introducer key trait
                    key.pop_back();

                    // Set introducer members
                    switch (GetTrait(key))
                      {
                        case Trait::IntroHost:
                          {
                            // TODO(unassigned): error handling
                            boost::system::error_code ecode;
                            introducer.host =
                                boost::asio::ip::address::from_string(
                                    value, ecode);
                          }
                          break;
                        case Trait::IntroPort:
                          introducer.port = boost::lexical_cast<std::uint16_t>(value);
                          break;
                        case Trait::IntroTag:
                          introducer.tag =
                              boost::lexical_cast<std::uint32_t>(value);
                          break;
                        case Trait::IntroKey:
                          kovri::core::Base64ToByteStream(
                              value.c_str(), value.size(), introducer.key, 32);
                          break;
                        default:
                          LOG(error) << "RouterInfo: invalid introducer trait";
                          is_valid_address = false;
                          break;
                      }
                  }
                // TODO(anonimal): review/finish. We do not process/handle all possible RI entries
                break;
            }
        }

      // Log RI details, save valid addresses
      LOG(debug) << GetDescription(address);
      if (is_valid_address)
        m_Addresses.push_back(address);
    }

  // Read peers
  // TODO(unassigned): handle peers
  std::uint8_t num_peers;
  stream.Read(&num_peers, sizeof(num_peers));
  stream.Seekg(num_peers * 32, std::ios_base::cur);

  // Read remaining options
  stream.Read(&given_size, sizeof(given_size));
  given_size = be16toh(given_size);

  // Reset remaining size
  remaining_size = 0;
  while (remaining_size < given_size)
    {
      // Get key/value pair
      // TODO(anonimal): consider member for stream size read, replace tuple with pair
      std::tie(key, value, read_size) = stream.ReadKeyPair();
      remaining_size += read_size;

      // Set option
      SetOption(key, value);

      // Set capabilities
      // TODO(anonimal): review setter implementation
      if (key == GetTrait(Trait::Caps))
        SetCaps(value);
    }

  // Router *should* be unreachable
  if (!m_SupportedTransports || !m_Addresses.size()
      || (UsesIntroducer() && !has_introducers))
    {
      LOG(error) << "RouterInfo: " << __func__ << ": router is unreachable";
      // TODO(anonimal): ensure this doesn't add router info to NetDb
      SetUnreachable(true);
    }
}

void RouterInfo::SetCaps(const std::string& caps)
{
  LOG(debug) << "RouterInfo: " << __func__ << ": setting caps " << caps;
  for (const auto& cap : caps)
    {
      switch (GetTrait(cap))
        {
          case CapFlag::Floodfill:
            m_Caps |= Cap::Floodfill;
            break;
          case CapFlag::UnlimitedBandwidth:
            m_Caps |= Cap::UnlimitedBandwidth;
            break;
          case CapFlag::HighBandwidth1:
          case CapFlag::HighBandwidth2:
          case CapFlag::HighBandwidth3:
          case CapFlag::HighBandwidth4:
            m_Caps |= Cap::HighBandwidth;
            break;
          case CapFlag::LowBandwidth1:
          case CapFlag::LowBandwidth2:
            // TODO(anonimal): implement!
            break;
          case CapFlag::Hidden:
            m_Caps |= Cap::Hidden;
            break;
          case CapFlag::Reachable:
            m_Caps |= Cap::Reachable;
            break;
          case CapFlag::Unreachable:
            m_Caps |= Cap::Unreachable;
            break;
          case CapFlag::SSUTesting:
            m_Caps |= Cap::SSUTesting;
            break;
          case CapFlag::SSUIntroducer:
            m_Caps |= Cap::SSUIntroducer;
            break;
          case CapFlag::Unknown:
          default:
            {
              LOG(error) << "RouterInfo: " << __func__
                         << ": ignoring unknown cap " << cap;
            }
        }
    }
}

// TODO(anonimal): debug + trace logging
// TODO(anonimal): unit-test
void RouterInfo::CreateRouterInfo(
    core::StringStream& router_info,
    const PrivateKeys& private_keys)
{
  LOG(debug) << "RouterInfo: " << __func__;

  // Write ident
  // TODO(anonimal): review the following arbitrary size (must be >= 387)
  std::array<std::uint8_t, 1024> ident{};
  auto ident_len =
      private_keys.GetPublic().ToBuffer(ident.data(), ident.size());
  router_info.Write(ident.data(), ident_len);

  // Set published timestamp
  SetTimestamp(core::GetMillisecondsSinceEpoch());

  // Write published timestamp
  std::uint64_t timestamp = htobe64(GetTimestamp());
  router_info.Write(&timestamp, sizeof(timestamp));

  // Write number of addresses to follow
  std::uint8_t num_addresses = GetAddresses().size();
  router_info.Write(&num_addresses, sizeof(num_addresses));

  // RI options, once populated, written to RI stream
  core::StringStream options(
      GetTrait(Trait::Delimiter), GetTrait(Trait::Terminator));

  LOG(debug) << "RouterInfo: " << __func__ << ": processing "
             << GetAddresses().size() << " addresses";

  // Write each address + options
  for (const auto& address : GetAddresses())
    {
      // Reset options for next address
      options.Str(std::string());

      // Write cost + date
      router_info.Write(&address.cost, sizeof(address.cost));
      router_info.Write(&address.date, sizeof(address.date));

      // Write transport
      switch (address.transport)
        {
          case Transport::NTCP:
            router_info.WriteByteAndString(GetTrait(Trait::NTCP));
            break;
          case Transport::SSU:
            {
              router_info.WriteByteAndString(GetTrait(Trait::SSU));

              // Get/Set SSU capabilities flags
              std::string caps;
              if (HasCap(Cap::SSUTesting))
                caps += GetTrait(CapFlag::SSUTesting);
              if (HasCap(Cap::SSUIntroducer))
                caps += GetTrait(CapFlag::SSUIntroducer);

              // Write SSU capabilities
              options.WriteKeyPair(GetTrait(Trait::Caps), caps);
              break;
            }
          default:
            // TODO(anonimal): review
            router_info.WriteByteAndString(GetTrait(Trait::Unknown));
            break;
        }

      // Write host
      options.WriteKeyPair(GetTrait(Trait::Host), address.host.to_string());

      // SSU
      if (address.transport == Transport::SSU)
        {
          // Write introducers (if any)
          if (!address.introducers.empty())
            {
              LOG(debug) << "RouterInfo: " << __func__ << " writing "
                         << address.introducers.size() << " introducers";

              std::uint8_t count{};
              for (const auto& introducer : address.introducers)
                {
                  std::string num = boost::lexical_cast<std::string>(count);

                  // Write introducer host
                  options.WriteKeyPair(
                      GetTrait(Trait::IntroHost) + num,
                      introducer.host.to_string());

                  // Write introducer key
                  std::array<char, 64> key{};
                  core::ByteStreamToBase64(
                      introducer.key,
                      sizeof(introducer.key),
                      key.data(),
                      key.size());

                  options.WriteKeyPair(
                      GetTrait(Trait::IntroKey) + num, key.data());

                  // Write introducer port
                  options.WriteKeyPair(
                      GetTrait(Trait::IntroPort) + num,
                      boost::lexical_cast<std::string>(introducer.port));

                  // Write introducer tag
                  options.WriteKeyPair(
                      GetTrait(Trait::IntroTag) + num,
                      boost::lexical_cast<std::string>(introducer.tag));

                  count++;
                }
            }

          // Write key
          std::array<char, 64> value{};
          core::ByteStreamToBase64(
              address.key, sizeof(address.key), value.data(), value.size());

          options.WriteKeyPair(GetTrait(Trait::Key), value.data());

          // Write MTU
          if (address.mtu)
            options.WriteKeyPair(
                GetTrait(Trait::MTU),
                boost::lexical_cast<std::string>(address.mtu));
        }

      // Write port
      options.WriteKeyPair(
          GetTrait(Trait::Port),
          boost::lexical_cast<std::string>(address.port));

      // Write size of populated options
      std::uint16_t size = htobe16(options.Str().size());
      router_info.Write(&size, sizeof(size));

      // Write options to RI
      router_info.Write(options.Str().c_str(), options.Str().size());
    }

  // Write number of peers
  // Note: this is unused / unimplemented, see RI spec
  std::uint8_t num_peers{};
  router_info.Write(&num_peers, sizeof(num_peers));

  // Reset for more options
  options.Str(std::string());

  // Write remaining options
  for (const auto& opt : GetOptions())
    options.WriteKeyPair(opt.first, opt.second);

  // Write size of remaining options
  std::uint16_t size = htobe16(options.Str().size());
  router_info.Write(&size, sizeof(size));

  // Write remaining options to RI
  router_info.Write(options.Str().c_str(), options.Str().size());

  // TODO(anonimal): we should implement RI signing *here*

  LOG(debug) << "RouterInfo: " << __func__
             << " total RI size: " << router_info.Str().size();
}

const std::uint8_t* RouterInfo::LoadBuffer() {
  if (!m_Buffer) {
    if (LoadFile())
      LOG(debug)
        << "RouterInfo: buffer for "
        << GetIdentHashAbbreviation() << " loaded from file";
  }
  return m_Buffer.get();
}

void RouterInfo::CreateBuffer(const PrivateKeys& private_keys) {
  core::StringStream router_info;
  CreateRouterInfo(router_info, private_keys);
  m_BufferLen = router_info.Str().size();
  if (!m_Buffer)
    m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
  memcpy(m_Buffer.get(), router_info.Str().c_str(), m_BufferLen);
  // signature
  // TODO(anonimal): signing should be done when creating RI, not after. Requires other refactoring.
  private_keys.Sign(
    reinterpret_cast<std::uint8_t *>(m_Buffer.get()),
    m_BufferLen,
    reinterpret_cast<std::uint8_t *>(m_Buffer.get()) + m_BufferLen);
  m_BufferLen += private_keys.GetPublic().GetSignatureLen();
}

void RouterInfo::SaveToFile(
    const std::string& full_path) {
  m_FullPath = full_path;
  if (m_Buffer) {
    std::ofstream f(full_path, std::ofstream::binary | std::ofstream::out);
    if (f.is_open())
      f.write(reinterpret_cast<char *>(m_Buffer.get()), m_BufferLen);
    else
      LOG(error) << "RouterInfo: can't save RouterInfo to " << full_path;
  } else {
    LOG(error) << "RouterInfo: can't save RouterInfo, buffer is empty";
  }
}

void RouterInfo::AddNTCPAddress(
    const std::string& host,
    std::uint16_t port) {
  Address addr;
  addr.host = boost::asio::ip::address::from_string(host);
  addr.port = port;
  addr.transport = Transport::NTCP;
  addr.cost = 10;  // NTCP should have priority over SSU
  addr.date = 0;
  addr.mtu = 0;
  m_Addresses.push_back(addr);
  m_SupportedTransports |= addr.host.is_v6() ? SupportedTransport::NTCPv6
                                             : SupportedTransport::NTCPv6;
}

void RouterInfo::AddSSUAddress(
    const std::string& host,
    std::uint16_t port,
    const std::uint8_t* key,
    std::uint16_t mtu) {
  Address addr;
  addr.host = boost::asio::ip::address::from_string(host);
  addr.port = port;
  addr.transport = Transport::SSU;
  addr.cost = 5;
  addr.date = 0;
  addr.mtu = mtu;
  memcpy(addr.key, key, 32);
  m_Addresses.push_back(addr);
  m_SupportedTransports |=
      addr.host.is_v6() ? SupportedTransport::SSUv6 : SupportedTransport::SSUv4;
  m_Caps |= Cap::SSUTesting;
  m_Caps |= Cap::SSUIntroducer;
}

bool RouterInfo::AddIntroducer(
    const Address* address,
    std::uint32_t tag) {
  for (auto& addr : m_Addresses) {
    if (addr.transport == Transport::SSU && addr.host.is_v4()) {
      for (auto intro : addr.introducers)
        if (intro.tag == tag)
          return false;  // already presented
      Introducer i;
      i.host = address->host;
      i.port = address->port;
      i.tag = tag;
      memcpy(i.key, address->key, 32);  // TODO(unassigned): replace to Tag<32>
      addr.introducers.push_back(i);
      return true;
    }
  }
  return false;
}

bool RouterInfo::RemoveIntroducer(
    const boost::asio::ip::udp::endpoint& e) {
  for (auto& addr : m_Addresses) {
    if (addr.transport == Transport::SSU && addr.host.is_v4()) {
      for (std::vector<Introducer>::iterator it = addr.introducers.begin();
          it != addr.introducers.end();
          it++)
        if (boost::asio::ip::udp::endpoint(
              it->host,
              it->port) == e) {
          addr.introducers.erase(it);
          return true;
        }
    }
  }
  return false;
}

void RouterInfo::SetCaps(std::uint8_t caps)
{
  // Set member
  m_Caps = caps;

  // Set RI option with new caps flags
  SetOption(GetTrait(Trait::Caps), GetCapsFlags());
}

const std::string RouterInfo::GetCapsFlags() const
{
  std::string flags;

  if (m_Caps & Cap::Floodfill)
    {
      flags += GetTrait(CapFlag::HighBandwidth4);  // highest bandwidth
      flags += GetTrait(CapFlag::Floodfill);
    }
  else
    {
      flags += (m_Caps & Cap::HighBandwidth) ? GetTrait(CapFlag::HighBandwidth3)
                                             : GetTrait(CapFlag::LowBandwidth2);
      // TODO(anonimal): what about lowest bandwidth cap?
    }

  if (m_Caps & Cap::Hidden)
    flags += GetTrait(CapFlag::Hidden);

  if (m_Caps & Cap::Reachable)
    flags += GetTrait(CapFlag::Reachable);

  if (m_Caps & Cap::Unreachable)
    flags += GetTrait(CapFlag::Unreachable);

  return flags;
}

void RouterInfo::SetOption(
    const std::string& key,
    const std::string& value) {
  m_Options[key] = value;
}

void RouterInfo::DeleteOption(
    const std::string& key) {
  m_Options.erase(key);
}

bool RouterInfo::IsNTCP(
    bool v4only) const {
  if (v4only)
    return m_SupportedTransports & SupportedTransport::NTCPv4;
  else
    return m_SupportedTransports
           & (SupportedTransport::NTCPv4 | SupportedTransport::NTCPv6);
}

bool RouterInfo::IsSSU(
    bool v4only) const {
  if (v4only)
    return m_SupportedTransports & SupportedTransport::SSUv4;
  else
    return m_SupportedTransports
           & (SupportedTransport::SSUv4 | SupportedTransport::SSUv6);
}

bool RouterInfo::IsV6() const {
  return m_SupportedTransports
         & (SupportedTransport::NTCPv6 | SupportedTransport::SSUv6);
}

void RouterInfo::EnableV6() {
  if (!IsV6())
    m_SupportedTransports |=
        SupportedTransport::NTCPv6 | SupportedTransport::SSUv6;
}

void RouterInfo::DisableV6() {
  if (IsV6()) {
    // NTCP
    m_SupportedTransports &= ~SupportedTransport::NTCPv6;
    for (std::size_t i = 0; i < m_Addresses.size(); i++) {
      if (m_Addresses[i].transport ==
          core::RouterInfo::Transport::NTCP &&
          m_Addresses[i].host.is_v6()) {
        m_Addresses.erase(m_Addresses.begin() + i);
        break;
      }
    }
    // SSU
    m_SupportedTransports &= ~SupportedTransport::SSUv6;
    for (std::size_t i = 0; i < m_Addresses.size(); i++) {
      if (m_Addresses[i].transport ==
          Transport::SSU &&
          m_Addresses[i].host.is_v6()) {
        m_Addresses.erase(m_Addresses.begin() + i);
        break;
      }
    }
  }
}

bool RouterInfo::UsesIntroducer() const {
  return HasCap(Cap::Unreachable);  // Router is unreachable, must use introducer
}

const RouterInfo::Address* RouterInfo::GetNTCPAddress(
    bool v4only) const {
  return GetAddress(Transport::NTCP, v4only);
}

const RouterInfo::Address* RouterInfo::GetSSUAddress(
    bool v4only) const {
  return GetAddress(Transport::SSU, v4only);
}

const RouterInfo::Address* RouterInfo::GetSSUV6Address() const {
  return GetAddress(Transport::SSU, false, true);
}

const RouterInfo::Address* RouterInfo::GetAddress(
    Transport s,
    bool v4only,
    bool v6only) const {
  for (auto& address : m_Addresses) {
    if (address.transport == s) {
      if ((!v4only || address.host.is_v4()) &&
          (!v6only || address.host.is_v6()))
        return &address;
    }
  }
  return nullptr;
}

std::shared_ptr<RouterProfile> RouterInfo::GetProfile() const {
  if (!m_Profile)
    m_Profile = GetRouterProfile(GetIdentHash());
  return m_Profile;
}

const std::string RouterInfo::GetDescription(const std::string& tabs) const
{
  std::stringstream ss;
  boost::posix_time::ptime time_epoch(boost::gregorian::date(1970, 1, 1));
  boost::posix_time::ptime timestamp =
      time_epoch + boost::posix_time::milliseconds(m_Timestamp);
  ss << "RouterInfo: " << std::endl
     << m_RouterIdentity.GetDescription(tabs + "\t") << tabs
     << "\tPublished: " << boost::posix_time::to_simple_string(timestamp)
     << std::endl
     << tabs << "\tOptions(" << m_Options.size() << "): " << std::endl;
  for (const auto& opt : m_Options)
    ss << tabs << "\t\t[" << opt.first << "] : [" << opt.second << "]" << std::endl;
  ss << tabs << "\tSSU Caps: ["
     << (HasCap(Cap::SSUTesting) ? GetTrait(CapFlag::SSUTesting)
                                 : GetTrait(CapFlag::Unknown))
     << (HasCap(Cap::SSUIntroducer) ? GetTrait(CapFlag::SSUIntroducer)
                                    : GetTrait(CapFlag::Unknown))
     << "]" << std::endl;
  ss << tabs << "\tAddresses(" << m_Addresses.size() << "): " << std::endl;
  for (const auto& address : m_Addresses)
    ss << GetDescription(address, tabs + "\t\t");
  return ss.str();
}

}  // namespace core
}  // namespace kovri
