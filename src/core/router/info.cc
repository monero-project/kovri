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
std::string RouterInfo::Introducer::GetDescription(
    const std::string& tabs) const
{
  std::stringstream ss;
  ss << tabs << "Host: " << host.to_string() << std::endl
     << tabs << "Port: " << port << std::endl
     << tabs << "Key: " << key.ToBase64() << std::endl
     << tabs << "Tag: " << tag;
  return ss.str();
}

// TODO(unassigned): though this was originally intended for the kovri utility binary,
//  we can expand reporting to include remaining POD types of the Address struct
std::string RouterInfo::Address::GetDescription(const std::string& tabs) const
{
  std::stringstream ss;
  ss << tabs << "Type: ";
  switch (transport_style)
    {
      case Transport::NTCP:
        ss << "NTCP";
        break;
      case Transport::SSU:
        ss << "SSU";
        break;
      case Transport::Unknown:
        ss << "Unknown";
        return ss.str();
    }
  ss << std::endl
     << tabs << "\tCost: " << static_cast<int>(cost) << std::endl
     << tabs << "\tHost: " << host.to_string() << std::endl
     << tabs << "\tPort: " << port << std::endl;
  if (transport_style == Transport::SSU)
    {
      ss << tabs << "\tIntroducers (" << introducers.size() << ")" << std::endl;
      for (const Introducer& introducer : introducers)
        ss << introducer.GetDescription(tabs + "\t\t") << std::endl;
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
  m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
  memcpy(m_Buffer.get(), buf, len);
  m_BufferLen = len;
  ReadFromBuffer(true);
}

RouterInfo::~RouterInfo() {}

void RouterInfo::Update(
    const std::uint8_t* buf,
    int len) {
  if (!m_Buffer)
    m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
  m_IsUpdated = true;
  m_IsUnreachable = false;
  m_SupportedTransports = 0;
  m_Caps = 0;
  m_Addresses.clear();
  m_Properties.clear();
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
    if (m_BufferLen < 40) {
      LOG(error) << "RouterInfo: file" << m_FullPath << " is malformed";
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
  if (LoadFile())
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

      // Read cost + data
      stream.Read(&address.cost, sizeof(address.cost));
      stream.Read(&address.date, sizeof(address.date));

      // Read/set transport
      std::string transport(stream.ReadStringFromByte());
      switch (GetTrait(transport))
        {
          case Trait::NTCP:
            address.transport_style = Transport::NTCP;
            break;
          case Trait::SSU:
            address.transport_style = Transport::SSU;
            break;
          default:
            address.transport_style = Transport::Unknown;
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
                      switch (address.transport_style)
                        {
		          case Transport::NTCP:
                            // NTCP will (should be) resolved in transports
                            // TODO(unassigned): refactor. Though we will resolve host later, assigning values upon error is simply confusing.
                            m_SupportedTransports |= SupportedTransport::NTCPv4;
                            address.address_string = value;
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
                        (address.transport_style == Transport::NTCP)
                            ? SupportedTransport::NTCPv4
                            : SupportedTransport::SSUv4;
                  else
                    m_SupportedTransports |=
                        (address.transport_style == Transport::NTCP)
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
                ExtractCaps(value.c_str());
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
      LOG(debug) << address.GetDescription();
      if (is_valid_address)
        m_Addresses.push_back(address);
    }

  // Read peers
  // TODO(unassigned): handle peers
  std::uint8_t num_peers;
  stream.Read(&num_peers, sizeof(num_peers));
  stream.Seekg(num_peers * 32, std::ios_base::cur);

  // Read remaining properties
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

      // Set property
      SetProperty(key, value);

      // Set capabilities
      // TODO(anonimal): review setter implementation
      if (key == GetTrait(Trait::Caps))
        ExtractCaps(value.c_str());
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

// TODO(anonimal): rename as setter
void RouterInfo::ExtractCaps(
    const char* value) {
  const char* cap = value;
  while (*cap) {
    switch (*cap) {
      case CAPS_FLAG_FLOODFILL:
        m_Caps |= Caps::Floodfill;
        break;
      case CAPS_FLAG_UNLIMITED_BANDWIDTH:
        m_Caps |= Caps::UnlimitedBandwidth;
        break;
      case CAPS_FLAG_HIGH_BANDWIDTH1:
      case CAPS_FLAG_HIGH_BANDWIDTH2:
      case CAPS_FLAG_HIGH_BANDWIDTH3:
      case CAPS_FLAG_HIGH_BANDWIDTH4:
        m_Caps |= Caps::HighBandwidth;
        break;
      case CAPS_FLAG_HIDDEN:
        m_Caps |= Caps::Hidden;
        break;
      case CAPS_FLAG_REACHABLE:
        m_Caps |= Caps::Reachable;
        break;
      case CAPS_FLAG_UNREACHABLE:
        m_Caps |= Caps::Unreachable;
        break;
      case CAPS_FLAG_SSU_TESTING:
        m_Caps |= Caps::SSUTesting;
        break;
      case CAPS_FLAG_SSU_INTRODUCER:
        m_Caps |= Caps::SSUIntroducer;
        break;
      default: {}
    }
    cap++;
  }
}

void RouterInfo::UpdateCapsProperty() {
  std::string caps;
  if (m_Caps & Caps::Floodfill) {
    caps += CAPS_FLAG_HIGH_BANDWIDTH4;  // highest bandwidth
    caps += CAPS_FLAG_FLOODFILL;  // floodfill
  } else {
    caps += (m_Caps & Caps::HighBandwidth) ?
      CAPS_FLAG_HIGH_BANDWIDTH3 :
      CAPS_FLAG_LOW_BANDWIDTH2;  // bandwidth
  }
  if (m_Caps & Caps::Hidden) caps += CAPS_FLAG_HIDDEN;  // hidden
  if (m_Caps & Caps::Reachable) caps += CAPS_FLAG_REACHABLE;  // reachable
  if (m_Caps & Caps::Unreachable) caps += CAPS_FLAG_UNREACHABLE;  // unreachable
  SetProperty("caps", caps);
}

void RouterInfo::WriteToStream(
    std::ostream& s) {
  std::uint64_t ts = htobe64(m_Timestamp);
  s.write(reinterpret_cast<char *>(&ts), sizeof(ts));
  // addresses
  std::uint8_t num_addresses = m_Addresses.size();
  s.write(reinterpret_cast<char *>(&num_addresses), sizeof(num_addresses));
  for (auto& address : m_Addresses) {
    s.write(reinterpret_cast<char *>(&address.cost), sizeof(address.cost));
    s.write(reinterpret_cast<char *>(&address.date), sizeof(address.date));
    std::stringstream properties;
    if (address.transport_style == Transport::NTCP) {
      WriteString("NTCP", s);
    } else if (address.transport_style == Transport::SSU) {
      WriteString("SSU", s);
      // caps
      WriteString("caps", properties);
      properties << '=';
      std::string caps;
      if (IsPeerTesting())
        caps += CAPS_FLAG_SSU_TESTING;
      if (IsIntroducer())
        caps += CAPS_FLAG_SSU_INTRODUCER;
      WriteString(caps, properties);
      properties << ';';
    } else {
      WriteString("", s);
    }
    WriteString("host", properties);
    properties << '=';
    WriteString(address.host.to_string(), properties);
    properties << ';';
    if (address.transport_style == Transport::SSU) {
      // write introducers if any
      if (address.introducers.size() > 0) {
        int i = 0;
        for (auto introducer : address.introducers) {
          WriteString(
              "ihost" + boost::lexical_cast<std::string>(i),
              properties);
          properties << '=';
          WriteString(
              introducer.host.to_string(),
              properties);
          properties << ';';
          i++;
        }
        i = 0;
        for (auto introducer : address.introducers) {
          WriteString("ikey" + boost::lexical_cast<std::string>(i), properties);
          properties << '=';
          char value[64];
          std::size_t len =
            kovri::core::ByteStreamToBase64(introducer.key, 32, value, 64);
          value[len] = 0;
          WriteString(value, properties);
          properties << ';';
          i++;
        }
        i = 0;
        for (auto introducer : address.introducers) {
          WriteString(
              "iport" + boost::lexical_cast<std::string>(i),
              properties);
          properties << '=';
          WriteString(
              boost::lexical_cast<std::string>(introducer.port),
              properties);
          properties << ';';
          i++;
        }
        i = 0;
        for (auto introducer : address.introducers) {
          WriteString(
              "itag" + boost::lexical_cast<std::string>(i),
              properties);
          properties << '=';
          WriteString(
              boost::lexical_cast<std::string>(introducer.tag),
              properties);
          properties << ';';
          i++;
        }
      }
      // write intro key
      WriteString("key", properties);
      properties << '=';
      char value[64];
      std::size_t len = kovri::core::ByteStreamToBase64(address.key, 32, value, 64);
      value[len] = 0;
      WriteString(value, properties);
      properties << ';';
      // write mtu
      if (address.mtu) {
        WriteString("mtu", properties);
        properties << '=';
        WriteString(boost::lexical_cast<std::string>(address.mtu), properties);
        properties << ';';
      }
    }
    WriteString("port", properties);
    properties << '=';
    WriteString(boost::lexical_cast<std::string>(address.port), properties);
    properties << ';';
    std::uint16_t size = htobe16(properties.str().size());
    s.write(reinterpret_cast<char *>(&size), sizeof(size));
    s.write(properties.str().c_str(), properties.str().size());
  }
  // peers
  std::uint8_t num_peers = 0;
  s.write(reinterpret_cast<char *>(&num_peers), sizeof(num_peers));
  // properties
  std::stringstream properties;
  for (auto& p : m_Properties) {
    WriteString(p.first, properties);
    properties << '=';
    WriteString(p.second, properties);
    properties << ';';
  }
  std::uint16_t size = htobe16(properties.str().size());
  s.write(reinterpret_cast<char *>(&size), sizeof(size));
  s.write(properties.str().c_str(), properties.str().size());
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

void RouterInfo::CreateBuffer(const PrivateKeys& privateKeys) {
  m_Timestamp = kovri::core::GetMillisecondsSinceEpoch();  // refresh timestamp
  std::stringstream s;
  std::uint8_t ident[1024];
  auto ident_len = privateKeys.GetPublic().ToBuffer(ident, 1024);
  s.write(reinterpret_cast<char *>(ident), ident_len);
  WriteToStream(s);
  m_BufferLen = s.str().size();
  if (!m_Buffer)
    m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
  memcpy(m_Buffer.get(), s.str().c_str(), m_BufferLen);
  // signature
  privateKeys.Sign(
    reinterpret_cast<std::uint8_t *>(m_Buffer.get()),
    m_BufferLen,
    reinterpret_cast<std::uint8_t *>(m_Buffer.get()) + m_BufferLen);
  m_BufferLen += privateKeys.GetPublic().GetSignatureLen();
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

void RouterInfo::WriteString(
    const std::string& str,
    std::ostream& s) {
  std::uint8_t len = str.size();
  s.write(reinterpret_cast<char *>(&len), 1);
  s.write(str.c_str(), len);
}

void RouterInfo::AddNTCPAddress(
    const std::string& host,
    std::uint16_t port) {
  Address addr;
  addr.host = boost::asio::ip::address::from_string(host);
  addr.port = port;
  addr.transport_style = Transport::NTCP;
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
  addr.transport_style = Transport::SSU;
  addr.cost = 5;
  addr.date = 0;
  addr.mtu = mtu;
  memcpy(addr.key, key, 32);
  m_Addresses.push_back(addr);
  m_SupportedTransports |=
      addr.host.is_v6() ? SupportedTransport::SSUv6 : SupportedTransport::SSUv4;
  m_Caps |= Caps::SSUTesting;
  m_Caps |= Caps::SSUIntroducer;
}

bool RouterInfo::AddIntroducer(
    const Address* address,
    std::uint32_t tag) {
  for (auto& addr : m_Addresses) {
    if (addr.transport_style == Transport::SSU && addr.host.is_v4()) {
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
    if (addr.transport_style == Transport::SSU && addr.host.is_v4()) {
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

void RouterInfo::SetCaps(
    std::uint8_t caps) {
  m_Caps = caps;
  UpdateCapsProperty();
}

// TODO(anonimal): refactor this setter, it should be simpler
void RouterInfo::SetCaps(
    const char* caps) {
  SetProperty("caps", caps);
  m_Caps = 0;
  ExtractCaps(caps);
}

void RouterInfo::SetProperty(
    const std::string& key,
    const std::string& value) {
  m_Properties[key] = value;
}

void RouterInfo::DeleteProperty(
    const std::string& key) {
  m_Properties.erase(key);
}

bool RouterInfo::IsFloodfill() const {
  return m_Caps & Caps::Floodfill;
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
      if (m_Addresses[i].transport_style ==
          core::RouterInfo::Transport::NTCP &&
          m_Addresses[i].host.is_v6()) {
        m_Addresses.erase(m_Addresses.begin() + i);
        break;
      }
    }
    // SSU
    m_SupportedTransports &= ~SupportedTransport::SSUv6;
    for (std::size_t i = 0; i < m_Addresses.size(); i++) {
      if (m_Addresses[i].transport_style ==
          Transport::SSU &&
          m_Addresses[i].host.is_v6()) {
        m_Addresses.erase(m_Addresses.begin() + i);
        break;
      }
    }
  }
}

bool RouterInfo::UsesIntroducer() const {
  return m_Caps & Caps::Unreachable;  // non-reachable
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
    if (address.transport_style == s) {
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

std::string RouterInfo::GetDescription(const std::string& tabs) const
{
  std::stringstream ss;
  boost::posix_time::ptime time_epoch(boost::gregorian::date(1970, 1, 1));
  boost::posix_time::ptime timestamp =
      time_epoch + boost::posix_time::milliseconds(m_Timestamp);
  ss << "RouterInfo: " << std::endl
     << m_RouterIdentity.GetDescription(tabs + "\t") << tabs
     << "\tPublished: " << boost::posix_time::to_simple_string(timestamp)
     << std::endl
     << tabs << "\tOptions(" << m_Properties.size() << "): " << std::endl;
  for (const auto& p : m_Properties)
    ss << tabs << "\t\t[" << p.first << "] : [" << p.second << "]" << std::endl;
  ss << tabs << "\tSSU Caps: ["
     << (IsPeerTesting() ? CAPS_FLAG_SSU_TESTING : ' ')
     << (IsIntroducer() ? CAPS_FLAG_SSU_INTRODUCER : ' ') << "]" << std::endl;
  ss << tabs << "\tAddresses(" << m_Addresses.size() << "): " << std::endl;
  for (const auto& a : m_Addresses)
    ss << a.GetDescription(tabs + "\t\t");
  return ss.str();
}

}  // namespace core
}  // namespace kovri
