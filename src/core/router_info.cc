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

#include "router_info.h"

#include <boost/lexical_cast.hpp>

#include <stdio.h>
#include <string.h>

#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "router_context.h"
#include "util/base64.h"
#include "util/i2p_endian.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace data {

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
    const uint8_t* buf,
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
    const uint8_t* buf,
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
  m_Timestamp = i2p::util::GetMillisecondsSinceEpoch();
}

bool RouterInfo::LoadFile() {
  std::ifstream s(m_FullPath.c_str(), std::ifstream::binary);
  if (s.is_open()) {
    s.seekg(0, std::ios::end);
    m_BufferLen = s.tellg();
    if (m_BufferLen < 40) {
      LogPrint(eLogError, "RouterInfo: file", m_FullPath, " is malformed");
      return false;
    }
    s.seekg(0, std::ios::beg);
    if (!m_Buffer)
      m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
    s.read(reinterpret_cast<char *>(m_Buffer.get()), m_BufferLen);
  } else {
    LogPrint(eLogError, "RouterInfo: can't open file ", m_FullPath);
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
  size_t identity_len = m_RouterIdentity.FromBuffer(m_Buffer.get(), m_BufferLen);
  std::stringstream str(
      std::string(
        reinterpret_cast<char *>(m_Buffer.get()) + identity_len,
        m_BufferLen - identity_len));
  ReadFromStream(str);
  if (verify_signature) {
    // verify signature
    int len = m_BufferLen - m_RouterIdentity.GetSignatureLen();
    if (!m_RouterIdentity.Verify(
          reinterpret_cast<uint8_t *>(m_Buffer.get()),
          len,
          reinterpret_cast<uint8_t *>(m_Buffer.get() + len))) {
      LogPrint(eLogError, "RouterInfo: signature verification failed");
      m_IsUnreachable = true;
    }
    m_RouterIdentity.DropVerifier();
  }
}

void RouterInfo::ReadFromStream(
    std::istream& s) {
  s.read(reinterpret_cast<char *>(&m_Timestamp), sizeof(m_Timestamp));
  m_Timestamp = be64toh(m_Timestamp);
  // read addresses
  uint8_t num_addresses;
  s.read(reinterpret_cast<char *>(&num_addresses), sizeof(num_addresses));
  bool introducers = false;
  for (int i = 0; i < num_addresses; i++) {
    bool is_valid_address = true;
    Address address;
    s.read(reinterpret_cast<char *>(&address.cost), sizeof(address.cost));
    s.read(reinterpret_cast<char *>(&address.date), sizeof(address.date));
    char transport_style[5];
    ReadString(transport_style, s);
    if (!strcmp(transport_style, "NTCP"))
      address.transport_style = eTransportNTCP;
    else if (!strcmp(transport_style, "SSU"))
      address.transport_style = eTransportSSU;
    else
      address.transport_style = eTransportUnknown;
    address.port = 0;
    address.mtu = 0;
    uint16_t size, r = 0;
    s.read(reinterpret_cast<char *>(&size), sizeof(size));
    size = be16toh(size);
    while (r < size) {
      char key[500], value[500];
      r += ReadString(key, s);
      s.seekg(1, std::ios_base::cur);
      r++;  // =
      r += ReadString(value, s);
      s.seekg(1, std::ios_base::cur);
      r++;  // ;
      if (!strcmp(key, "host")) {
        boost::system::error_code ecode;
        address.host = boost::asio::ip::address::from_string(value, ecode);
        if (ecode) {  // no error
          if (address.transport_style == eTransportNTCP) {
            m_SupportedTransports |= eNTCPV4;  // TODO(unassigned): ???
            address.address_string = value;
          } else {
            // TODO(unassigned): resolve address for SSU
            LogPrint(eLogWarn, "RouterInfo: unexpected SSU address ", value);
            is_valid_address = false;
          }
        } else {
          // add supported protocol
          if (address.host.is_v4())
            m_SupportedTransports |=
              (address.transport_style == eTransportNTCP) ? eNTCPV4 : eSSUV4;
          else
            m_SupportedTransports |=
              (address.transport_style == eTransportNTCP) ? eNTCPV6 : eSSUV6;
        }
      } else if (!strcmp(key, "port")) {
        address.port = boost::lexical_cast<int>(value);
      } else if (!strcmp(key, "mtu")) {
        address.mtu = boost::lexical_cast<int>(value);
      } else if (!strcmp(key, "key")) {
        i2p::util::Base64ToByteStream(value, strlen(value), address.key, 32);
      } else if (!strcmp(key, "caps")) {
        ExtractCaps(value);
      } else if (key[0] == 'i') {
        // introducers
        introducers = true;
        size_t len = strlen(key);
        unsigned char index = key[len - 1] - '0';  // TODO(unassigned): ???
        key[len - 1] = 0;
        if (index >= address.introducers.size())
          address.introducers.resize(index + 1);
        Introducer& introducer = address.introducers.at(index);
        if (!strcmp(key, "ihost")) {
          boost::system::error_code ecode;
          introducer.host =
            boost::asio::ip::address::from_string(value, ecode);
        } else if (!strcmp(key, "iport")) {
          introducer.port = boost::lexical_cast<int>(value);
        } else if (!strcmp(key, "itag")) {
          introducer.tag = boost::lexical_cast<uint32_t>(value);
        } else if (!strcmp(key, "ikey")) {
          i2p::util::Base64ToByteStream(
              value,
              strlen(value),
              introducer.key,
              32);
        }
      }
    }
    if (is_valid_address)
      m_Addresses.push_back(address);
  }
  // read peers
  uint8_t num_peers;
  s.read(reinterpret_cast<char *>(&num_peers), sizeof(num_peers));
  s.seekg(num_peers*32, std::ios_base::cur);  // TODO(unassigned): read peers
  // read properties
  uint16_t size, r = 0;
  s.read(reinterpret_cast<char *>(&size), sizeof(size));
  size = be16toh(size);
  while (r < size) {
#ifdef _WIN32
    char key[500], value[500];
    // TODO(unassigned): investigate why properties get read as one
    // long string under Windows. Length should not be more than 44.
#else
    char key[50], value[50];
#endif
    r += ReadString(key, s);
    s.seekg(1, std::ios_base::cur);
    r++;  // =
    r += ReadString(value, s);
    s.seekg(1, std::ios_base::cur);
    r++;  // ;
    m_Properties[key] = value;
    // extract caps
    if (!strcmp(key, "caps"))
      ExtractCaps(value);
  }
  if (!m_SupportedTransports || !m_Addresses.size() ||
      (UsesIntroducer() && !introducers))
    SetUnreachable(true);
}

void RouterInfo::ExtractCaps(
    const char* value) {
  const char* cap = value;
  while (*cap) {
    switch (*cap) {
      case CAPS_FLAG_FLOODFILL:
        m_Caps |= Caps::eFloodfill;
      break;
      case CAPS_FLAG_UNLIMITED_BANDWIDTH:
        m_Caps |= Caps::eUnlimitedBandwidth;
      case CAPS_FLAG_HIGH_BANDWIDTH1:
      case CAPS_FLAG_HIGH_BANDWIDTH2:
      case CAPS_FLAG_HIGH_BANDWIDTH3:
      case CAPS_FLAG_HIGH_BANDWIDTH4:
        m_Caps |= Caps::eHighBandwidth;
      break;
      case CAPS_FLAG_HIDDEN:
        m_Caps |= Caps::eHidden;
      break;
      case CAPS_FLAG_REACHABLE:
        m_Caps |= Caps::eReachable;
      break;
      case CAPS_FLAG_UNREACHABLE:
        m_Caps |= Caps::eUnreachable;
      break;
      case CAPS_FLAG_SSU_TESTING:
        m_Caps |= Caps::eSSUTesting;
      break;
      case CAPS_FLAG_SSU_INTRODUCER:
        m_Caps |= Caps::eSSUIntroducer;
      break;
      default: {}
    }
    cap++;
  }
}

void RouterInfo::UpdateCapsProperty() {
  std::string caps;
  if (m_Caps & eFloodfill) {
    caps += CAPS_FLAG_HIGH_BANDWIDTH4;  // highest bandwidth
    caps += CAPS_FLAG_FLOODFILL;  // floodfill
  } else {
    caps += (m_Caps & eHighBandwidth) ?
      CAPS_FLAG_HIGH_BANDWIDTH3 :
      CAPS_FLAG_LOW_BANDWIDTH2;  // bandwidth
  }
  if (m_Caps & eHidden) caps += CAPS_FLAG_HIDDEN;  // hidden
  if (m_Caps & eReachable) caps += CAPS_FLAG_REACHABLE;  // reachable
  if (m_Caps & eUnreachable) caps += CAPS_FLAG_UNREACHABLE;  // unreachable
  SetProperty("caps", caps);
}

void RouterInfo::WriteToStream(
    std::ostream& s) {
  uint64_t ts = htobe64(m_Timestamp);
  s.write(reinterpret_cast<char *>(&ts), sizeof(ts));
  // addresses
  uint8_t num_addresses = m_Addresses.size();
  s.write(reinterpret_cast<char *>(&num_addresses), sizeof(num_addresses));
  for (auto& address : m_Addresses) {
    s.write(reinterpret_cast<char *>(&address.cost), sizeof(address.cost));
    s.write(reinterpret_cast<char *>(&address.date), sizeof(address.date));
    std::stringstream properties;
    if (address.transport_style == eTransportNTCP) {
      WriteString("NTCP", s);
    } else if (address.transport_style == eTransportSSU) {
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
    if (address.transport_style == eTransportSSU) {
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
          size_t len =
            i2p::util::ByteStreamToBase64(introducer.key, 32, value, 64);
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
      size_t len = i2p::util::ByteStreamToBase64(address.key, 32, value, 64);
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
    uint16_t size = htobe16(properties.str().size());
    s.write(reinterpret_cast<char *>(&size), sizeof(size));
    s.write(properties.str().c_str(), properties.str().size());
  }
  // peers
  uint8_t num_peers = 0;
  s.write(reinterpret_cast<char *>(&num_peers), sizeof(num_peers));
  // properties
  std::stringstream properties;
  for (auto& p : m_Properties) {
    WriteString(p.first, properties);
    properties << '=';
    WriteString(p.second, properties);
    properties << ';';
  }
  uint16_t size = htobe16(properties.str().size());
  s.write(reinterpret_cast<char *>(&size), sizeof(size));
  s.write(properties.str().c_str(), properties.str().size());
}

const uint8_t* RouterInfo::LoadBuffer() {
  if (!m_Buffer) {
    if (LoadFile())
      LogPrint(eLogInfo,
          "RouterInfo: buffer for ",
          GetIdentHashAbbreviation(), " loaded from file");
  }
  return m_Buffer.get();
}

void RouterInfo::CreateBuffer(const PrivateKeys& privateKeys) {
  m_Timestamp = i2p::util::GetMillisecondsSinceEpoch();  // refresh timestamp
  std::stringstream s;
  uint8_t ident[1024];
  auto ident_len = privateKeys.GetPublic().ToBuffer(ident, 1024);
  s.write(reinterpret_cast<char *>(ident), ident_len);
  WriteToStream(s);
  m_BufferLen = s.str().size();
  if (!m_Buffer)
    m_Buffer = std::make_unique<std::uint8_t[]>(MAX_RI_BUFFER_SIZE);
  memcpy(m_Buffer.get(), s.str().c_str(), m_BufferLen);
  // signature
  privateKeys.Sign(
    reinterpret_cast<uint8_t *>(m_Buffer.get()),
    m_BufferLen,
    reinterpret_cast<uint8_t *>(m_Buffer.get()) + m_BufferLen);
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
      LogPrint(eLogError, "RouterInfo: can't save RouterInfo to ", full_path);
  } else {
    LogPrint(eLogError, "RouterInfo: can't save RouterInfo, buffer is empty");
  }
}

size_t RouterInfo::ReadString(
    char* str,
    std::istream& s) {
  uint8_t len;
  s.read(reinterpret_cast<char *>(&len), 1);
  s.read(str, len);
  str[len] = 0;
  return len+1;
}

void RouterInfo::WriteString(
    const std::string& str,
    std::ostream& s) {
  uint8_t len = str.size();
  s.write(reinterpret_cast<char *>(&len), 1);
  s.write(str.c_str(), len);
}

void RouterInfo::AddNTCPAddress(
    const std::string& host,
    int port) {
  Address addr;
  addr.host = boost::asio::ip::address::from_string(host);
  addr.port = port;
  addr.transport_style = eTransportNTCP;
  addr.cost = 10;  // NTCP should have priority over SSU
  addr.date = 0;
  addr.mtu = 0;
  m_Addresses.push_back(addr);
  m_SupportedTransports |= addr.host.is_v6() ? eNTCPV6 : eNTCPV4;
}

void RouterInfo::AddSSUAddress(
    const std::string& host,
    int port,
    const uint8_t* key,
    int mtu) {
  Address addr;
  addr.host = boost::asio::ip::address::from_string(host);
  addr.port = port;
  addr.transport_style = eTransportSSU;
  addr.cost = 5;
  addr.date = 0;
  addr.mtu = mtu;
  memcpy(addr.key, key, 32);
  m_Addresses.push_back(addr);
  m_SupportedTransports |= addr.host.is_v6() ? eSSUV6 : eSSUV4;
  m_Caps |= eSSUTesting;
  m_Caps |= eSSUIntroducer;
}

bool RouterInfo::AddIntroducer(
    const Address* address,
    uint32_t tag) {
  for (auto& addr : m_Addresses) {
    if (addr.transport_style == eTransportSSU && addr.host.is_v4()) {
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
    if (addr.transport_style == eTransportSSU && addr.host.is_v4()) {
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
    uint8_t caps) {
  m_Caps = caps;
  UpdateCapsProperty();
}

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
  return m_Caps & Caps::eFloodfill;
}

bool RouterInfo::IsNTCP(
    bool v4only) const {
  if (v4only)
    return m_SupportedTransports & eNTCPV4;
  else
    return m_SupportedTransports & (eNTCPV4 | eNTCPV6);
}

bool RouterInfo::IsSSU(
    bool v4only) const {
  if (v4only)
    return m_SupportedTransports & eSSUV4;
  else
    return m_SupportedTransports & (eSSUV4 | eSSUV6);
}

bool RouterInfo::IsV6() const {
  return m_SupportedTransports & (eNTCPV6 | eSSUV6);
}

void RouterInfo::EnableV6() {
  if (!IsV6())
    m_SupportedTransports |= eNTCPV6 | eSSUV6;
}

void RouterInfo::DisableV6() {
  if (IsV6()) {
    // NTCP
    m_SupportedTransports &= ~eNTCPV6;
    for (size_t i = 0; i < m_Addresses.size(); i++) {
      if (m_Addresses[i].transport_style ==
          i2p::data::RouterInfo::eTransportNTCP &&
          m_Addresses[i].host.is_v6()) {
        m_Addresses.erase(m_Addresses.begin() + i);
        break;
      }
    }
    // SSU
    m_SupportedTransports &= ~eSSUV6;
    for (size_t i = 0; i < m_Addresses.size(); i++) {
      if (m_Addresses[i].transport_style ==
          i2p::data::RouterInfo::eTransportSSU &&
          m_Addresses[i].host.is_v6()) {
        m_Addresses.erase(m_Addresses.begin() + i);
        break;
      }
    }
  }
}

bool RouterInfo::UsesIntroducer() const {
  return m_Caps & Caps::eUnreachable;  // non-reachable
}

const RouterInfo::Address* RouterInfo::GetNTCPAddress(
    bool v4only) const {
  return GetAddress(eTransportNTCP, v4only);
}

const RouterInfo::Address* RouterInfo::GetSSUAddress(
    bool v4only) const {
  return GetAddress(eTransportSSU, v4only);
}

const RouterInfo::Address* RouterInfo::GetSSUV6Address() const {
  return GetAddress(eTransportSSU, false, true);
}

const RouterInfo::Address* RouterInfo::GetAddress(
    TransportStyle s,
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

}  // namespace data
}  // namespace i2p
