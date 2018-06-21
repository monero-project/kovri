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

#include "core/router/info.h"

#include <boost/lexical_cast.hpp>
#include <boost/endian/conversion.hpp>

#include <cstring>
#include <fstream>
#include <tuple>

#include "core/crypto/radix.h"

#include "core/router/context.h"

#include "core/util/filesystem.h"
#include "core/util/log.h"
#include "core/util/timestamp.h"

#include "version.h"

namespace kovri
{
namespace core
{

RouterInfo::RouterInfo() : m_Exception(__func__), m_Buffer(nullptr)  // TODO(anonimal): buffer refactor
{
}

RouterInfo::RouterInfo(
    const core::PrivateKeys& keys,
    const std::vector<std::pair<std::string, std::uint16_t>>& points,
    const std::pair<bool, bool>& has_transport,
    const std::uint8_t caps)
    : m_Exception(__func__), m_RouterIdentity(keys.GetPublic())
{
  // Reject non-EdDSA signing keys, see #498 and spec
  if (m_RouterIdentity.GetSigningKeyType()
      != core::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519)
    throw std::invalid_argument("RouterInfo: invalid signing key type");

  // Reject empty addresses
  if (points.empty())
    throw std::invalid_argument("RouterInfo: no transport address(es)");

  // Reject routers with NTCP & SSU disabled
  if (!has_transport.first && !has_transport.second)
    throw std::invalid_argument("RouterInfo: no supported transports");

  // Log our identity
  const IdentHash& hash = m_RouterIdentity.GetIdentHash();
  LOG(info) << "RouterInfo: our router's ident: " << m_RouterIdentity.ToBase64();
  LOG(info) << "RouterInfo: our router's ident hash: " << hash.ToBase64();

  // Set default caps
  SetCaps(caps);

  for (const auto& point : points)
    {
      // Set default transports
      if (has_transport.first)
        AddAddress(std::make_tuple(Transport::NTCP, point.first, point.second));

      if (has_transport.second)
        AddAddress(
            std::make_tuple(Transport::SSU, point.first, point.second), hash);
    }

  if (has_transport.second)
    {
      SetCaps(
          m_Caps | core::RouterInfo::Cap::SSUTesting
          | core::RouterInfo::Cap::SSUIntroducer);
    }

  // Set default options
  SetDefaultOptions();

  // Set RI buffer + create RI
  CreateBuffer(keys);
}

RouterInfo::RouterInfo(const std::string& path)
    : m_Exception(__func__),
      m_Path(path),
      m_Buffer(std::make_unique<std::uint8_t[]>(Size::MaxBuffer))  // TODO(anonimal): buffer refactor
{
  ReadFromFile();
  ReadFromBuffer(false);
}

RouterInfo::RouterInfo(const std::uint8_t* buf, std::uint16_t len)
    : m_Exception(__func__),
      m_Buffer(std::make_unique<std::uint8_t[]>(Size::MaxBuffer)),  // TODO(anonimal): buffer refactor
      m_BufferLen(len)
{
  if (!buf)
    throw std::invalid_argument("RouterInfo: null buffer");
  if (len < Size::MinBuffer || len > Size::MaxBuffer)
    throw std::length_error("RouterInfo: invalid buffer length");
  std::memcpy(m_Buffer.get(), buf, len);
  ReadFromBuffer(true);
  m_IsUpdated = true;
}

RouterInfo::~RouterInfo()
{
}

void RouterInfo::ReadFromFile()
{
  try
    {
      core::InputFileStream stream(m_Path.c_str(), std::ifstream::binary);
      if (stream.Fail())
        throw std::runtime_error("can't open file " + m_Path);

      // Get full length of stream
      stream.Seekg(0, std::ios::end);
      m_BufferLen = stream.Tellg();
      if (m_BufferLen < Size::MinBuffer || m_BufferLen > Size::MaxBuffer)
        {
          LOG(error) << "RouterInfo: buffer length = " << m_BufferLen;
          throw std::runtime_error(m_Path + " is malformed");
        }

      // Read in complete length of stream
      stream.Seekg(0, std::ios::beg);
      if (!m_Buffer)
        m_Buffer = std::make_unique<std::uint8_t[]>(Size::MaxBuffer);
      stream.Read(m_Buffer.get(), m_BufferLen);
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }
}

void RouterInfo::ReadFromBuffer(bool verify_signature)
{
  try
    {
      // Get + verify identity length from existing RI in buffer
      std::size_t ident_len =
          m_RouterIdentity.FromBuffer(m_Buffer.get(), m_BufferLen);
      if (!ident_len)
        throw std::length_error("null ident length");

      // Parse existing RI from buffer
      std::string router_info(
          reinterpret_cast<char*>(m_Buffer.get()) + ident_len,
          m_BufferLen - ident_len);

      ParseRouterInfo(router_info);

      // Verify signature
      if (verify_signature)
        {
          // Note: signature length is guaranteed to be no less than buffer length
          std::uint16_t len = m_BufferLen - m_RouterIdentity.GetSignatureLen();
          if (!m_RouterIdentity.Verify(
                  reinterpret_cast<std::uint8_t*>(m_Buffer.get()),
                  len,
                  reinterpret_cast<std::uint8_t*>(m_Buffer.get() + len)))
            {
              LOG(error) << "RouterInfo: signature verification failed";
              m_IsUnreachable = true;
            }
          m_RouterIdentity.DropVerifier();
        }
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
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
  boost::endian::big_to_native_inplace(m_Timestamp);
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
      boost::endian::big_to_native_inplace(given_size);

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
                            // fall-through
                          default:
                            is_valid_address = false;
                        }
                      break;
                    }
                  // Add supported transport
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
                {
                  // Our intro key as introducer
                  std::vector<std::uint8_t> key;
                  try
                    {
                      key = core::Base64::Decode(value.c_str(), value.size());
                    }
                  catch (...)
                    {
                      m_Exception.Dispatch("RouterInfo: invalid intro key trait");
                      is_valid_address = false;
                    }

                  //TODO(anonimal): let's try to avoid a memcpy
                  std::memcpy(address.key, key.data(), sizeof(address.key));
                  break;
                }
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
                            boost::system::error_code ecode;
                            introducer.host =
                                boost::asio::ip::address::from_string(
                                    value, ecode);
                            // TODO(unassigned):
                            // Because unresolved hosts return EINVAL,
                            // and since we currently have no implementation to resolve introducer hosts,
                            // treat *all* errors as an invalid address.
                            if (ecode)
                              {
                                LOG(error) << "RouterInfo: " << __func__
                                           << ": introducer host error: '"
                                           << ecode.message() << "'";
                                is_valid_address = false;
                              }
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
                          {
                            std::vector<std::uint8_t> const decoded(
                                core::Base64::Decode(
                                    value.c_str(), value.size()));

                            //TODO(anonimal): let's try to avoid a memcpy
                            std::memcpy(
                                introducer.key,
                                decoded.data(),
                                sizeof(introducer.key));
                          }
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
  boost::endian::big_to_native_inplace(given_size);

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

void RouterInfo::SetDefaultOptions()
{
  SetOption(GetTrait(Trait::NetID), std::to_string(I2P_NETWORK_ID));
  SetOption(GetTrait(Trait::RouterVersion), I2P_VERSION);
  // TODO(anonimal): implement known lease-sets and known routers.
  //   We current only set default options when starting/creating RI *before*
  //   netdb starts. We'll need to ensure the 'known' opts are set *after* netdb starts.
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

void RouterInfo::AddAddress(
    const std::tuple<Transport, std::string, std::uint16_t>& point,
    const std::uint8_t* key,
    const std::uint16_t mtu)
{
  Address addr;
  addr.transport = std::get<0>(point);
  boost::system::error_code ec;
  addr.host = boost::asio::ip::address::from_string(std::get<1>(point), ec);
  if (ec)
    throw std::invalid_argument(
        "RouterInfo: " + std::string(__func__) + ": " + ec.message());
  addr.port = std::get<2>(point);
  if (addr.port < PortRange::MinPort || addr.port > PortRange::MaxPort)
    throw std::invalid_argument("RouterInfo: port not in valid range");
  addr.date = 0;  // TODO(anonimal): ?...

  // Set transport-specific
  switch (addr.transport)
    {
      case Transport::NTCP:
        {
          addr.cost = Size::NTCPCost;
          addr.mtu = 0;  // TODO(anonimal): ?...
          m_SupportedTransports |= addr.host.is_v6()
                                       ? SupportedTransport::NTCPv6
                                       : SupportedTransport::NTCPv4;
        }
        break;

      case Transport::SSU:
        {
          addr.cost = Size::SSUCost;
          addr.mtu = mtu;
          if (!key)
            throw std::runtime_error("RouterInfo: null SSU intro key");
          addr.key = key;
          m_SupportedTransports |= addr.host.is_v6()
                                       ? SupportedTransport::SSUv6
                                       : SupportedTransport::SSUv4;
          // Set our caps
          m_Caps |= Cap::SSUTesting | Cap::SSUIntroducer;
        }
        break;

      default:
        throw std::runtime_error(
            "RouterInfo: " + std::string(__func__) + ": unsupported transport");
        break;
    }

  // Save address
  m_Addresses.push_back(addr);
}

bool RouterInfo::AddIntroducer(const Address* address, std::uint32_t tag)
{
  for (auto& addr : m_Addresses)
    {
      // TODO(anonimal): IPv6 SSU introducers when we bump I2P version
      if (addr.transport == Transport::SSU && addr.host.is_v4())
        {
          for (auto intro : addr.introducers)
            if (intro.tag == tag)
              return false;  // already presented
          Introducer i;
          i.host = address->host;
          i.port = address->port;
          i.tag = tag;
          std::memcpy(
              i.key, address->key, 32);  // TODO(unassigned): replace to Tag<32>
          addr.introducers.push_back(i);
          return true;
        }
    }
  return false;
}

bool RouterInfo::RemoveIntroducer(
    const boost::asio::ip::udp::endpoint& endpoint)
{
  for (auto& addr : m_Addresses)
    {
      // TODO(anonimal): IPv6 SSU introducers when we bump I2P version
      if (addr.transport == Transport::SSU && addr.host.is_v4())
        {
          for (std::vector<Introducer>::iterator it = addr.introducers.begin();
               it != addr.introducers.end();
               it++)
            if (boost::asio::ip::udp::endpoint(it->host, it->port) == endpoint)
              {
                addr.introducers.erase(it);
                return true;
              }
        }
    }
  return false;
}

void RouterInfo::EnableV6()
{
  if (!HasV6())
    {
      LOG(debug) << "RouterInfo: " << __func__ << ": enabling IPv6";
      m_SupportedTransports |=
          SupportedTransport::NTCPv6 | SupportedTransport::SSUv6;
    }
}

// TODO(anonimal): this is currently useless because we
//  A) disable IPv6 by default on startup
//  B) if IPv6 is set at startup, we do not currently disable during run-time (could be used by API though)
void RouterInfo::DisableV6()
{
  // Test if RI supports V6
  if (!HasV6())
    return;

  // Disable V6 transports
  m_SupportedTransports &= ~SupportedTransport::NTCPv6;
  m_SupportedTransports &= ~SupportedTransport::SSUv6;

  // Remove addresses in question
  m_Addresses.erase(
      std::remove_if(
          std::begin(m_Addresses),
          std::end(m_Addresses),
          [](const auto& address) { return address.host.is_v6(); }),
      std::end(m_Addresses));
}

void RouterInfo::Update(const std::uint8_t* buf, std::uint16_t len)
{
  if (len < Size::MinBuffer || len > Size::MaxBuffer)
    throw std::length_error(
        "RouterInfo: " + std::string(__func__) + ": invalid buffer length");
  if (!m_Buffer)
    m_Buffer = std::make_unique<std::uint8_t[]>(Size::MaxBuffer);
  m_BufferLen = len;
  m_IsUpdated = true;
  m_IsUnreachable = false;
  m_SupportedTransports = 0;
  m_Caps = 0;
  m_Addresses.clear();
  m_Options.clear();
  std::memcpy(m_Buffer.get(), buf, len);
  ReadFromBuffer(true);
  // don't delete buffer until saved to file
}

const std::uint8_t* RouterInfo::LoadBuffer()
{
  if (!m_Buffer)
    {
      ReadFromFile();
      LOG(debug) << "RouterInfo: buffer for " << GetIdentHashAbbreviation()
                 << " loaded from file";
    }

  return m_Buffer.get();
}

void RouterInfo::CreateBuffer(const PrivateKeys& private_keys)
{
  try
    {
      // Create RI
      core::StringStream router_info;
      CreateRouterInfo(router_info, private_keys);
      if (router_info.Str().size() > Size::MaxBuffer)
        throw std::length_error("created RI is too big");

      // Create buffer
      m_BufferLen = router_info.Str().size();
      if (!m_Buffer)
        m_Buffer = std::make_unique<std::uint8_t[]>(Size::MaxBuffer);
      std::memcpy(m_Buffer.get(), router_info.Str().c_str(), m_BufferLen);
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }
}

bool RouterInfo::Verify()
{
  bool success = false;
  try
    {
      std::size_t len = m_BufferLen - m_RouterIdentity.GetSignatureLen();
      if (len < Size::MinUnsignedBuffer)
        throw std::length_error("RouterInfo: invalid RouterInfo size");
      success =
          m_RouterIdentity.Verify(m_Buffer.get(), len, m_Buffer.get() + len);
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }
  return success;
}

// TODO(anonimal): debug + trace logging
// TODO(anonimal): unit-test
void RouterInfo::CreateRouterInfo(
    core::StringStream& router_info,
    const PrivateKeys& private_keys)
{
  // TODO(anonimal): more useful logging
  LOG(debug) << "RouterInfo: " << __func__;

  // Write ident
  // Max size for ident with key certificate, see spec
  std::array<std::uint8_t, 391> ident {{}};
  auto ident_len =
      private_keys.GetPublic().ToBuffer(ident.data(), ident.size());
  router_info.Write(ident.data(), ident_len);

  // Set published timestamp
  SetTimestamp(core::GetMillisecondsSinceEpoch());

  // Write published timestamp
  std::uint64_t timestamp = boost::endian::native_to_big(GetTimestamp());
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
                  std::string const key(core::Base64::Encode(
                      introducer.key, sizeof(introducer.key)));
                  options.WriteKeyPair(GetTrait(Trait::IntroKey) + num, key);

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
          std::string const value(
              core::Base64::Encode(address.key, sizeof(address.key)));
          options.WriteKeyPair(GetTrait(Trait::Key), value);

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
      // TODO(anonimal): there is no spec-defined size limit, but we need 2 bytes...
      std::uint16_t size = options.Str().size();
      boost::endian::native_to_big_inplace(size);
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
    {
      LOG(debug) << "RouterInfo: writing: " << opt.first << "=" << opt.second;
      options.WriteKeyPair(opt.first, opt.second);
    }

  // Write size of remaining options
  // TODO(anonimal): there is no spec-defined size limit, but we need 2 bytes...
  std::uint16_t size = options.Str().size();
  boost::endian::native_to_big_inplace(size);
  router_info.Write(&size, sizeof(size));

  // Write remaining options to RI
  router_info.Write(options.Str().c_str(), options.Str().size());

  // Ensure signature has proper capacity
  std::vector<std::uint8_t> sig_buf(private_keys.GetPublic().GetSignatureLen());

  // Sign RI
  private_keys.Sign(
      reinterpret_cast<const std::uint8_t*>(router_info.Str().c_str()),
      router_info.Str().size(),
      sig_buf.data());

  // Write signature to RI
  router_info.Write(sig_buf.data(), sig_buf.size());

  LOG(debug) << "RouterInfo: " << __func__
             << " total RI size: " << router_info.Str().size();
}

void RouterInfo::SaveToFile(const std::string& path)
{
  core::OutputFileStream stream(path, std::ofstream::binary);

  if (stream.Fail())
    throw std::runtime_error("RouterInfo: cannot open " + path);

  // TODO(anonimal): buffer should be guaranteed
  if (!m_Buffer)
    throw std::length_error("RouterInfo: cannot save file, buffer is empty");

  if (!stream.Write(m_Buffer.get(), m_BufferLen))
    throw std::runtime_error("RouterInfo: cannot save " + path);
}

std::shared_ptr<RouterProfile> RouterInfo::GetProfile() const
{
  if (!m_Profile)
    m_Profile = GetRouterProfile(GetIdentHash());
  return m_Profile;
}

const RouterInfo::Address* RouterInfo::GetNTCPAddress(bool has_v6) const
{
  if (!has_v6)
    return GetAddress(SupportedTransport::NTCPv4);
  return GetAddress(SupportedTransport::NTCPv4 | SupportedTransport::NTCPv6);
}

const RouterInfo::Address* RouterInfo::GetSSUAddress(bool has_v6) const
{
  if (!has_v6)
    return GetAddress(SupportedTransport::SSUv4);
  return GetAddress(SupportedTransport::SSUv4 | SupportedTransport::SSUv6);
}

const RouterInfo::Address* RouterInfo::GetAddress(
    const std::uint8_t transports) const
{
  // Ensures supported transports
  auto has_transport = [transports](const std::uint8_t supported) -> bool {
    return transports & supported;
  };

  Transport transport;
  bool has_v6(false);

  // Ensure address has appropriate transport
  if (has_transport(SupportedTransport::NTCPv4 | SupportedTransport::NTCPv6))
    transport = Transport::NTCP;

  if (has_transport(SupportedTransport::SSUv4 | SupportedTransport::SSUv6))
    transport = Transport::SSU;

  if (has_transport(SupportedTransport::NTCPv6 | SupportedTransport::SSUv6))
    has_v6 = true;

  // Return only usable addresses
  for (const auto& address : GetAddresses())
    {
      if (address.transport == transport)
        {
          // Ensurew we return v6 capable address if selected
          if (address.host.is_v4() || (has_v6 && address.host.is_v6()))
            {
              LOG(debug) << "RouterInfo: " << __func__ << GetTrait(transport)
                         << " " << address.host;
              return &address;
            }
        }
    }

  return nullptr;
}

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
     << tabs << "\t" << GetTrait(Trait::Host) << delimiter
     << address.host.to_string() << terminator

     << tabs << "\t" << GetTrait(Trait::Port) << delimiter
     << address.port << terminator

     << tabs << "\t" << GetTrait(Trait::MTU) << delimiter
     << address.mtu << terminator

     << tabs << "\t" << GetTrait(Trait::Date) << delimiter
     << address.date << terminator

     << tabs << "\t" << GetTrait(Trait::Cost) << delimiter
     << static_cast<std::uint16_t>(address.cost) << terminator;

  if (address.transport == Transport::SSU)
    {
      ss << tabs << "\t" << GetTrait(Trait::Key) << delimiter
         << address.key.ToBase64() << terminator

         << tabs << "\n\tIntroducers(" << address.introducers.size() << ")"
         << std::endl;

      for (const Introducer& introducer : address.introducers)
        ss << GetDescription(introducer, tabs + "\t\t") << std::endl;
    }

  return ss.str();
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
