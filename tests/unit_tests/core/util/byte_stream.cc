/**                                                                                           //
 * Copyright (c) 2015-2017, The Kovri I2P Router Project                                      //
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
 */

#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include <array>
#include <limits>

#include "core/util/byte_stream.h"

namespace core = kovri::core;

struct ByteStreamFixture
{
  const std::string m_IPv4String = "10.11.12.13";
  std::array<std::uint8_t, 4> m_IPv4Array{{0x0A, 0x0B, 0x0C, 0x0D}};

  const std::string m_IPv6String = "fe80::42:acff:fe11:2";
  const std::array<std::uint8_t, 16> m_IPv6Array{{
      0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x42, 0xac, 0xff, 0xfe, 0x11, 0x00, 0x02}};
};

BOOST_FIXTURE_TEST_SUITE(ByteStreamTests, ByteStreamFixture)

BOOST_AUTO_TEST_CASE(StreamsEmpty)
{
  core::OutputByteStream output;
  BOOST_CHECK_NO_THROW(output.ProduceData(0));
  BOOST_CHECK_THROW(output.ProduceData(1), std::length_error);
  BOOST_CHECK_THROW(output.Write<std::uint8_t>(1), std::length_error);
  BOOST_CHECK_THROW(output.Write<std::uint16_t>(1), std::length_error);
  BOOST_CHECK_THROW(output.Write<std::uint32_t>(1), std::length_error);
  BOOST_CHECK_THROW(output.Write<std::uint64_t>(1), std::length_error);

  core::InputByteStream input;
  BOOST_CHECK_NO_THROW(input.ConsumeData(0));
  BOOST_CHECK_THROW(input.ConsumeData(1), std::length_error);
  BOOST_CHECK_THROW(input.ReadBytes(1), std::length_error);
  BOOST_CHECK_THROW(input.Read<std::uint8_t>(), std::length_error);
  BOOST_CHECK_THROW(input.Read<std::uint16_t>(), std::length_error);
  BOOST_CHECK_THROW(input.Read<std::uint32_t>(), std::length_error);
  BOOST_CHECK_THROW(input.Read<std::uint64_t>(), std::length_error);
}

BOOST_AUTO_TEST_CASE(InputByteStream)
{
  core::InputByteStream input(m_IPv4Array.data(), m_IPv4Array.size());
  BOOST_CHECK_NO_THROW(input.ConsumeData(0));
  BOOST_CHECK_EQUAL(input.Read<std::uint8_t>(), m_IPv4Array.at(0));
  BOOST_CHECK_EQUAL(input.ReadBytes(3), &m_IPv4Array.at(1));
  BOOST_CHECK_THROW(input.ConsumeData(1), std::length_error);
}

BOOST_AUTO_TEST_CASE(OutputByteStream)
{
  std::array<std::uint8_t, 4> buffer;
  core::OutputByteStream output(buffer.data(), buffer.size());
  BOOST_CHECK_NO_THROW(output.WriteData(nullptr, 0));
  BOOST_CHECK_NO_THROW(output.WriteData(buffer.data(), 0));
  BOOST_CHECK_THROW(output.WriteData(nullptr, 1), std::runtime_error);
  BOOST_CHECK_NO_THROW(output.Write<std::uint8_t>(m_IPv4Array.at(0)));
  BOOST_CHECK_EQUAL(output.GetSize(), buffer.size());
  BOOST_CHECK_EQUAL(output.GetData(), buffer.data());
  BOOST_CHECK_EQUAL(output.GetPosition(), buffer.data() + 1);
  BOOST_CHECK_NO_THROW(output.WriteData(&m_IPv4Array.at(1), 3));
  BOOST_CHECK_EQUAL(output.GetPosition(), buffer.data() + buffer.size());
  BOOST_CHECK_THROW(output.Write<std::uint8_t>(1), std::length_error);
  BOOST_CHECK_EQUAL_COLLECTIONS(
      buffer.data(),
      buffer.data() + buffer.size(),
      m_IPv4Array.data(),
      m_IPv4Array.data() + m_IPv4Array.size());
}

BOOST_AUTO_TEST_CASE(Bits16Test)
{
  std::array<std::uint8_t, sizeof(std::uint16_t)> buffer{{}};
  std::uint16_t value = std::numeric_limits<std::uint16_t>::max();

  core::OutputByteStream output(buffer.data(), buffer.size());
  BOOST_CHECK_NO_THROW(output.Write<std::uint16_t>(value));
  BOOST_CHECK_THROW(output.Write<std::uint8_t>(0), std::length_error);

  core::InputByteStream input(buffer.data(), buffer.size());
  BOOST_CHECK_EQUAL(input.Read<std::uint16_t>(), value);
  BOOST_CHECK_THROW(input.Read<std::uint8_t>(), std::length_error);
}

BOOST_AUTO_TEST_CASE(Bits32Test)
{
  std::array<std::uint8_t, sizeof(std::uint32_t)> buffer{{}};
  std::uint32_t value = std::numeric_limits<std::uint32_t>::max();

  core::OutputByteStream output(buffer.data(), buffer.size());
  BOOST_CHECK_NO_THROW(output.Write<std::uint32_t>(value));
  BOOST_CHECK_THROW(output.Write<std::uint8_t>(0), std::length_error);

  core::InputByteStream input(buffer.data(), buffer.size());
  BOOST_CHECK_EQUAL(input.Read<std::uint32_t>(), value);
  BOOST_CHECK_THROW(input.Read<std::uint8_t>(), std::length_error);
}

BOOST_AUTO_TEST_CASE(Bits64Test)
{
  std::array<std::uint8_t, sizeof(std::uint64_t)> buffer{{}};
  std::uint64_t value = std::numeric_limits<std::uint64_t>::max();

  core::OutputByteStream output(buffer.data(), buffer.size());
  BOOST_CHECK_NO_THROW(output.Write<std::uint64_t>(value));
  BOOST_CHECK_THROW(output.Write<std::uint8_t>(0), std::length_error);

  core::InputByteStream input(buffer.data(), buffer.size());
  BOOST_CHECK_EQUAL(input.Read<std::uint64_t>(), value);
  BOOST_CHECK_THROW(input.Read<std::uint8_t>(), std::length_error);
}

BOOST_AUTO_TEST_CASE(AddressToByteVectorIPv4)
{
  boost::asio::ip::address address;
  BOOST_CHECK_NO_THROW(
      address = boost::asio::ip::address::from_string(m_IPv4String));
  auto const ip = core::AddressToByteVector(address);
  BOOST_CHECK_EQUAL(ip->size(), address.to_v4().to_bytes().size());
  BOOST_CHECK_EQUAL_COLLECTIONS(
      ip->data(),
      ip->data() + ip->size(),
      m_IPv4Array.data(),
      m_IPv4Array.data() + m_IPv4Array.size());
  // Reconstruct a new address and check with original
  boost::asio::ip::address_v4::bytes_type bytes;
  std::memcpy(bytes.data(), ip->data(), address.to_v4().to_bytes().size());
  BOOST_CHECK_EQUAL(boost::asio::ip::address_v4(bytes), address.to_v4());
}

BOOST_AUTO_TEST_CASE(AddressToByteVectorIPv6)
{
  boost::asio::ip::address address;
  BOOST_CHECK_NO_THROW(
      address = boost::asio::ip::address::from_string(m_IPv6String));
  auto const ip = core::AddressToByteVector(address);
  BOOST_CHECK_EQUAL(ip->size(), address.to_v6().to_bytes().size());
  BOOST_CHECK_EQUAL_COLLECTIONS(
      ip->data(),
      ip->data() + ip->size(),
      m_IPv6Array.data(),
      m_IPv6Array.data() + m_IPv6Array.size());
  // Reconstruct a new address and check with original
  boost::asio::ip::address_v6::bytes_type bytes;
  std::memcpy(bytes.data(), ip->data(), address.to_v6().to_bytes().size());
  BOOST_CHECK_EQUAL(boost::asio::ip::address_v6(bytes), address.to_v6());
}

BOOST_AUTO_TEST_SUITE_END()
