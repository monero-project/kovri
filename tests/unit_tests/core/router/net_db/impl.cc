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

#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include "core/router/identity.h"
#include "core/router/info.h"
#include "core/router/net_db/impl.h"

#include "tests/unit_tests/core/router/identity.h"

namespace core = kovri::core;

struct NetDbFixture : public IdentityExFixture
{
  /// @alias RouterCap
  /// @brief Capabilities alias
  /// @details Intended for readability & user-friendliness when writing new tests
  using RouterCap = core::RouterInfoTraits::Cap;

  /// @brief Create identity from buffer
  /// @details Useful for getting a valid IdentHash
  void CreateIdent()
  {
    // Create valid identity
    BOOST_CHECK(
        m_Ident.FromBuffer(m_AliceIdentity.data(), m_AliceIdentity.size()));

    // Set ident hash for convenience
    m_Hash = m_Ident.GetIdentHash();
  }

  /// @brief Add router to NetDb
  /// @param cap Capability to add to router
  void AddRouter(const RouterCap cap)
  {
    // Create new private keys
    m_Keys = core::PrivateKeys::CreateRandomKeys(
        core::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519);

    // Create new router
    m_RI =
        std::make_unique<core::RouterInfo>(m_Keys, m_Points, m_Transports, cap);

    // Add router to NetDb
    BOOST_CHECK_NO_THROW(m_NetDB.AddRouterInfo(
        m_RI->GetIdentHash(), m_RI->GetBuffer(), m_RI->GetBufferLen()));
  }

  core::NetDb m_NetDB;
  core::IdentHash m_Hash;
  core::IdentityEx m_Ident;
  core::PrivateKeys m_Keys;
  std::set<core::IdentHash> m_Ex;
  std::unique_ptr<core::RouterInfo> m_RI;
  std::pair<bool, bool> m_Transports{true, false};
  std::vector<std::pair<std::string, std::uint16_t> > m_Points{{"127.0.0.1", 9111}};
};

BOOST_FIXTURE_TEST_SUITE(NetDbTests, NetDbFixture)

BOOST_AUTO_TEST_CASE(ValidClosestFloodfill)
{
  // Create a valid router identity
  CreateIdent();

  // Add floodfill router to NetDb
  AddRouter(RouterCap::Floodfill);

  std::shared_ptr<const core::RouterInfo> ret_ri;

  // Ensure no exceptions thrown getting valid floodfill
  BOOST_CHECK_NO_THROW(ret_ri = m_NetDB.GetClosestFloodfill(m_Hash, m_Ex));

  // Ensure expected floodfill is returned
  BOOST_CHECK(ret_ri && ret_ri->GetIdentHash() == m_RI->GetIdentHash());
}

BOOST_AUTO_TEST_CASE(InvalidClosestFloodfill)
{
  // Ensure null destination throws
  BOOST_CHECK_THROW(
      m_NetDB.GetClosestFloodfill(nullptr, m_Ex), std::invalid_argument);

  // Ensure zero-initialized destination throws
  BOOST_CHECK_THROW(
      m_NetDB.GetClosestFloodfill(m_Hash, m_Ex), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(ValidClosestFloodfills)
{
  // Create a valid router identity
  CreateIdent();

  // Add floodfill router to NetDb
  AddRouter(RouterCap::Floodfill);

  // Store the first floodfill locally
  std::unique_ptr<core::RouterInfo> flood_ri{nullptr};
  flood_ri.swap(m_RI);

  // Add another floodfill router to NetDb
  AddRouter(RouterCap::Floodfill);

  std::vector<core::IdentHash> ret_hash;
  const std::uint8_t limit = 2;

  // Ensure no exceptions thrown getting valid floodfill(s)
  BOOST_CHECK_NO_THROW(
      ret_hash = m_NetDB.GetClosestFloodfills(m_Hash, limit, m_Ex));

  // Ensure number of floodfills added are returned
  BOOST_CHECK(ret_hash.size() == limit);

  // Ensure returned ident hashes are unique
  BOOST_CHECK(ret_hash.front() != ret_hash.back());

  // Ensure returned ident hashes match expected floodfills
  for (auto const& h : ret_hash)
    BOOST_CHECK(h == flood_ri->GetIdentHash() || h == m_RI->GetIdentHash());

  // Ensure limit is respected
  BOOST_CHECK(m_NetDB.GetClosestFloodfills(m_Hash, 0, m_Ex).empty());
}

BOOST_AUTO_TEST_CASE(InvalidClosestFloodfills)
{
  // Ensure null destination throws
  BOOST_CHECK_THROW(
      m_NetDB.GetClosestFloodfills(nullptr, 1, m_Ex), std::invalid_argument);

  // Ensure zero-initialized destination throws
  BOOST_CHECK_THROW(
      m_NetDB.GetClosestFloodfills(m_Hash, 1, m_Ex), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(ValidClosestNonFloodfill)
{
  // Create a valid router identity
  CreateIdent();

  // Add non-floodfill to NetDb
  AddRouter(RouterCap::HighBandwidth);

  std::shared_ptr<const core::RouterInfo> ret_ri;

  // Ensure no exceptions thrown getting valid non-floodfill
  BOOST_CHECK_NO_THROW(ret_ri = m_NetDB.GetClosestNonFloodfill(m_Hash, m_Ex));

  // Ensure expected non-floodfill is returned
  BOOST_CHECK(ret_ri && ret_ri->GetIdentHash() == m_RI->GetIdentHash());
}

BOOST_AUTO_TEST_CASE(InvalidClosestNonFloodfill)
{
  // Ensure null destination throws
  BOOST_CHECK_THROW(
      m_NetDB.GetClosestNonFloodfill(nullptr, m_Ex), std::invalid_argument);

  // Ensure zero-initialized destination throws
  BOOST_CHECK_THROW(
      m_NetDB.GetClosestNonFloodfill(m_Hash, m_Ex), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()
