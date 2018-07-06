/**                                                                                           //
 * Copyright (c) 2015-2018, The Kovri I2P Router Project                                      //
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
 */

#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "core/router/identity.h"
#include "core/router/info.h"
#include "core/router/net_db/impl.h"

#include "tests/unit_tests/core/router/identity.h"

namespace core = kovri::core;

struct NetDbFixture : public IdentityExFixture
{
  using Cap = core::RouterInfoTraits::Cap;

  NetDbFixture() : m_NetDb(std::make_unique<core::NetDb>())
  {
    // Use Alice's data from IdentityEx fixture
    core::IdentityEx m_Ident;
    m_Ident.FromBuffer(raw_ident.data(), raw_ident.size());
    m_Hash = m_Ident.GetIdentHash();
  }

  std::unique_ptr<core::RouterInfo> AddRouterInfo(Cap cap)
  {
    auto ri = std::make_unique<core::RouterInfo>(
        core::PrivateKeys::CreateRandomKeys(
            core::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519),
        std::vector<std::pair<std::string, std::uint16_t>>{{"127.0.0.1", 9111}},
        std::make_pair(true, false),
        cap);

    BOOST_CHECK_NO_THROW(
        m_NetDb->AddRouterInfo(ri->GetIdentHash(), ri->data(), ri->size()));

    return ri;
  }

  std::shared_ptr<const core::RouterInfo> GetClosestFloodfill()
  {
    auto ff = m_NetDb->GetClosestFloodfill(m_Hash);
    if (!ff)
      throw std::runtime_error("no floodfill available");
    return ff;
  }

  std::vector<core::IdentHash> GetClosestFloodfills(const std::uint8_t count)
  {
    auto ffs = m_NetDb->GetClosestFloodfills(m_Hash, count);
    if (ffs.empty())
      throw std::runtime_error("no floodfills available");
    return ffs;
  }

  std::shared_ptr<const core::RouterInfo> GetClosestNonFloodfill()
  {
    auto ri = m_NetDb->GetClosestNonFloodfill(m_Hash);
    if (!ri)
      throw std::runtime_error("no routers available");
    return ri;
  }

  core::IdentHash m_Hash;
  std::unique_ptr<core::NetDb> m_NetDb;
};

BOOST_FIXTURE_TEST_SUITE(NetDbTests, NetDbFixture)

// TODO(unassigned): this isn't an accurate testcase (we should rather test kademlia)
BOOST_AUTO_TEST_CASE(ValidClosestFloodfills)
{
  constexpr std::uint8_t count(2);  // FF count

  // Add floodfills to netdb
  std::set<std::unique_ptr<core::RouterInfo>> infos;
  for (auto i(0); i < count; i++)
    infos.insert(AddRouterInfo(Cap::Floodfill));

  // Get added floodfill hashes
  std::vector<core::IdentHash> hashes;
  for (const auto& ri : infos)
    hashes.push_back(ri->GetIdentHash());

  // Get closest floodfills
  std::vector<core::IdentHash> ffs;
  BOOST_REQUIRE_NO_THROW(ffs = GetClosestFloodfills(infos.size()));

  // Floodfill hashes should match added router hashes
  // TODO(unassigned): this should change once we include the kademlia test
  std::sort(ffs.begin(), ffs.end());
  std::sort(hashes.begin(), hashes.end());

  BOOST_CHECK(ffs == hashes);
}

BOOST_AUTO_TEST_CASE(ValidClosestFloodfill)
{
  std::unique_ptr<core::RouterInfo> ri;
  BOOST_REQUIRE_NO_THROW(ri = AddRouterInfo(Cap::Floodfill));

  std::shared_ptr<const core::RouterInfo> ff;
  BOOST_REQUIRE_NO_THROW(ff = GetClosestFloodfill());

  BOOST_REQUIRE_EQUAL(ff->GetIdentHash(), ri->GetIdentHash());
}

BOOST_AUTO_TEST_CASE(ValidClosestNonFloodfill)
{
  std::unique_ptr<core::RouterInfo> ri;
  BOOST_REQUIRE_NO_THROW(ri = AddRouterInfo(Cap::HighBandwidth));

  std::shared_ptr<const core::RouterInfo> ff;
  BOOST_REQUIRE_NO_THROW(ff = GetClosestNonFloodfill());

  BOOST_CHECK_EQUAL(ff->GetIdentHash(), ri->GetIdentHash());
}

BOOST_AUTO_TEST_CASE(InvalidRouters)
{
  core::IdentHash hash;  // Empty hash

  BOOST_CHECK_THROW(m_NetDb->GetClosestFloodfill(hash), std::exception);
  BOOST_CHECK_THROW(m_NetDb->GetClosestFloodfill(nullptr), std::exception);

  BOOST_CHECK_THROW(m_NetDb->GetClosestFloodfills(hash, 1), std::exception);
  BOOST_CHECK_THROW(m_NetDb->GetClosestFloodfills(nullptr, 1), std::exception);

  BOOST_CHECK_THROW(GetClosestFloodfills(0), std::exception);

  BOOST_CHECK_THROW(m_NetDb->GetClosestNonFloodfill(nullptr), std::exception);
  BOOST_CHECK_THROW(m_NetDb->GetClosestNonFloodfill(hash), std::exception);
}

BOOST_AUTO_TEST_SUITE_END()
