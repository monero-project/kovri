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
 */

#define BOOST_TEST_DYN_LINK

#include <boost/test/unit_test.hpp>

#include "core/router/net_db/impl.h"
#include "core/util/byte_stream.h"

BOOST_AUTO_TEST_SUITE(NetDbTests)

BOOST_AUTO_TEST_CASE(NetDbStart) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  BOOST_CHECK_EQUAL(netdb.IsRunning(), true);
}

BOOST_AUTO_TEST_CASE(NetDbStop) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  netdb.Stop();
  BOOST_CHECK_EQUAL(netdb.IsRunning(), false);
  BOOST_CHECK_EQUAL(netdb.GetNumRouters(), 0);
  BOOST_CHECK_EQUAL(netdb.GetNumFloodfills(), 0);
  BOOST_CHECK_EQUAL(netdb.GetNumLeaseSets(), 0);
  BOOST_CHECK_EQUAL(netdb.GetNumRequestedDestinations(), 0);
}

BOOST_AUTO_TEST_CASE(NetDbUpdateNumExploratoryTunnels) {
  using namespace kovri::core;
  NetDb netdb;
  std::uint16_t low_routers = 300,
    high_routers = 2000;
  // known_routers < NetDbSize::MinKnownRouters,
  // tunnels to build = NetDbSize::MaxExploratoryTunnels
  BOOST_CHECK_EQUAL(
      netdb.UpdateNumExploratoryTunnels(
        low_routers,
        1,
        2),
      GetType(NetDbSize::MaxExploratoryTunnels));
  // known_routers > NetDbSize::MinKnownRouters,
  // tunnels to build = NetDbSize::MinExploratoryTunnels
  BOOST_CHECK_EQUAL(
      netdb.UpdateNumExploratoryTunnels(
        high_routers,
        1,
        2),
      GetType(NetDbSize::MinExploratoryTunnels));
  // ts - last_exploratory >= NetDbInterval::DelayedExploratory
  // for known_routers < NetDbSize::MinKnownRouters
  // tunnels to build = NetDbSize::MaxExploratoryTunnels
  BOOST_CHECK_EQUAL(
      netdb.UpdateNumExploratoryTunnels(
        low_routers,
        GetType(NetDbInterval::DelayedExploratory),
        0),
      GetType(NetDbSize::MaxExploratoryTunnels));
  // ts - last_exploratory >= NetDbInterval::DelayedExploratory
  // for known_routers > MinKnownRouters
  // tunnels to build = NetDbSize::MinExploratoryTunnels
  BOOST_CHECK_EQUAL(
      netdb.UpdateNumExploratoryTunnels(
        high_routers,
        GetType(NetDbInterval::DelayedExploratory),
        0),
      GetType(NetDbSize::MinExploratoryTunnels));
}

BOOST_AUTO_TEST_CASE(NetDbAddRouterInfo) {
  using namespace kovri::core;
  NetDb netdb;
  kovri::RouterContext router;
  router.Init("test", 12345);
  BOOST_CHECK_EQUAL(
      netdb.AddRouterInfo(
        router.GetRouterInfo().GetBuffer(),
        router.GetRouterInfo().GetBufferLen()),
      true);
}

// TODO(olark): Write a test for NetDb::AddLeaseSet()

BOOST_AUTO_TEST_CASE(NetDbFindRouter) {
  using namespace kovri::core;
  NetDb netdb;
  kovri::RouterContext router;
  router.Init("test", 12345);
  netdb.AddRouterInfo(
      router.GetRouterInfo().GetBuffer(),
      router.GetRouterInfo().GetBufferLen());
  BOOST_CHECK_EQUAL(
      netdb.FindRouter(
        router.GetIdentHash())->GetIdentHash(),
      router.GetIdentHash());
}

// TODO(olark): Write a test for NetDb::FindLeaseSet()

BOOST_AUTO_TEST_CASE(NetDbSetUnreachable) {
  using namespace kovri::core;
  NetDb netdb;
  kovri::RouterContext router;
  router.Init("test", 12345);
  netdb.AddRouterInfo(
      router.GetRouterInfo().GetBuffer(),
      router.GetRouterInfo().GetBufferLen());
  netdb.SetUnreachable(router.GetIdentHash(), true);
  BOOST_CHECK_EQUAL(
      netdb.FindRouter(
        router.GetIdentHash())->IsUnreachable(),
      true);
  netdb.SetUnreachable(router.GetIdentHash(), false);
  BOOST_CHECK_EQUAL(
      netdb.FindRouter(
        router.GetIdentHash())->IsUnreachable(),
      false);
}

BOOST_AUTO_TEST_CASE(NetDbRequestDestination) {
  using namespace kovri::core;
  NetDb netdb;
  kovri::RouterContext destination;
  destination.Init("test", 12345);
  BOOST_CHECK_NO_THROW(
      netdb.RequestDestination(
        destination.GetIdentHash()));
}

// TODO(olark): write a test for storing a leaseset
BOOST_AUTO_TEST_CASE(NetDbHandleDatabaseStoreMsg) {
  using namespace kovri::core;
  NetDb netdb;
  kovri::RouterContext router;
  router.Init("test", 12345);
  netdb.AddRouterInfo(
      router.GetRouterInfo().GetBuffer(),
      router.GetRouterInfo().GetBufferLen());
  auto msg =
    CreateDatabaseStoreMsg(
        netdb.FindRouter(
          router.GetIdentHash()),
        // no reply token
        0);
  BOOST_CHECK_NO_THROW(netdb.HandleDatabaseStoreMsg(msg));
  msg =
    CreateDatabaseStoreMsg(
        netdb.FindRouter(
          router.GetIdentHash()),
        12345);
  BOOST_CHECK_NO_THROW(netdb.HandleDatabaseStoreMsg(msg));
}

BOOST_AUTO_TEST_CASE(NetDbHandleDatabaseSearchReplyMsg) {
  using namespace kovri::core;
  NetDb netdb;
  kovri::RouterContext router, router2;
  router.Init("test", 12345);
  router2.Init("test2", 12345);
  std::vector<IdentHash> routers;
  routers.push_back(router2.GetIdentHash());
  auto msg =
    CreateDatabaseSearchReply(
        router.GetIdentHash(),
        routers);
  BOOST_CHECK_NO_THROW(netdb.HandleDatabaseSearchReplyMsg(msg));
}

// TODO(olark): write a test for a leaseset lookup
BOOST_AUTO_TEST_CASE(NetDbHandleDatabaseLookupMsg) {
  using namespace kovri::core;
  NetDb netdb;
  kovri::RouterContext router, destination;
  router.Init("test", 12345);
  destination.Init("test", 12345);
  auto msg =
    CreateRouterInfoDatabaseLookupMsg(
        destination.GetIdentHash(),
        router.GetIdentHash(),
        0,
        false);
  BOOST_CHECK_NO_THROW(netdb.HandleDatabaseLookupMsg(msg));
  msg =
    CreateRouterInfoDatabaseLookupMsg(
        destination.GetIdentHash(),
        router.GetIdentHash(),
        0,
        // exploratory
        true);
  BOOST_CHECK_NO_THROW(netdb.HandleDatabaseLookupMsg(msg));
}

// TODO(olark) write a test for template NetDb::GetRandomRouter() shuffling

BOOST_AUTO_TEST_CASE(NetDbGetRandomRouter) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  auto router = netdb.GetRandomRouter();
  BOOST_CHECK_EQUAL(!router->IsHidden(), true);
}

// TODO(olark) add a check for a router that won't be compatible
BOOST_AUTO_TEST_CASE(NetDbGetRandomRouterCompatibleWith) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  kovri::RouterContext compatible_with;
  compatible_with.Init("compatible_test", 12345);
  auto router =
    netdb.GetRandomRouter(
        compatible_with.GetSharedRouterInfo());
  BOOST_CHECK_EQUAL(
      !router->IsHidden() &&
      router != compatible_with.GetSharedRouterInfo()
      && router->IsCompatible(compatible_with.GetRouterInfo()),
      true);
}

BOOST_AUTO_TEST_CASE(NetDbGetRandomPeerTestRouter) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  auto router = netdb.GetRandomPeerTestRouter();
  BOOST_CHECK_EQUAL(
      !router->IsHidden() &&
      router->IsPeerTesting(),
      true);
}

BOOST_AUTO_TEST_CASE(NetDbGetRandomIntroducer) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  auto router = netdb.GetRandomIntroducer();
  BOOST_CHECK_EQUAL(
      !router->IsHidden() &&
      router->IsIntroducer(),
      true);
}

BOOST_AUTO_TEST_CASE(NetDbGetHighBandwidthRandomRouter) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  kovri::RouterContext compatible_with;
  compatible_with.Init("compatible_test", 12345);
  auto router =
    netdb.GetHighBandwidthRandomRouter(
        compatible_with.GetSharedRouterInfo());
  BOOST_CHECK_EQUAL(
      !router->IsHidden() &&
      router != compatible_with.GetSharedRouterInfo()
      && router->IsCompatible(compatible_with.GetRouterInfo())
      && (router->GetCaps() & RouterInfo::eHighBandwidth),
      true);
}

// TODO(olark) write tests for other i2np messages?
BOOST_AUTO_TEST_CASE(NetDbPostI2NPMsg) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  kovri::RouterContext router;
  router.Init("test", 12345);
  auto msg =
    CreateDatabaseStoreMsg(
        router.GetSharedRouterInfo());
  BOOST_CHECK_NO_THROW(netdb.PostI2NPMsg(msg));
}

// TODO(olark): test the xor distance between the
// floodfill and routing key?
BOOST_AUTO_TEST_CASE(NetDbGetClosestFloodfill) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  kovri::RouterContext router;
  router.Init("test", 12345);
  std::set<IdentHash> excluded;
  auto floodfill =
    netdb.GetClosestFloodfill(
        router.GetIdentHash(),
        excluded);
  BOOST_CHECK_EQUAL(
      !floodfill->IsUnreachable() &&
      floodfill->IsFloodfill(),
      true);
}

BOOST_AUTO_TEST_CASE(NetDbGetClosestFloodfills) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  kovri::RouterContext router;
  router.Init("test", 12345);
  std::set<IdentHash> excluded;
  auto floodfills =
    netdb.GetClosestFloodfills(
        router.GetIdentHash(),
        3,
        excluded);
  for (auto it : floodfills) {
    BOOST_CHECK_EQUAL(
        !netdb.FindRouter(it)->IsUnreachable()
        && netdb.FindRouter(it)->IsFloodfill(),
        true);
  }
}

BOOST_AUTO_TEST_CASE(NetDbGetClosestNonFloodfill) {
  using namespace kovri::core;
  NetDb netdb;
  netdb.Start();
  kovri::RouterContext router;
  router.Init("test", 12345);
  std::set<IdentHash> excluded;
  auto non_floodfill =
    netdb.GetClosestNonFloodfill(
        router.GetIdentHash(),
        excluded);
  BOOST_CHECK_EQUAL(
      !non_floodfill->IsUnreachable()
      && !non_floodfill->IsFloodfill(),
      true);
}

BOOST_AUTO_TEST_SUITE_END()
