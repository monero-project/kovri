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

#include <boost/test/unit_test.hpp>

#include "client/util/parse.h"

BOOST_AUTO_TEST_SUITE(ClientParsing)

// TODO(unassigned): improve + refactor to expand test-cases
struct CSVFixture {
  /// @brief Creates a test vector with given string and count
  const std::vector<std::string> CreateTestVector(
      const std::string& test,
      const std::size_t count) {
    std::vector<std::string> vec;
    for (std::size_t i = 0; i < count; i++)
      vec.push_back(std::string(test + std::to_string(i)));
    return vec;
  }

  /// @brief Create CSV vector from non-CSV "test" vector
  const std::vector<std::string> CreateCSVVector(
      const std::vector<std::string>& csv) {
    std::vector<std::string> vec;
    for (auto const& field : csv)
      vec.push_back(std::string(field + ","));
    return vec;
  }

  /// @brief Create record from vector
  const std::string CreateRecord(
      const std::vector<std::string>& vec) {
    std::string record;
    for (auto const& field : vec)
      record.append(field);
    return record;
  }
};

// TODO(unassigned): improve + refactor to expand test-cases
BOOST_AUTO_TEST_CASE(ParseCSV) {
  CSVFixture csv;
  // Create test fixture
  auto test_vector = csv.CreateTestVector("test", 10);

  // Create test record to test against parsed record
  auto test_record = csv.CreateRecord(test_vector);

  // Create CSV record to parse
  auto csv_record = csv.CreateRecord(csv.CreateCSVVector(test_vector));

  // Get final parsed record, should return equivalent of test fixture
  auto final_record = csv.CreateRecord(kovri::client::ParseCSV(csv_record));

  // Test against original test record
  BOOST_CHECK_EQUAL(final_record, test_record);
}

struct TunnelFixture {
  kovri::client::TunnelAttributes tunnel{};
};

// Test for correct delimiter parsing against plain configuration
BOOST_AUTO_TEST_CASE(ParseClientDestination) {
  // Create plain destination
  auto plain = std::make_unique<TunnelFixture>();

  plain->tunnel.dest = "anonimal.i2p";
  plain->tunnel.dest_port = 80;

  kovri::client::ParseClientDestination(&plain->tunnel);

  // Create delimited destination
  auto delimited = std::make_unique<TunnelFixture>();

  delimited->tunnel.dest = "anonimal.i2p:80";
  delimited->tunnel.dest_port = 12345;

  kovri::client::ParseClientDestination(&delimited->tunnel);

  // Both destinations should be equal after being parsed
  BOOST_CHECK_EQUAL(delimited->tunnel.dest, plain->tunnel.dest);
  BOOST_CHECK_EQUAL(delimited->tunnel.dest_port, plain->tunnel.dest_port);
}

// Test for bad port length
BOOST_AUTO_TEST_CASE(CatchBadClientDestination) {
  // Create bad destination
  auto bad = std::make_unique<TunnelFixture>();

  bad->tunnel.dest = "anonimal.i2p:111111111";
  bad->tunnel.dest_port = 80;

  BOOST_REQUIRE_THROW(
      kovri::client::ParseClientDestination(&bad->tunnel),
      std::exception);

  // TODO(unassigned): expand test-case (see TODO in function definition)
}

BOOST_AUTO_TEST_SUITE_END()