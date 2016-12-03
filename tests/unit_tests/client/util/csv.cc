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

#include <boost/test/unit_test.hpp>

#include "client/util/csv.h"

BOOST_AUTO_TEST_SUITE(CSVTest)

// TODO(unassigned): improve + refactor to expand test-cases

/// @brief Creates a test vector fixture with given string and count
const std::vector<std::string> CreateTestFixture(
    const std::string& fixture,
    const std::size_t count) {
  std::vector<std::string> test;
  for (std::size_t i = 0; i < count; i++)
    test.push_back(std::string(fixture + std::to_string(i)));
  return test;
}

/// @brief Create CSV fixture from non-csv "test" fixture
const std::vector<std::string> CreateCSVFixture(
    const std::vector<std::string> fixture) {
  std::vector<std::string> csv;
  for (auto const& field : fixture)
    csv.push_back(std::string(field + ","));
  return csv;
}

/// @brief Create record from fixture
const std::string CreateRecord(
    const std::vector<std::string>& fixture) {
  std::string record;
  for (auto const& field : fixture)
    record.append(field);
  return record;
}

// TODO(unassigned): improve + refactor to expand test-cases

BOOST_AUTO_TEST_CASE(CSVParse) {
  // Create test fixture
  auto test_fixture = CreateTestFixture("test", 10);

  // Create test record to test against parsed record
  auto test_record = CreateRecord(test_fixture);

  // Create CSV record to parse
  auto csv_record = CreateRecord(CreateCSVFixture(test_fixture));

  // Get final parsed record, should return equivalent of test fixture
  auto final_record = CreateRecord(kovri::client::ParseCSV(csv_record));

  // Test against original test record
  BOOST_CHECK_EQUAL(final_record, test_record);
}

BOOST_AUTO_TEST_SUITE_END()