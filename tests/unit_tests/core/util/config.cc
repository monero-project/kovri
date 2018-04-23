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

#include "core/util/config.h"

namespace core = kovri::core;

struct ConfigurationFixture
{
  // Needed for passing templated arguments to Boost macros
  using StringListParameter =
      core::Configuration::ListParameter<std::string, 2>;
  using IntegerListParameter =
      core::Configuration::ListParameter<std::uint16_t, 1>;
  using FloatListParameter =
      core::Configuration::ListParameter<float, 1>;
  using UnsupportedListParameter =
      core::Configuration::ListParameter<std::map<char, char>, 2>;

  const std::string m_IPv4String{"10.11.12.13"};
  const std::string m_IPv6String{"fe80::42:acff:fe11:2"};
  const std::string m_IPList{"10.11.12.13,fe80::42:acff:fe11:2"};
  const std::string m_OversizedList{"10.11.12.13,fe80::42:acff:fe11:2,15.16.17.18"};
  const std::string m_PortString{"1337"};
  const std::string m_FloatString{"13.37"};
  const std::uint16_t m_Port = 1337;
  const float m_Float = 13.37;
};

BOOST_FIXTURE_TEST_SUITE(ConfigurationTests, ConfigurationFixture)

BOOST_AUTO_TEST_CASE(ValidListParameter)
{
  // Comma-separated string values should parse correctly
  BOOST_CHECK_NO_THROW(StringListParameter lps_(m_IPList));
  StringListParameter lp(m_IPList);
  BOOST_CHECK(m_IPv4String == lp.values.front());
  BOOST_CHECK(m_IPv6String == lp.values.back());
  BOOST_CHECK(lp.IsExpectedSize());

  // Integer should be parsed and converted correctly
  BOOST_CHECK_NO_THROW(IntegerListParameter lpi_(m_PortString));
  IntegerListParameter lpi(m_PortString);
  BOOST_CHECK(m_Port == lpi.values.front());
  BOOST_CHECK(lpi.IsExpectedSize());

  // Float should be parsed and converted correctly
  BOOST_CHECK_NO_THROW(FloatListParameter lpf_(m_FloatString));
  FloatListParameter lpf(m_FloatString);
  BOOST_CHECK(m_Float == lpf.values.front());
  BOOST_CHECK(lpf.IsExpectedSize());
}

BOOST_AUTO_TEST_CASE(OversizedListParameter)
{
  BOOST_CHECK_NO_THROW(StringListParameter lps_(m_OversizedList));
  StringListParameter lps(m_OversizedList);
  BOOST_CHECK(!lps.IsExpectedSize());
}

BOOST_AUTO_TEST_CASE(InvalidListParameter)
{
#ifndef NDEBUG
  // Unsupported type should throw on release builds,
  //   static_assert fires during compilation for debug builds.
  BOOST_CHECK_THROW(
      UnsupportedListParameter lpu_(m_IPList),
      boost::program_options::validation_error);
#endif
}

BOOST_AUTO_TEST_SUITE_END()
