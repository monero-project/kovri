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

#include "tests/unit_tests/main.h"

#include "core/util/buffer.h"

struct BufferFixture
{
  core::Buffer<> buf;
  std::array<std::uint8_t, 3> arr{{1, 2, 3}};
  enum { Max = 4096 };
};

BOOST_FIXTURE_TEST_SUITE(Buffer, BufferFixture)

BOOST_AUTO_TEST_CASE(Ctor)
{
  BOOST_CHECK_NO_THROW(core::Buffer<> buf(arr.data(), arr.size()));

  core::Buffer<> buf(arr.data(), arr.size());
  BOOST_CHECK_EQUAL(std::memcmp(buf.data(), arr.data(), buf.size()), 0);
}

BOOST_AUTO_TEST_CASE(Comparison)
{
  core::Buffer<> comp;
  BOOST_CHECK(comp == buf);

  comp(arr.data(), arr.size());
  BOOST_CHECK(comp != buf);
  BOOST_CHECK_NE(std::memcmp(comp.data(), buf.data(), comp.size()), 0);

  core::Buffer<> elem(100);
  BOOST_CHECK(comp != elem);
  comp.clear();

  BOOST_CHECK(comp != elem);
  // New buffer should still be zero initialized
  BOOST_CHECK_EQUAL(std::memcmp(comp.data(), elem.data(), comp.size()), 0);
}

BOOST_AUTO_TEST_CASE(Empty)
{
  std::array<std::uint8_t, Max> max{{}};
  BOOST_CHECK(buf.get() == max);
  BOOST_CHECK_EQUAL(std::memcmp(buf.data(), max.data(), max.size()), 0);

  buf.clear();
  BOOST_CHECK_EQUAL(buf.size(), 0);
  BOOST_CHECK_EQUAL(buf.capacity(), Max);
}

BOOST_AUTO_TEST_CASE(Data)
{
  core::Buffer<123, 456> buf;
  std::array<std::uint8_t, 456> data{{}};

  BOOST_CHECK_NO_THROW(buf(data.data(), data.size()));
  BOOST_CHECK(buf.get() == data);

  data.fill(1);

  BOOST_CHECK_EQUAL(buf.size(), data.size());
  BOOST_CHECK(buf.get() != data);

  BOOST_CHECK_NO_THROW(buf(data.data(), data.size()));
  BOOST_CHECK(buf.get() == data);
}

BOOST_AUTO_TEST_CASE(Size)
{
  BOOST_CHECK_EQUAL(buf.size(), Max);
  BOOST_CHECK_EQUAL(buf.capacity(), Max);

  BOOST_CHECK_NO_THROW(buf(100));
  BOOST_CHECK_EQUAL(buf.size(), 100);
  BOOST_CHECK_EQUAL(buf.capacity(), Max);

  BOOST_CHECK_NO_THROW(buf(arr.data(), arr.size()));
  BOOST_CHECK_EQUAL(buf.size(), arr.size());
  BOOST_CHECK_EQUAL(buf.capacity(), Max);
}

BOOST_AUTO_TEST_CASE(InvalidBuffer)
{
  using Buf = core::Buffer<0, 1024>;
  BOOST_CHECK_THROW(Buf buf(Max), std::exception);
  BOOST_CHECK_THROW(Buf buf(-123), std::exception);
  BOOST_CHECK_THROW(core::Buffer<> buf(Max + 1), std::exception);
}

BOOST_AUTO_TEST_CASE(DataOverwrite)
{
  core::Buffer<0, 32> bad;
  std::array<std::uint8_t, Max> data{{}};
  BOOST_CHECK_THROW(bad(data.data(), data.size()), std::exception);
}

BOOST_AUTO_TEST_SUITE_END()
