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

#include <iostream>

#include "client/address_book/impl.h"
#include "client/address_book/storage.h"

#include "core/router/context.h"

struct AddressBookStorageFixture
{
  /// @alias Subscription
  /// @brief Subscription alias for readability and convenience
  /// @details Intended for user-convenience and readability
  using SubscriptionType = client::AddressBook::SubscriptionType;

  AddressBookStorageFixture() : m_Storage(nullptr)
  {
    // Setup temporary data directory
    core::context.SetCustomDataDir(temp_path.string());

    // Ensure Client and AddressBook paths exist
    core::EnsurePath(core::GetPath(core::Path::Client));

    core::EnsurePath(core::GetPath(core::Path::AddressBook));

    // Setup storage
    m_Storage = GetStorageInstance();
  }

  ~AddressBookStorageFixture()
  {
    BOOST_CHECK_NO_THROW(RemoveFiles());
  }

  /// @brief Remove files created by AddressBookStorage
  void RemoveFiles()
  {
    try
      {
        boost::filesystem::directory_iterator end_itr;
        for (boost::filesystem::directory_iterator dir_itr(
                 core::GetPath(core::Path::AddressBook));
             dir_itr != end_itr;
             ++dir_itr)
          {
            boost::filesystem::remove(dir_itr->path().filename());
          }
      }
    catch (...)
      {
        core::Exception ex(__func__);
        ex.Dispatch();
        throw;
      }
  }

  /// @brief Insert test hosts into an address map
  void ToAddressMap(SubscriptionType source)
  {
    for (const auto& host : m_Hosts)
      {
        client::BookEntry entry(host);
        m_Addresses[entry.get_host()] = std::make_pair(entry.get_address(), source);
      }
  }

  /// @brief Create new storage instance
  /// @notes Called after creating custom data directory
  std::unique_ptr<client::AddressBookStorage> GetStorageInstance()
  {
    return std::make_unique<client::AddressBookStorage>();
  }


  std::size_t saved_addresses{};
  client::AddressBook::AddressMap m_Addresses;
  std::unique_ptr<client::AddressBookStorage> m_Storage;
  boost::filesystem::path temp_path = boost::filesystem::temp_directory_path();
  std::array<std::string, 2> const m_Hosts{{
      "kovri.i2p=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ4zWvELv-5OsBYTHKtnLzvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rt9SzLkcpwhO3t0Zwe6jXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdWCAPio5Z-YnRL46n0IHWOQPYYSStJMYPlPS-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVF2qwQRnBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MBw7pmABr-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7QRmT4X8X-EITwNlKN6r1t3uoQ~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA==",
      "monero.i2p=3VzGaQQXwzN1iAwaPI17RK~gUqKqMH6fI2dkkGBwdayAPAdiZMyk1KGoTq~q1~HBraPZnz9mZJlzf6WVGCkUmUV3SBjBEbrdL9ud0fArq3P1~Ui9ViR9B7m5EG8smAnFvKZdqS-cnmHploUfIOefoQe0ecM7YYHErZsn3kL-WtvlfoDiSth-edIBpWxeHfmXSKoHSGSJ2snl5p9hxh30KmKj9AB0d4En-jcD83Ep3jsSvtPoQl7tSsh575~q0JJLsqGqm2sR9w4nZr7O58cg-21A2tlZeldM287uoTMb9eHWnYuozUGzzWOXvqg0UxPQSTfwh7YEhx0aRTXT2OFpr84XPoH2M6xIXfEMkFtJEJ-XlM-ILUZkg3kuBEFN7n4mBK~8L0Ht1QCq8L3~y7YnN61sxC0E9ZdyEOoC~nFJxndri9s9NzgZPo5eo6DsZXweOrTAIVQgKFUozL7WXKMlgqBZ5Nl3ijD6MGCIy0fWYHGLJ4jDBY7wrcfynVXFGm4EBQAEAAcAAA==",
  }};
};

BOOST_FIXTURE_TEST_SUITE(AddressBookStorageTests, AddressBookStorageFixture)

BOOST_AUTO_TEST_CASE(ValidSaveSubscription)
{
  // Check we have a storage instance
  BOOST_CHECK(m_Storage);

  // Ensure successful address insertion
  BOOST_CHECK_NO_THROW(ToAddressMap(SubscriptionType::Default));

  // Ensure addresses written to storage
  BOOST_CHECK_NO_THROW(saved_addresses = m_Storage->Save(m_Addresses));

  // Ensure addresses are saved
  BOOST_CHECK(saved_addresses && saved_addresses == m_Hosts.size());
}

BOOST_AUTO_TEST_CASE(InvalidSaveSubscription)
{
  // Check we have a storage instance
  BOOST_CHECK(m_Storage);

  // Save an empty subscription
  BOOST_CHECK_NO_THROW(saved_addresses = m_Storage->Save(m_Addresses));

  // Ensure no addresses are saved
  BOOST_CHECK(!saved_addresses && m_Addresses.empty());
}

BOOST_AUTO_TEST_CASE(ValidLoadSubscription)
{
  // Check we have a storage instance
  BOOST_CHECK(m_Storage);

  // Ensure successful address insertion
  BOOST_CHECK_NO_THROW(ToAddressMap(SubscriptionType::Default));

  // Ensure addresses written to storage
  BOOST_CHECK_NO_THROW(saved_addresses = m_Storage->Save(m_Addresses));
  BOOST_CHECK(saved_addresses == m_Hosts.size());

  // Reset the address map
  m_Addresses.clear();

  // Ensure addresses loaded from storage
  BOOST_CHECK_NO_THROW(m_Storage->Load(m_Addresses));
  BOOST_CHECK(m_Addresses.size() == m_Hosts.size());
}

BOOST_AUTO_TEST_CASE(InvalidLoadSubscription)
{
  // Check we have a storage instance
  BOOST_CHECK(m_Storage);

  // Save empty address map to storage
  BOOST_CHECK_NO_THROW(saved_addresses = m_Storage->Save(m_Addresses));

  // Ensure no addresses are saved
  BOOST_CHECK(!saved_addresses && m_Addresses.empty());

  // Load from empty address catalog
  BOOST_CHECK_NO_THROW(m_Storage->Load(m_Addresses));

  // Ensure no addresses are loaded
  BOOST_CHECK(m_Addresses.empty());
}

BOOST_AUTO_TEST_SUITE_END()
