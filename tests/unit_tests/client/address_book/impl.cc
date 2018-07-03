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

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include "client/address_book/impl.h"

#include "core/crypto/rand.h"


/// @class SubscriptionFixture
struct SubscriptionFixture {
  /// @brief Validates given lines as proven addressbook host/address pairs
  /// @param lines Lines to validate
  /// @return Only valid data that was parsed
  auto Validate(const std::vector<std::string>& lines) {
    std::stringstream stream;
    for (auto const& l : lines)
      stream << l << "\n";
    return book.ValidateSubscription(stream);
  }

  /// @brief Compares and validates lines against subscription fixture
  /// @return False if test data does not match subscription fixture
  bool Validate() {
    // Save fixture (malformed or redundant lines will be removed)
    for (auto const& s : subscription) {
      const std::string valid(s);
      lines.push_back(valid);
    }
    // Validate
    std::vector<std::string> validated;
    for (auto const& v : Validate(lines))
      validated.push_back(v.first + "=" + v.second.ToBase64());
    return validated != subscription ? false : true;
  }

  /// @brief Subscription with valid hosts
  const std::vector<std::string> subscription {{
    "anonimal.i2p=AQZGLAMpI9Q0l0kmMj1vpJJYK3CjLp~fE3MfvE-e7KMKjI5cPOH6EN8m794uHJ6b09qM8mb9VEv1lVLEov~usVliTSXCSHuRBOCIwIOuDNU0AbVa4BpIx~2sU4TxKhoaA3zQ6VzINoduTdR2IJhPvI5xzezp7dR21CEQGGTbenDslXeQ4iLHFA2~bzp1f7etSl9T2W9RID-KH78sRQmzWnv7dbhNodMbpO6xsf1vENf6bMRzqD5vgHEHZu2aSoNuPyYxDU1eM6--61b2xp9mt1k3ud-5WvPVg89RaU9ugU5cxaHgR927lHMCAEU2Ax~zUb3DbrvgQBOTHnJEx2Fp7pOK~PnP6ylkYKQMfLROosLDXinxOoSKP0UYCh2WgIUPwE7WzJH3PiJVF0~WZ1dZ9mg00c~gzLgmkOxe1NpFRNg6XzoARivNVB5NuWqNxr5WKWMLBGQ9YHvHO1OHhUJTowb9X90BhtHnLK2AHwO6fV-iHWxRJyDabhSMj1kuYpVUBQAEAAcAAA==",
    "check.kovri.i2p=5MDeZbodxbx3baVqISWAghnvSo1ZgQjs0cg1h3bK~SmqbCvDCy4pRjAf68rK3hSthMXj3-YEck5-UaeqmXOg~-5rZRXQWBjvtDFnwyQSacR7zK5E-E8fVDG-ILbJOPV-OgIgFa9ulECjhXRffYqOOeqSyRH7--pZKVcp6d43b-09FTFgB9PJV~VI5sHKZWlTt4uwQpbEwti5xymqW9IvSRjq2HNJbk5ITnEKnUi6hJMBmuI3-ReGT9aUrFQN1nXT4r17YVeuTBI7ZinAeVBGPnA7~p~X6FAhOh2UVLd3Z8OqRcQwhDVVF3lKqkRm9o1U8PAvPnt4pmugYYoFkNsD0K3HxC8HTQAsvlbevQQY2f1oHnYCxxC57D-qMD2QqMG-zUoEa7SkBkqs91Pm6~c4MVYvysg3cFoX6ZB7xqK6vXJh~XdRq9GdNdIuKbSpwS~yYLhKgVGERprea7J9eusglH~WD628FHjMIwTktT4wh5QRA31ha2gIOgIXjpXLlCFKBQAEAAcAAA==",
    "kovri.i2p=0UVPqAA4xUSfPYPBca24h8fdokhwcJZ4zWvELv-5OsBYTHKtnLzvK7byXtXT~fOV2pExi8vrkgarGTNDfJbB2KCsdVS3V7qwtTvoCGYyklcDBlJsWMj7H763hEz5rt9SzLkcpwhO3t0Zwe6jXL1UB-QW8KxM30t-ZOfPc6OiJ1QpnE6Bo5OUm6jPurQGXdWCAPio5Z-YnRL46n0IHWOQPYYSStJMYPlPS-S75rMIKbZbEMDraRvSzYAphUaHfvtWr2rCSPkKh3EbrOiBYiAP2oWvAQCsjouPgVF2qwQRnBbiAezHedM2gXzkgIyCV2kGOOcHhiihd~7fWwJOloH-gO78QkmCuY-3kp3633v3MBw7pmABr-XNKWnATZOuf2syWVBZbTnOXsWf41tu6a33HOuNsMxAOUrwbu7QRmT4X8X-EITwNlKN6r1t3uoQ~yZm4RKsJUsBGfVtKl8PBMak3flQAg95oV0OBDGuizIQ9vREOWvPGlQCAXZzEg~cUNbfBQAEAAcAAA==",
    "monero.i2p=3VzGaQQXwzN1iAwaPI17RK~gUqKqMH6fI2dkkGBwdayAPAdiZMyk1KGoTq~q1~HBraPZnz9mZJlzf6WVGCkUmUV3SBjBEbrdL9ud0fArq3P1~Ui9ViR9B7m5EG8smAnFvKZdqS-cnmHploUfIOefoQe0ecM7YYHErZsn3kL-WtvlfoDiSth-edIBpWxeHfmXSKoHSGSJ2snl5p9hxh30KmKj9AB0d4En-jcD83Ep3jsSvtPoQl7tSsh575~q0JJLsqGqm2sR9w4nZr7O58cg-21A2tlZeldM287uoTMb9eHWnYuozUGzzWOXvqg0UxPQSTfwh7YEhx0aRTXT2OFpr84XPoH2M6xIXfEMkFtJEJ-XlM-ILUZkg3kuBEFN7n4mBK~8L0Ht1QCq8L3~y7YnN61sxC0E9ZdyEOoC~nFJxndri9s9NzgZPo5eo6DsZXweOrTAIVQgKFUozL7WXKMlgqBZ5Nl3ijD6MGCIy0fWYHGLJ4jDBY7wrcfynVXFGm4EBQAEAAcAAA=="
  }};

  /// @brief Test data to verify against Host=Address
  std::vector<std::string> lines;

  /// @brief Addressbook instance
  kovri::client::AddressBook book;
};

BOOST_FIXTURE_TEST_SUITE(AddressBook, SubscriptionFixture)

BOOST_AUTO_TEST_CASE(GoodSubscription) {
  BOOST_CHECK(Validate());
}

BOOST_AUTO_TEST_CASE(EmptyLines) {
  for (auto const& s : subscription)
    lines.push_back(std::string("\n\n" + s + "\n\n"));
  BOOST_CHECK(Validate());
}

BOOST_AUTO_TEST_CASE(WhiteSpaces) {
  for (auto const& s : subscription)
    lines.push_back(std::string(" " + s + " "));
  BOOST_CHECK(Validate());
}

BOOST_AUTO_TEST_CASE(BadHosts) {
  const std::array<std::string, 3> hosts {{ "(_!@*Z", "x9a0f3;21n,", " -123- ", }};  // Etc.
  for (auto const& host : hosts)
    lines.push_back(host + "=AQZGLAMpI9Q0l0kmMj1vpJJYK3CjLp~fE3MfvE-e7KMKjI5cPOH6EN8m794uHJ6b09qM8mb9VEv1lVLEov~usVliTSXCSHuRBOCIwIOuDNU0AbVa4BpIx~2sU4TxKhoaA3zQ6VzINoduTdR2IJhPvI5xzezp7dR21CEQGGTbenDslXeQ4iLHFA2~bzp1f7etSl9T2W9RID-KH78sRQmzWnv7dbhNodMbpO6xsf1vENf6bMRzqD5vgHEHZu2aSoNuPyYxDU1eM6--61b2xp9mt1k3ud-5WvPVg89RaU9ugU5cxaHgR927lHMCAEU2Ax~zUb3DbrvgQBOTHnJEx2Fp7pOK~PnP6ylkYKQMfLROosLDXinxOoSKP0UYCh2WgIUPwE7WzJH3PiJVF0~WZ1dZ9mg00c~gzLgmkOxe1NpFRNg6XzoARivNVB5NuWqNxr5WKWMLBGQ9YHvHO1OHhUJTowb9X90BhtHnLK2AHwO6fV-iHWxRJyDabhSMj1kuYpVUBQAEAAcAAA==");
  BOOST_CHECK(Validate());
}

BOOST_AUTO_TEST_CASE(InvalidHostTLDs) {
  const std::array<std::string, 3> tlds {{ ".com", ".net", ".biz", }};  // Etc.
  for (auto const& tld :tlds)
    lines.push_back("host" + tld + "=AQZGLAMpI9Q0l0kmMj1vpJJYK3CjLp~fE3MfvE-e7KMKjI5cPOH6EN8m794uHJ6b09qM8mb9VEv1lVLEov~usVliTSXCSHuRBOCIwIOuDNU0AbVa4BpIx~2sU4TxKhoaA3zQ6VzINoduTdR2IJhPvI5xzezp7dR21CEQGGTbenDslXeQ4iLHFA2~bzp1f7etSl9T2W9RID-KH78sRQmzWnv7dbhNodMbpO6xsf1vENf6bMRzqD5vgHEHZu2aSoNuPyYxDU1eM6--61b2xp9mt1k3ud-5WvPVg89RaU9ugU5cxaHgR927lHMCAEU2Ax~zUb3DbrvgQBOTHnJEx2Fp7pOK~PnP6ylkYKQMfLROosLDXinxOoSKP0UYCh2WgIUPwE7WzJH3PiJVF0~WZ1dZ9mg00c~gzLgmkOxe1NpFRNg6XzoARivNVB5NuWqNxr5WKWMLBGQ9YHvHO1OHhUJTowb9X90BhtHnLK2AHwO6fV-iHWxRJyDabhSMj1kuYpVUBQAEAAcAAA==");
  BOOST_CHECK(Validate());
}

BOOST_AUTO_TEST_CASE(BadAddresses) {
  const std::array<std::string, 3> addresses {{ "(_!@*Z", "x9a0f3;21n,", " -123- ", }};  // Etc.
  for (auto const& address : addresses)
    lines.push_back("anonimal.i2p=" + address);
  BOOST_CHECK(Validate());
}

BOOST_AUTO_TEST_CASE(GarbageLines) {
  for (std::size_t i = 0; i < subscription.size(); i++) {
    std::array<std::uint8_t, 100> rand;
    kovri::core::RandBytes(rand.data(), rand.size());
    const std::string line(std::begin(rand), std::end(rand));
    lines.push_back(line);
  }
  BOOST_CHECK(Validate());
}

BOOST_AUTO_TEST_CASE(LongLines) {
  for (std::size_t i = 0; i < subscription.size(); i++) {
    const std::string line(book.SubscriptionLine + 1000, 'A');
    lines.push_back(line);
  }
  BOOST_CHECK(Validate());
}

BOOST_AUTO_TEST_CASE(PGPClearSign) {
  const std::string line =
    "-----BEGIN PGP SIGNED MESSAGE-----"
    "Hash: SHA256"
    ""
    "anonimal.i2p=AQZGLAMpI9Q0l0kmMj1vpJJYK3CjLp~fE3MfvE-e7KMKjI5cPOH6EN8m794uHJ6b09qM8mb9VEv1lVLEov~usVliTSXCSHuRBOCIwIOuDNU0AbVa4BpIx~2sU4TxKhoaA3zQ6VzINoduTdR2IJhPvI5xzezp7dR21CEQGGTbenDslXeQ4iLHFA2~bzp1f7etSl9T2W9RID-KH78sRQmzWnv7dbhNodMbpO6xsf1vENf6bMRzqD5vgHEHZu2aSoNuPyYxDU1eM6--61b2xp9mt1k3ud-5WvPVg89RaU9ugU5cxaHgR927lHMCAEU2Ax~zUb3DbrvgQBOTHnJEx2Fp7pOK~PnP6ylkYKQMfLROosLDXinxOoSKP0UYCh2WgIUPwE7WzJH3PiJVF0~WZ1dZ9mg00c~gzLgmkOxe1NpFRNg6XzoARivNVB5NuWqNxr5WKWMLBGQ9YHvHO1OHhUJTowb9X90BhtHnLK2AHwO6fV-iHWxRJyDabhSMj1kuYpVUBQAEAAcAAA=="
    "-----BEGIN PGP SIGNATURE-----"
    ""
    "iQIzBAEBCAAdFiEEEhhics1I4lOeLdKbZqduz5FECfEFAlhYd6MACgkQZqduz5FE"
    "CfFp9RAAm7fzWX/3ojOl+sF9attDNub7FY0kuhgOzhjiUqnoN7lokaHI+EMGtFNz"
    "Mkf48lDwqNWtOQ6aaJSFBUzQC+fn2OrTinfVfIxHvDak8NnMzl1GZh51iZSusaYn"
    "SsJ9pRhxwVIK2VaxlN08UKjMAhlTmxYOKsotEGUCj1hcuIXSeMVpK4Xt4qjJNic4"
    "4i+9t5Lmcz1ZVDwfKIcvvNlW/qXNxyYVIXEnkHDkhPozmgUcPYSjoBk5TKmrAama"
    "BtvYicxdaioHVH01KRi6/tPCZ7KgwvgB/LAIIMLZVsh3dVt7K9uoKZKTvRHVLJiq"
    "25TegnZgVYtoHiW088Y9Yqj72NpQO8KvWD8rSnj4UymMZgRclEX1m5Q2ke8EohDZ"
    "20cBPSOpMg5P6c0CsLXlGw8DwyeYYlA45va4BxAUGAIKTaC3aw6+T7C6pCs4Xv7G"
    "ufUzlGclVhwla5SAAvgL2U4ux8zxCg01PdOdXR8gRLKzfoabCsSuTFLWQB+wpqLu"
    "fVcY4VzH8FlT18ZWoJYgMR2Z1NHGWpalhm24cc8XCXPv3wfAsSdAU1PTMyG7Lfna"
    "8Z7DUkJcRcOnmfW+zB/NO4LoffOMXdQZTtM8K77sDTqKLGUaPoARwgMgGkfBOPC8"
    "eHM9ZXgdxRBeOQhEaVEre4n3+2NYDzB9rfZmGCRsm9lr6MKcrTE="
    "=P8Ug"
    "-----END PGP SIGNATURE-----";
  lines.push_back(line);
  BOOST_CHECK(Validate());
}

BOOST_AUTO_TEST_CASE(ValidBookEntry) {
  // Test constructing from a subscription line
  BOOST_CHECK_NO_THROW(kovri::client::BookEntry entry(subscription.front()));
  kovri::client::BookEntry entry(subscription.front());

  // Test constructing from an identity hash
  BOOST_CHECK_NO_THROW(
      kovri::client::BookEntry e("kovri.i2p", entry.get_address()));

  // Test constructing from a base64-encoded address
  std::string const valid_dest =
      subscription.front().substr(subscription.front().find('=') + 1);
  BOOST_CHECK_NO_THROW(kovri::client::BookEntry e("kovri.i2p", valid_dest));
}

BOOST_AUTO_TEST_CASE(InvalidBookEntry) {
  std::string const valid_dest =
      subscription.front().substr(subscription.front().find('=') + 1);
  kovri::core::IdentityEx ident;
  BOOST_CHECK_NO_THROW(ident.FromBase64(valid_dest));
  ident.FromBase64(valid_dest);

  // Empty Kovri hostname w/ base64-encoded address
  BOOST_CHECK_THROW(
      kovri::client::BookEntry entry("", valid_dest), std::invalid_argument);
  // Empty Kovri hostname w/ identity hash address
  BOOST_CHECK_THROW(
      kovri::client::BookEntry entry("", ident.GetIdentHash()),
      std::invalid_argument);
  // Garbage Kovri address
  BOOST_CHECK_THROW(
      kovri::client::BookEntry entry("kovri.i2p", "QnNcMfHF"),
      std::runtime_error);
  // Empty Kovri address
  BOOST_CHECK_THROW(
      kovri::client::BookEntry entry("kovri.i2p", ""), std::runtime_error);
  // Subscription line with no hostname
  BOOST_CHECK_THROW(
      kovri::client::BookEntry entry("=" + valid_dest), std::runtime_error);
  // Subscription line with no address
  BOOST_CHECK_THROW(
      kovri::client::BookEntry entry("kovri.i2p="), std::runtime_error);
  // Garbage subscription line
  BOOST_CHECK_THROW(
      kovri::client::BookEntry entry("QnNcMfHF"), std::runtime_error);
  // Empty subscription line
  BOOST_CHECK_THROW(kovri::client::BookEntry entry(""), std::invalid_argument);
}
// TODO(unassigned): more cases?

BOOST_AUTO_TEST_CASE(RejectDuplicateEntry)
{
  BOOST_CHECK_NO_THROW(kovri::client::BookEntry entry(subscription.front()));
  kovri::client::BookEntry entry(subscription.front());

  // Ensure valid entry is inserted
  BOOST_CHECK_NO_THROW(
      book.InsertAddress(
          entry.get_host(),
          entry.get_address(),
          kovri::client::AddressBook::SubscriptionType::Default));
  // Ensure address book throws for duplicate host
  BOOST_CHECK_THROW(
      book.InsertAddress(
          entry.get_host(),
          entry.get_address(),
          kovri::client::AddressBook::SubscriptionType::Default),
      std::runtime_error);
  // Ensure address book throws for duplicate address
  BOOST_CHECK_THROW(
      book.InsertAddress(
          "unique." + entry.get_host(),
          entry.get_address(),
          kovri::client::AddressBook::SubscriptionType::Default),
      std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()
