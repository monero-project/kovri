/**
 * Copyright (c) 2015-2018, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "tests/unit_tests/main.h"

#include "src/client/api/datagram.h"
#include "src/core/crypto/util/compression.h"

namespace core = kovri::core;
namespace client = kovri::client;

struct DatagramFixture
{
  void make_datagram_dest(bool dsa = false)
  {
    auto const type = dsa ? core::SIGNING_KEY_TYPE_DSA_SHA1
                          : core::SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519;
    client = std::make_unique<client::ClientDestination>(
        core::PrivateKeys::CreateRandomKeys(type), true /*is_public*/);
    datagram = std::make_unique<client::DatagramDestination>(*client);
  }

  template <std::size_t Size = 5>
  std::vector<std::uint8_t> prepare_payload(bool dsa = false)
  {
    make_datagram_dest(dsa);
    auto const& id = client->GetPrivateKeys().GetPublic();
    // Prepare the payload
    std::array<std::uint8_t, Size> p{0x42};
    // Prepare the signature
    std::size_t const sig_size = id.GetSignatureLen();
    std::uint8_t sig_buf[sig_size];
    client->GetPrivateKeys().Sign(p.data(), p.size(), sig_buf);
    // Prepare the packet
    std::size_t const id_size = id.GetFullLen();
    std::uint8_t id_buf[id_size];
    std::vector<std::uint8_t> packet(id_size + sig_size + p.size());
    id.ToBuffer(id_buf, id_size);
    // Copy identity to the packet
    packet.insert(packet.begin(), id_buf, id_buf + id_size);
    // Copy signature to the packet
    packet.insert(packet.end(), sig_buf, sig_buf + sig_size);
    // Copy payload to the packet
    packet.insert(packet.end(), p.begin(), p.end());
    // Gzip the packet
    core::Gzip gz;
    gz.Put(packet.data(), packet.size());
    std::vector<std::uint8_t> out(gz.MaxRetrievable());
    gz.Get(out.data(), out.size());
    return out;
  }

  std::unique_ptr<client::ClientDestination> client;
  std::unique_ptr<client::DatagramDestination> datagram;
};

BOOST_FIXTURE_TEST_SUITE(DatagramTests, DatagramFixture)

BOOST_AUTO_TEST_CASE(DefaultDatagram)
{
  BOOST_CHECK_NO_THROW(make_datagram_dest());
}

BOOST_AUTO_TEST_CASE(SendDatagramTo)
{
  std::array<std::uint8_t, 256> p{0x42};

  make_datagram_dest();
  BOOST_CHECK_NO_THROW(datagram->SendDatagramTo(p.data(), p.size(), {}, 0, 0));

  make_datagram_dest(true /*dsa*/);
  BOOST_CHECK_NO_THROW(datagram->SendDatagramTo(p.data(), p.size(), {}, 0, 0));
}

BOOST_AUTO_TEST_CASE(BadSendDatagramTo)
{
  make_datagram_dest();
  BOOST_CHECK_THROW(
      datagram->SendDatagramTo(nullptr, 0, {}, 0, 0), std::exception);
}

BOOST_AUTO_TEST_CASE(HandleDataMessagePayload)
{
  // Prepare Ed25519 signed payload
  auto const out = prepare_payload();
  BOOST_CHECK_NO_THROW(
      datagram->HandleDataMessagePayload(0, 0, out.data(), out.size()));

  // Prepare DSA signed payload
  auto const out_dsa = prepare_payload(true /*dsa*/);
  BOOST_CHECK_NO_THROW(
      datagram->HandleDataMessagePayload(0, 0, out_dsa.data(), out_dsa.size()));
}

BOOST_AUTO_TEST_CASE(BadHandleDataMessagePayload)
{
  // Prepare oversized payload
  auto out = prepare_payload<client::MAX_DATAGRAM_SIZE + 1>(false);
  BOOST_CHECK_NO_THROW(
      datagram->HandleDataMessagePayload(0, 0, out.data(), out.size()));
}

BOOST_AUTO_TEST_CASE(SetReceiver)
{
  auto const r = [](const kovri::core::IdentityEx&,
                    std::uint16_t,
                    std::uint16_t,
                    const std::uint8_t*,
                    std::size_t) {};
  make_datagram_dest();
  BOOST_CHECK_NO_THROW(datagram->SetReceiver(r));
  BOOST_CHECK_NO_THROW(datagram->SetReceiver(r, 0));
}

BOOST_AUTO_TEST_CASE(ResetReceiver)
{
  make_datagram_dest();
  BOOST_CHECK_NO_THROW(datagram->ResetReceiver());
  BOOST_CHECK_NO_THROW(datagram->ResetReceiver(0));
}

BOOST_AUTO_TEST_SUITE_END()
