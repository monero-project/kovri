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

#include "src/core/crypto/hash.h"
#include "src/core/router/identity.h"
#include "src/core/router/info.h"

#include "src/core/router/tunnel/config.h"

struct TunnelConfigFixture
{
  TunnelConfigFixture()
  {
    BOOST_CHECK_NO_THROW(hop = CreateTunnelHop());
  }

  std::unique_ptr<core::TunnelHopConfig> CreateTunnelHop()
  {
    const std::vector<std::pair<std::string, std::uint16_t>> points{
        {"127.0.0.1", 9111}};
    const std::pair<bool, bool> transports{true, false};

    return std::make_unique<core::TunnelHopConfig>(
        std::make_shared<const core::RouterInfo>(
            core::PrivateKeys::CreateRandomKeys(
                core::DEFAULT_ROUTER_SIGNING_KEY_TYPE),
            points,
            transports,
            0x80));
  }

  void CheckCreateBuildRequest(const std::uint32_t reply_ID)
  {
    core::InputByteStream reader(clear_record.data(), clear_record.size());

    BOOST_CHECK_EQUAL(hop->GetTunnelID(), reader.Read<std::uint32_t>());

    const auto& ident = hop->GetCurrentRouter()->GetIdentHash();
    const std::uint8_t* stream_ident = reader.ReadBytes(ident.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(
        ident(),
        ident() + ident.size(),
        stream_ident,
        stream_ident + ident.size());

    BOOST_CHECK_EQUAL(hop->GetNextTunnelID(), reader.Read<std::uint32_t>());

    const auto& next_ident = hop->GetNextRouter()->GetIdentHash();
    const std::uint8_t* next_stream_ident = reader.ReadBytes(next_ident.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(
        next_ident(),
        next_ident() + next_ident.size(),
        next_stream_ident,
        next_stream_ident + next_ident.size());

    const auto& aes = hop->GetAESAttributes();
    const std::uint8_t* layer_key = reader.ReadBytes(aes.layer_key.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(
        aes.layer_key.data(),
        aes.layer_key.data() + aes.layer_key.size(),
        layer_key,
        layer_key + aes.layer_key.size());

    const std::uint8_t* IV_key = reader.ReadBytes(aes.IV_key.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(
        aes.IV_key.data(),
        aes.IV_key.data() + aes.IV_key.size(),
        IV_key,
        IV_key + aes.IV_key.size());

    const std::uint8_t* reply_key = reader.ReadBytes(aes.reply_key.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(
        aes.reply_key.data(),
        aes.reply_key.data() + aes.reply_key.size(),
        reply_key,
        reply_key + aes.reply_key.size());

    const std::uint8_t* reply_IV = reader.ReadBytes(aes.reply_IV.size());

    BOOST_CHECK_EQUAL_COLLECTIONS(
        aes.reply_IV.data(),
        aes.reply_IV.data() + aes.reply_IV.size(),
        reply_IV,
        reply_IV + aes.reply_IV.size());

    if (hop->IsGateway())
      BOOST_CHECK_EQUAL(0x80, reader.Read<std::uint8_t>());
    else if (hop->IsEndpoint())
      BOOST_CHECK_EQUAL(0x40, reader.Read<std::uint8_t>());
    else
      BOOST_CHECK_EQUAL(0x00, reader.Read<std::uint8_t>());

    BOOST_CHECK_EQUAL(core::GetHoursSinceEpoch(), reader.Read<std::uint32_t>());

    BOOST_CHECK_EQUAL(reply_ID, reader.Read<std::uint32_t>());
  }

  std::unique_ptr<core::TunnelHopConfig> hop;
  std::shared_ptr<core::TunnelConfig> tunnel;
  core::ClearBuildRequestRecord clear_record;
};

BOOST_AUTO_TEST_CASE(NullHop)
{
  BOOST_CHECK_THROW(core::TunnelHopConfig c(nullptr), std::exception);
}

BOOST_AUTO_TEST_CASE(NullTunnel)
{
  BOOST_CHECK_THROW(core::TunnelConfig c({nullptr}, nullptr), std::exception);
}

BOOST_FIXTURE_TEST_CASE(BuildRequestRecord, TunnelConfigFixture)
{
  constexpr std::uint32_t reply_ID{0x42};
  BOOST_CHECK_NO_THROW(
      hop->SetNextRouter(CreateTunnelHop()->GetCurrentRouter(), 0x90));

  // Create participant build request record
  BOOST_CHECK_NO_THROW(hop->CreateBuildRequestRecord(clear_record, reply_ID));
  BOOST_CHECK_NO_THROW(CheckCreateBuildRequest(reply_ID));

  // Create endpoint build request record
  hop->SetIsEndpoint(true);
  BOOST_CHECK_NO_THROW(hop->CreateBuildRequestRecord(clear_record, reply_ID));
  BOOST_CHECK_NO_THROW(CheckCreateBuildRequest(reply_ID));

  // Create gateway build request record
  hop->SetIsGateway(true);
  BOOST_CHECK_NO_THROW(hop->CreateBuildRequestRecord(clear_record, reply_ID));
  BOOST_CHECK_NO_THROW(CheckCreateBuildRequest(reply_ID));
}

BOOST_FIXTURE_TEST_CASE(InvalidBuildRequestRecord, TunnelConfigFixture)
{
  BOOST_CHECK_NO_THROW(
      hop->SetNextRouter(CreateTunnelHop()->GetCurrentRouter(), 0x90));

  // Reply ID cannot be zero
  BOOST_CHECK_THROW(
      hop->CreateBuildRequestRecord(clear_record, 0x00), std::exception);
}

BOOST_FIXTURE_TEST_CASE(EncryptRecord, TunnelConfigFixture)
{
  constexpr std::uint8_t hop_ident_size{16};
  core::EncryptedBuildRequestRecord encrypted_record{{}};
  const auto& ident = hop->GetCurrentRouter()->GetIdentHash();

  BOOST_CHECK_NO_THROW(hop->EncryptRecord(clear_record, encrypted_record));
  BOOST_CHECK_EQUAL_COLLECTIONS(
      ident(),
      ident() + hop_ident_size,
      encrypted_record.data(),
      encrypted_record.data() + hop_ident_size);
}

BOOST_FIXTURE_TEST_CASE(TunnelConfig, TunnelConfigFixture)
{
  std::vector<std::shared_ptr<const core::RouterInfo>> peers{
      hop->GetCurrentRouter()};

  // Create inbound tunnel
  BOOST_CHECK_NO_THROW(
      tunnel = std::make_shared<core::TunnelConfig>(peers, nullptr));
  BOOST_CHECK(tunnel->IsInbound());

  // Create outbound tunnel
  BOOST_CHECK_NO_THROW(
      tunnel = std::make_shared<core::TunnelConfig>(peers, tunnel));
  BOOST_CHECK(!tunnel->IsInbound());

  BOOST_CHECK_EQUAL(peers.size(), tunnel->GetNumHops());
  BOOST_CHECK_EQUAL(
      tunnel->GetFirstHop()->GetCurrentRouter()->GetIdentHash(),
      tunnel->GetLastHop()->GetCurrentRouter()->GetIdentHash());
}

BOOST_FIXTURE_TEST_CASE(InvertTunnel, TunnelConfigFixture)
{
  std::shared_ptr<core::TunnelConfig> inverted;
  std::vector<std::shared_ptr<const core::RouterInfo>> peers{
      hop->GetCurrentRouter(), CreateTunnelHop()->GetCurrentRouter()};

  // Create inbound tunnel
  BOOST_CHECK_NO_THROW(
      tunnel = std::make_shared<core::TunnelConfig>(peers, nullptr));
  BOOST_CHECK(tunnel->IsInbound());

  // Invert tunnel
  BOOST_CHECK_NO_THROW(inverted = tunnel->Invert());
  BOOST_CHECK(!inverted->IsInbound());

  BOOST_CHECK_EQUAL(tunnel->GetNumHops(), inverted->GetNumHops());

  BOOST_CHECK_EQUAL(
      inverted->GetFirstHop()->GetCurrentRouter()->GetIdentHash(),
      tunnel->GetLastHop()->GetCurrentRouter()->GetIdentHash());

  BOOST_CHECK_EQUAL(
      inverted->GetLastHop()->GetCurrentRouter()->GetIdentHash(),
      tunnel->GetFirstHop()->GetCurrentRouter()->GetIdentHash());

  BOOST_CHECK_EQUAL(
      inverted->GetFirstHop()->GetNextHop()->GetCurrentRouter()->GetIdentHash(),
      tunnel->GetLastHop()->GetPreviousHop()->GetCurrentRouter()->GetIdentHash());
}
