/**                                                                                           //
 * Copyright (c) 2013-2018, The Kovri I2P Router Project                                      //
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

#include "core/router/transports/ssu/session.h"

#include <boost/bind.hpp>
#include <boost/endian/conversion.hpp>

#include "core/crypto/diffie_hellman.h"
#include "core/crypto/hash.h"
#include "core/crypto/rand.h"

#include "core/router/context.h"
#include "core/router/transports/ssu/packet.h"
#include "core/router/transports/ssu/server.h"
#include "core/router/transports/impl.h"

#include "core/util/byte_stream.h"
#include "core/util/log.h"
#include "core/util/timestamp.h"

namespace kovri {
namespace core {

// TODO(anonimal): session message creation/processing should be separated from
//  network session implementation and templated where possible.

// TODO(anonimal): bytestream refactor

std::uint8_t* SSUSessionPacket::MAC() const {
  return data;
}

std::uint8_t* SSUSessionPacket::IV() const {
  return data + std::size_t(16);
}

void SSUSessionPacket::PutFlag(
    std::uint8_t flag) const {
  data[32] = flag;
}

void SSUSessionPacket::PutTime(
    std::uint32_t time) const {
  return core::OutputByteStream::Write<std::uint32_t>(&data[33], time);
}

std::uint8_t* SSUSessionPacket::Encrypted() const {
  return data + std::size_t(32);
}

SSUSession::SSUSession(
    SSUServer& server,
    boost::asio::ip::udp::endpoint& remote_endpoint,
    std::shared_ptr<const kovri::core::RouterInfo> router,
    bool peer_test)
    : TransportSession(router),
      m_Server(server),
      m_RemoteEndpoint(remote_endpoint),
      m_Timer(GetService()),
      m_PeerTest(peer_test),
      m_State(SessionState::Unknown),
      m_IsSessionKey(false),
      m_RelayTag(0),
      m_Data(*this),
      m_IsDataReceived(false),
      m_Exception(__func__) {
  m_CreationTime = kovri::core::GetSecondsSinceEpoch();
}

SSUSession::~SSUSession() {}

boost::asio::io_service& SSUSession::GetService() {
  return m_Server.GetService();
}

bool SSUSession::CreateAESandMACKey(
    const std::uint8_t* pub_key) {
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    kovri::core::DiffieHellman dh;
    std::array<std::uint8_t, 256> shared_key;
    if (!dh.Agree(shared_key.data(), m_DHKeysPair->private_key.data(), pub_key)) {
      LOG(error)
        << "SSUSession:" << GetFormattedSessionInfo()
        << "couldn't create shared key";
      return false;
    }
    std::uint8_t* session_key = m_SessionKey();
    std::uint8_t* mac_key = m_MACKey();
    if (shared_key.at(0) & 0x80) {
      session_key[0] = 0;
      memcpy(session_key + 1, shared_key.data(), 31);
      memcpy(mac_key, shared_key.data() + 31, 32);
    } else if (shared_key.at(0)) {
      memcpy(session_key, shared_key.data(), 32);
      memcpy(mac_key, shared_key.data() + 32, 32);
    } else {
      // find first non-zero byte
      auto non_zero = shared_key.data() + 1;
      while (!*non_zero) {
        non_zero++;
        if (non_zero - shared_key.data() > 32) {
          LOG(warning)
            << "SSUSession:" << GetFormattedSessionInfo()
            << "first 32 bytes of shared key is all zeros. Ignored";
          return false;
        }
      }
      memcpy(session_key, non_zero, 32);
      kovri::core::SHA256().CalculateDigest(
          mac_key,
          non_zero,
          64 - (non_zero - shared_key.data()));
    }
    m_SessionKeyEncryption.SetKey(m_SessionKey);
    m_SessionKeyDecryption.SetKey(m_SessionKey);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
  return m_IsSessionKey = true;
}

/**
 *
 * Process encrypted/decrypted SSU messages
 *
 */

// TODO(anonimal): separate message validation / decryption from session
void SSUSession::ProcessNextMessage(
    std::uint8_t* buf,
    std::size_t len,
    const boost::asio::ip::udp::endpoint& sender_endpoint)
{
  try
    {
      if (!len && m_State != SessionState::Introduced)
        {
          LOG(warning) << "SSUSession:" << GetFormattedSessionInfo()
                       << ": ignoring zero-length message (expecting HolePunch)";
          return;  // TODO(anonimal): throw/warn for potential attacks
        }

      assert(buf);
      LOG(trace) << "SSUSession:" << GetFormattedSessionInfo() << __func__
                 << GetFormattedHex(buf, len);

      // Update session received byte count
      m_NumReceivedBytes += len;
      LOG(debug) << "SSUSession:" << GetFormattedSessionInfo() << "--> " << len
                 << " bytes transferred, " << m_NumReceivedBytes
                 << " total bytes received";

      // Update total received bytes during router run
      core::transports.UpdateReceivedBytes(len);

      switch (m_State)
        {
          case SessionState::Introduced:
            {
              // TODO(anonimal): verify
              LOG(debug) << "SSUSession: SSU HolePunch received";
              m_State = SessionState::Unknown;
              // Proceed to SessionRequest
              Connect();
              return;
            }
            break;
          case SessionState::Established:
            {
              // No further messages expected from this session
              ScheduleTermination();
            }
            break;
          case SessionState::Unknown:
            // Continue to message processing
            break;
          default:
            LOG(debug) << "SSUSession:" << GetFormattedSessionInfo() << __func__
                       << ": session state="
                       << static_cast<std::uint16_t>(m_State);

            throw std::invalid_argument("SSUSession: invalid session state");
            break;
        }

      // Validate message using either session key or introducer key
      const bool is_session(m_IsSessionKey);
      const std::uint8_t* key = is_session ? m_MACKey() : GetIntroKey();
      assert(key);

      // HMAC-MD5 validation
      if (!Validate(buf, len, key))
        {
          LOG(trace) << GetFormattedSessionInfo() << __func__
                     << ": Key=" << GetFormattedHex(key, 32);

          throw std::runtime_error(
              "SSUSession:" + (is_session ? GetFormattedSessionInfo() : " ")
              + "MAC verification failed with "
              + (is_session ? "session key" : "introducer key"));
        }

      // Decrypt message using given key or existing session keys
      Decrypt(buf, len, key, is_session);
      ProcessDecryptedMessage(buf, len, sender_endpoint);
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      m_Server.DeleteSession(shared_from_this());
      return;  // TODO(anonimal): throw/warn for potential attacks
    }
}

void SSUSession::ProcessDecryptedMessage(
    std::uint8_t* buf,
    std::size_t len,
    const boost::asio::ip::udp::endpoint& sender_endpoint) {
  len -= (len & 0x0F);  // %16, delete extra padding
  SSUPacketParser parser(buf, len);
  std::unique_ptr<SSUPacket> packet;
  try
    {
      packet = parser.ParsePacket();
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      throw;
    }
  switch (packet->GetHeader()->GetPayloadType()) {
    case SSUPayloadType::Data:
      ProcessData(packet.get());
      break;
    case SSUPayloadType::SessionRequest:
      ProcessSessionRequest(packet.get(), sender_endpoint);
      break;
    case SSUPayloadType::SessionCreated:
      ProcessSessionCreated(packet.get());
      break;
    case SSUPayloadType::SessionConfirmed:
      ProcessSessionConfirmed(packet.get());
      break;
    case SSUPayloadType::PeerTest:
      LOG(debug) << "SSUSession: PeerTest received";
      ProcessPeerTest(packet.get(), sender_endpoint);
      break;
    case SSUPayloadType::SessionDestroyed:
      LOG(debug) << "SSUSession: SessionDestroy received";
      m_Server.DeleteSession(shared_from_this());
      break;
    case SSUPayloadType::RelayResponse:
      ProcessRelayResponse(packet.get());
      if (m_State != SessionState::Established)
        m_Server.DeleteSession(shared_from_this());
      break;
    case SSUPayloadType::RelayRequest:
      LOG(debug) << "SSUSession: RelayRequest received";
      ProcessRelayRequest(packet.get(), sender_endpoint);
      break;
    case SSUPayloadType::RelayIntro:
      LOG(debug) << "SSUSession: RelayIntro received";
      ProcessRelayIntro(packet.get());
      break;
    default:
      LOG(warning)
        << "SSUSession: unexpected payload type: "
        << static_cast<int>(packet->GetHeader()->GetPayloadType());
  }
}

/**
 * SSU messages (payload types)
 * ------------------------
 *
 *  There are 10 defined SSU messages:
 *
 *  0 SessionRequest
 *  1 SessionCreated
 *  2 SessionConfirmed
 *  3 RelayRequest
 *  4 RelayResponse
 *  5 RelayIntro
 *  6 Data
 *  7 PeerTest
 *  8 SessionDestroyed (implemented as of 0.8.9)
 *  n/a HolePunch
 */

/**
 *
 * Payload type 0: SessionRequest
 *
 */

void SSUSession::ProcessSessionRequest(
    SSUPacket* pkt,
    const boost::asio::ip::udp::endpoint& sender_endpoint) {
  // We cannot handle session request if we are outbound
  if (IsOutbound()) {
    return;
  }
  LOG(debug) << "SSUSession: SessionRequest received";
  auto packet = static_cast<SSUSessionRequestPacket*>(pkt);
  SetRemoteEndpoint(sender_endpoint);
  if (!m_DHKeysPair)
    m_DHKeysPair = transports.GetNextDHKeysPair();
  if (!CreateAESandMACKey(packet->GetDhX())) {
    LOG(error)
      << "SSUSession:" << GetFormattedSessionInfo()
      << "invalid DH-X, not sending SessionCreated";
    return;
  }
  SendSessionCreated(packet->GetDhX());
}

// TODO(anonimal): separate message creation from session
void SSUSession::SendSessionRequest()
{
  LOG(debug) << "SSUSession:" << GetFormattedSessionInfo()
             << "sending SessionRequest";

  // Create message
  SSUSessionRequestPacket message;
  message.SetHeader(
      std::make_unique<SSUHeader>(SSUPayloadType::SessionRequest));

  // Set IV
  std::array<std::uint8_t, SSUSize::IV> IV;
  core::RandBytes(IV.data(), IV.size());
  message.GetHeader()->SetIV(IV.data());

  // Set our (Alice's) DH X
  message.SetDhX(m_DHKeysPair->public_key.data());

  // Set Bob's address size and address
  auto const remote_ip(core::AddressToByteVector(m_RemoteEndpoint.address()));

  // TODO(unassigned): remove const_cast, see bytestream TODO
  message.SetIPAddress(
      const_cast<std::uint8_t*>(remote_ip.data()), remote_ip.size());

  // Fill header extended options
  // TODO(anonimal): review, implement
  std::array<std::uint8_t, 2> options{{0x00, 0x00}};
  if (context.GetState() == RouterState::OK)
    {  // we don't need relays
      message.GetHeader()->SetExtendedOptions(true);
      message.GetHeader()->SetExtendedOptionsData(
          options.data(), options.size());
    }

  // Create encrypted message buffer
  std::vector<std::uint8_t> buf(
      SSUPacketBuilder::GetPaddedSize(message.GetSize())
      + SSUSize::BufferMargin);

  // Get Bob's introducer key for AES and MAC
  const std::uint8_t* intro_key = GetIntroKey();
  assert(intro_key);

  // Encrypt and send
  WriteAndEncrypt(&message, buf.data(), buf.size(), intro_key, intro_key);
  m_Server.Send(
      buf.data(), buf.size() - SSUSize::BufferMargin, m_RemoteEndpoint);
}

/**
 *
 * Payload type 1: SessionCreated
 *
 */

void SSUSession::ProcessSessionCreated(const SSUPacket* packet)
{
  // TODO(anonimal): this try block should be handled entirely by caller
  try
    {
      LOG(debug) << "SSUSession:" << GetFormattedSessionInfo()
                 << "SessionCreated received, processing";

      if (!m_RemoteRouter || !m_DHKeysPair)
        {
          LOG(warning) << "SSUSession:" << GetFormattedSessionInfo()
                       << "unsolicited SessionCreated message";
          return;  // TODO(anonimal): throw/assert?
        }

      // TODO(anonimal): continue review of timer management. Connect timer is
      //  canceled when it expires after sending SessionRequest, and is also canceled
      //  once the session is established - so we should not need to cancel here.
      //  Note: canceling also does not reset expiration time.

      assert(packet);
      const auto* message = static_cast<const SSUSessionCreatedPacket*>(packet);

      // Complete SessionRequest DH agreement using Bob's DH Y
      if (!CreateAESandMACKey(message->GetDhY()))
        {
          LOG(error) << "SSUSession:" << GetFormattedSessionInfo()
                     << "invalid DH-Y, not sending SessionConfirmed";
          return;  // TODO(anonimal): assert/throw?
        }

      // Create dataset of exchanged session data (the dataset Bob has signed)
      // TODO(anonimal): at this point, why would we allow mix-and-match IPv6 to send to IPv4 - or vice versa...
      bool const is_IPv6 = m_RemoteEndpoint.address().is_v6();
      core::OutputByteStream data(get_signed_data_size(
          message->GetIPAddressSize() + (is_IPv6 ? 16 : 4)));

      // Our (Alice's) DH X
      data.WriteData(m_DHKeysPair->public_key.data(), DHKeySize::PubKey);

      // Bob's DH Y
      data.WriteData(message->GetDhY(), DHKeySize::PubKey);

      // Our (Alice's) IP and port
      data.WriteData(message->GetIPAddress(), message->GetIPAddressSize());
      data.Write<std::uint16_t>(message->GetPort());

      // Bob's IP address
      data.WriteData(
          is_IPv6 ? m_RemoteEndpoint.address().to_v6().to_bytes().data()
                  : m_RemoteEndpoint.address().to_v4().to_bytes().data(),
          is_IPv6 ? 16 : 4);

      // Bob's port
      data.Write<std::uint16_t>(m_RemoteEndpoint.port());

      // Our (Alice's) relay tag
      data.Write<std::uint32_t>(m_RelayTag = message->GetRelayTag());

      // Bob's signed-on time
      data.Write<std::uint32_t>(message->GetSignedOnTime());

      // Get Bob's padded signature length
      std::uint8_t const signature_len =
          SSUPacketBuilder::GetPaddedSize(m_RemoteIdentity.GetSignatureLen());

      // Prepare decrypted-signature buffer
      std::vector<std::uint8_t> signature(signature_len);

      // Use Bob's IV to decrypt signature using our negotiated session key
      m_SessionKeyDecryption.SetIV(message->GetHeader()->GetIV());

      // Decrypt signature
      m_SessionKeyDecryption.Decrypt(
          message->GetSignature(), signature.size(), signature.data());

      // TODO(anonimal): log debug of encrypted/decrypted sig + message data

      // Verify signed dataset
      if (!m_RemoteIdentity.Verify(data.Data(), data.Size(), signature.data()))
        {
          LOG(error) << "SSUSession:" << GetFormattedSessionInfo()
                     << "SessionCreated signature verification failed";
          // TODO(anonimal): review if Java routers resend the message on failure.
          //   Instead of immediately resetting session key, we can explore ways
          //   to observe and mitigate potential attacks. Another possible case
          //   for failure:
          //     "If Bob's NAT/firewall has mapped his internal port to a
          //     different external port, and Bob is unaware of it, the
          //     verification by Alice will fail."
          m_IsSessionKey = false;
          return;  // TODO(anonimal): throw/assert?
        }

      // An SSU'ism: update our external address as perceived by Bob
      context.UpdateAddress(
          message->GetIPAddress(),
          message->GetIPAddressSize(),
          message->GetPort());

      // Session created, create/send confirmation
      SendSessionConfirmed(
          message->GetDhY(),
          message->GetIPAddress(),
          message->GetIPAddressSize(),
          message->GetPort());
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      // TODO(anonimal): ensure exception handling by callers
      throw;
    }
}

// TODO(anonimal): separate message creation / signed data writing from session
void SSUSession::SendSessionCreated(const std::uint8_t* dh_x)
{
  // TODO(anonimal): this try block should be handled entirely by caller
  try
    {
      // Get our (Bob's) intro key and SSU address
      // TODO(anonimal): we can get/set this sooner. Redesign.
      const std::uint8_t* intro_key = GetIntroKey();
      auto* address = m_RemoteEndpoint.address().is_v6()
                          ? context.GetRouterInfo().GetSSUAddress(true)
                          : context.GetRouterInfo().GetSSUAddress();

      // If we don't support SSU, we shouldn't reach this stage in the session
      assert(intro_key || address);  // TODO(anonimal): redesign

      // Prepare SessionConfirmed message to send to Alice
      SSUSessionCreatedPacket message;
      message.SetHeader(
          std::make_unique<SSUHeader>(SSUPayloadType::SessionCreated));

      // Set IV
      std::array<std::uint8_t, SSUSize::IV> IV;
      kovri::core::RandBytes(IV.data(), IV.size());
      message.GetHeader()->SetIV(IV.data());

      // Set our (Bob's) DH Y
      message.SetDhY(m_DHKeysPair->public_key.data());

      // Set Alice's IP address size and address
      auto const alice_ip(
          core::AddressToByteVector(m_RemoteEndpoint.address()));

      message.SetIPAddress(
          // TODO(unassigned): remove const_cast, see bytestream TODO
          const_cast<std::uint8_t*>(alice_ip.data()),
          alice_ip.size());  // message IP address size must be set internally

      // Set Alice's port
      message.SetPort(m_RemoteEndpoint.port());

      // Compute exchanged session dataset size
      // TODO(anonimal): at this point, why would we allow mix-and-match IPv6 to send to IPv4 - or vice versa...
      bool const is_IPv6 = address->host.is_v6();
      std::uint16_t const data_size =
          get_signed_data_size(alice_ip.size() + (is_IPv6 ? 16 : 4));

      // Prepare dataset of exchanged session data (the dataset we will sign)
      // TODO(anonimal): assert for bad design. Redesign.
      assert(!m_SessionConfirmData.size());
      m_SessionConfirmData.reserve(data_size);

      core::OutputByteStream data(m_SessionConfirmData.data(), data_size);

      // Alice's DH X
      data.WriteData(dh_x, SSUSize::DHPublic);

      // Our (Bob's) DH Y
      data.WriteData(message.GetDhY(), SSUSize::DHPublic);

      // Alice's address and port
      data.WriteData(alice_ip.data(), alice_ip.size());
      data.Write<std::uint16_t>(message.GetPort());

      // Our (Bob's) address
      data.WriteData(
          is_IPv6 ? address->host.to_v6().to_bytes().data()
                  : address->host.to_v4().to_bytes().data(),
          is_IPv6 ? 16 : 4);

      // Our (Bob's) port
      data.Write<std::uint16_t>(address->port);

      // Set Alice's relay tag
      std::uint32_t relay_tag = 0;
      if (context.GetRouterInfo().HasCap(RouterInfo::Cap::SSUIntroducer))
        {
          // Non-zero = we are offering ourselves to be an introducer
          relay_tag = core::Rand<std::uint32_t>();
          if (!relay_tag)
            {
              // TODO(anonimal): ...not good if should we have more than one relay
              //  with tag valued 1. Get existing tags and set appropriately.
              relay_tag = 1;
            }
          m_Server.AddRelay(relay_tag, m_RemoteEndpoint);
        }
      message.SetRelayTag(relay_tag);
      data.Write<std::uint32_t>(relay_tag);

      // Our (Bob's) signed-on time
      message.SetSignedOnTime(core::GetSecondsSinceEpoch());
      data.Write<std::uint32_t>(message.GetSignedOnTime());

      // Compute required signature + padding size
      std::uint8_t signature_size = context.GetIdentity().GetSignatureLen();
      std::uint8_t const padding =
          SSUPacketBuilder::GetPaddingSize(message.GetSize() + signature_size);

      // Create the signature + padding
      std::vector<std::uint8_t> signature(signature_size + padding);
      context.GetPrivateKeys().Sign(data.Data(), data.Size(), signature.data());

      // Randomize signature padding
      core::RandBytes(signature.data() + signature_size, padding);
      message.SetSignature(signature.data(), signature.size());

      // Encrypt signature + padding with session key
      std::vector<std::uint8_t> encrypted(message.GetSignatureSize());

      m_SessionKeyEncryption.SetIV(message.GetHeader()->GetIV());
      m_SessionKeyEncryption.Encrypt(
          message.GetSignature(), encrypted.size(), encrypted.data());

      message.SetSignature(encrypted.data(), encrypted.size());

      // Encrypt message with Alice's intro key and send
      std::uint16_t const size =
          SSUPacketBuilder::GetPaddedSize(message.GetSize());
      // TODO(anonimal): IPv6 MTU...
      if (size <= SSUSize::MTUv4)
        {
          std::vector<std::uint8_t> buf(size + SSUSize::BufferMargin);
          WriteAndEncrypt(
              &message, buf.data(), buf.size(), intro_key, intro_key);
          Send(buf.data(), buf.size() - SSUSize::BufferMargin);
        }
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      // TODO(anonimal): ensure exception handling by callers
      throw;
    }
}

/**
 *
 * Payload type 2: SessionConfirmed
 *
 */

void SSUSession::ProcessSessionConfirmed(SSUPacket* pkt) {
  if (m_SessionConfirmData.empty())
    {
      // No session confirm data
      LOG(error) << "SSUSession:" << GetFormattedSessionInfo()
                 << "unsolicited SessionConfirmed";
      return;  // TODO(anonimal): throw/warn for potential attacks
    }

  LOG(debug)
    << "SSUSession:" << GetFormattedSessionInfo() << "SessionConfirmed received";
  auto packet = static_cast<SSUSessionConfirmedPacket*>(pkt);
  m_RemoteIdentity = packet->GetRemoteRouterIdentity();
  m_Data.UpdatePacketSize(m_RemoteIdentity.GetIdentHash());

  // Replace unused (spec-unused) signed-on type with Alice's value
  core::OutputByteStream data(
      m_SessionConfirmData.data(), m_SessionConfirmData.size());

  // TODO(anonimal): received as BE (at least with kovri). Ensure BE.
  std::uint32_t const time = packet->GetSignedOnTime();
  std::memcpy(data.Data() + (data.Size() - 4), &time, 4);

  LOG(trace) << "SSUSession:" << GetFormattedSessionInfo()
             << "SessionConfirmed data:"
             << core::GetFormattedHex(data.Data(), data.Size());

  // Verify data with Alice's signature
  if (!m_RemoteIdentity.Verify(
          data.Data(), data.Size(), packet->GetSignature()))
    {
      LOG(error) << "SSUSession:" << GetFormattedSessionInfo()
                 << "SessionConfirmed verification failed";
      return;  // TODO(anonimal): set threshold, throw/warn for potential attacks
    }

  LOG(debug) << "SSUSession:" << GetFormattedSessionInfo()
             << "SessionConfirmed success";

  Established();
}

// TODO(anonimal): separate message creation from session
void SSUSession::SendSessionConfirmed(
    const std::uint8_t* dh_y,
    const std::uint8_t* our_address,
    std::size_t our_address_len,
    std::uint16_t our_port)
{
  // TODO(anonimal): this try block should be handled entirely by caller
  try
    {
      SSUSessionConfirmedPacket message;
      message.SetHeader(
          std::make_unique<SSUHeader>(SSUPayloadType::SessionConfirmed));

      // Create IV
      std::array<std::uint8_t, SSUSize::IV> IV;
      core::RandBytes(IV.data(), IV.size());
      message.GetHeader()->SetIV(IV.data());

      // Set Bob's ident and new signed-on time
      message.SetRemoteRouterIdentity(context.GetIdentity());
      message.SetSignedOnTime(core::GetSecondsSinceEpoch());

      // Create message to sign
      // TODO(anonimal): at this point, why would we allow mix-and-match IPv6 to send to IPv4 - or vice versa...
      bool const is_IPv6 = m_RemoteEndpoint.address().is_v6();
      core::OutputByteStream data(
          get_signed_data_size(our_address_len + (is_IPv6 ? 16 : 4)));

      // Our (Alice's) DH X
      data.WriteData(m_DHKeysPair->public_key.data(), SSUSize::DHPublic);

      // Bob's DH Y
      data.WriteData(dh_y, SSUSize::DHPublic);

      // Our (Alice's) address and port
      data.WriteData(our_address, our_address_len);
      data.Write<std::uint16_t>(our_port);

      // Bob's address
      data.WriteData(
          is_IPv6 ? m_RemoteEndpoint.address().to_v6().to_bytes().data()
                  : m_RemoteEndpoint.address().to_v4().to_bytes().data(),
          is_IPv6 ? 16 : 4);

      // Bob's port
      data.Write<std::uint16_t>(m_RemoteEndpoint.port());

      // Our (Alice's) relay tag
      data.Write<std::uint32_t>(m_RelayTag);

      // Our's (Alice's) signed-on time
      data.Write<std::uint32_t>(message.GetSignedOnTime());

      // Sign message
      std::vector<std::uint8_t> signature(
          context.GetIdentity().GetSignatureLen());
      context.GetPrivateKeys().Sign(data.Data(), data.Size(), signature.data());
      message.SetSignature(signature.data());

      // Encrypt with session + mac keys generated from DH exchange, then send
      std::vector<std::uint8_t> buf(
          SSUPacketBuilder::GetPaddedSize(message.GetSize())
          + SSUSize::BufferMargin);
      WriteAndEncrypt(&message, buf.data(), buf.size(), m_SessionKey, m_MACKey);
      Send(buf.data(), buf.size() - SSUSize::BufferMargin);
    }
  catch (...)
    {
      m_Exception.Dispatch(__func__);
      // TODO(anonimal): ensure exception handling by callers
      throw;
    }
}

/**
 *
 * Payload type 3: RelayRequest
 *
 */

void SSUSession::ProcessRelayRequest(
    SSUPacket* pkt,
    const boost::asio::ip::udp::endpoint& from) {
  auto packet = static_cast<SSURelayRequestPacket*>(pkt);
  auto session = m_Server.FindRelaySession(packet->GetRelayTag());
  if (!session)
    return;
  SendRelayResponse(
      packet->GetNonce(),
      from,
      packet->GetIntroKey(),
      session->GetRemoteEndpoint());
  SendRelayIntro(session.get(), from);
}

void SSUSession::SendRelayRequest(
    const std::uint32_t introducer_tag,
    const std::uint8_t* introducer_key)
{
  auto* const address = context.GetRouterInfo().GetSSUAddress();
  if (!address)
    {
      LOG(error) << "SSUSession:" << GetFormattedSessionInfo() << __func__
                 << ": SSU is not supported";
      return;
    }

  // Create message  // TODO(anonimal): move to packet writer
  // TODO(unassigned): size if we include Alice's IP (see SSU spec, unimplemented)
  core::OutputByteStream message(
      SSUSize::RelayRequestBuffer + SSUSize::BufferMargin);  // TODO(anonimal): review buffer margin

  // TODO(unassigned): Endianness is not spec-defined, assuming BE

  // Skip header (written later)
  message.SkipBytes(SSUSize::HeaderMin);

  // Intro tag
  message.Write<std::uint32_t>(introducer_tag);

  // Address, port, and challenge (see SSU spec)
  message.SkipBytes(4);

  // Key
  message.Write<std::uint32_t>(
      core::InputByteStream::Read<std::uint32_t>(address->key));

  // Nonce
  message.Write<std::uint32_t>(core::Rand<std::uint32_t>());

  // Write header and send
  if (m_State == SessionState::Established)
    {
      // Use Alice/Bob session key if session is established
      FillHeaderAndEncrypt(
          SSUPayloadType::RelayRequest,
          message.Data(),
          SSUSize::RelayRequestBuffer,
          m_SessionKey,
          m_MACKey);
    }
  else
    {
      FillHeaderAndEncrypt(
          SSUPayloadType::RelayRequest,
          message.Data(),
          SSUSize::RelayRequestBuffer,
          introducer_key,
          introducer_key);
    }

  m_Server.Send(
      message.Data(), SSUSize::RelayRequestBuffer, GetRemoteEndpoint());
}

/**
 *
 * Payload type 4: RelayResponse
 *
 */

void SSUSession::ProcessRelayResponse(SSUPacket* pkt) {
  LOG(debug)
    << "SSUSession:" << GetFormattedSessionInfo() << "RelayResponse received";
  auto packet = static_cast<SSURelayResponsePacket*>(pkt);
  // TODO(EinMByte): Check remote (charlie) address
  context.UpdateAddress(
      packet->GetIPAddressAlice(),
      packet->GetIPAddressAliceSize(),
      packet->GetPortAlice());
}

void SSUSession::SendRelayResponse(
    const std::uint32_t nonce,
    const boost::asio::ip::udp::endpoint& from,
    const std::uint8_t* intro_key,
    const boost::asio::ip::udp::endpoint& to)
{
  // Charlie's address must always be IPv4
  if (!to.address().is_v4())
    {
      LOG(error) << "SSUSession:" << GetFormattedSessionInfo() << __func__
                 << ": Charlie's must use IPv4";
      // TODO(anonimal): don't throw?...
      return;
    }

  // Create message  // TODO(anonimal): move to packet writer
  core::OutputByteStream message(
      SSUSize::RelayResponseBuffer + SSUSize::BufferMargin);  // TODO(anonimal): review buffer margin

  // Skip header (written later)
  message.SkipBytes(SSUSize::HeaderMin);

  // Charlie's IPv4 size
  message.Write<std::uint8_t>(4);

  // Charlie's address
  message.Write<std::uint32_t>(to.address().to_v4().to_ulong());

  // Charlie's port
  message.Write<std::uint16_t>(to.port());

  // Alice's IP address
  bool const is_IPv4 = from.address().is_v4();
  if (is_IPv4)
    {
      message.Write<std::uint8_t>(4);
      message.WriteData(from.address().to_v4().to_bytes().data(), 4);
    }
  else  // TODO(anonimal): *assumes* IPv6?
    {
      message.Write<std::uint8_t>(16);
      message.WriteData(from.address().to_v6().to_bytes().data(), 16);
    }

  // Alice's port
  message.Write<std::uint16_t>(from.port());

  // Nonce
  message.Write<std::uint32_t>(nonce);

  // Write header and send
  std::uint8_t const message_size = is_IPv4 ? SSUSize::RelayResponseBuffer - 16
                                             : SSUSize::RelayResponseBuffer;
  if (m_State == SessionState::Established)
    {
      // Uses session key if established
      FillHeaderAndEncrypt(
          SSUPayloadType::RelayResponse, message.Data(), message_size);

      Send(message.Data(), message_size);
    }
  else
    {
      // Encrypt with Alice's intro key
      FillHeaderAndEncrypt(
          SSUPayloadType::RelayResponse,
          message.Data(),
          message_size,
          intro_key,
          intro_key);

      m_Server.Send(message.Data(), message_size, from);
    }

  LOG(debug) << "SSUSession: RelayResponse sent";
}

/**
 *
 * Payload type 5: RelayIntro
 *
 */

void SSUSession::ProcessRelayIntro(SSUPacket* packet)
{
  LOG(debug) << "SSUSession:" << GetFormattedSessionInfo()
             << "RelayIntro received, processing";

  // Get message
  auto* message = static_cast<SSURelayIntroPacket*>(packet);

  // Get Alice's address
  boost::asio::ip::address_v4 address(
      core::InputByteStream::Read<std::uint32_t>(message->GetIPAddress()));

  // Challenge is not implemented
  assert(!message->GetChallenge());

  // Send an empty HolePunch to Alice for our NAT/firewall traversal
  // Note: boost.asio allows sending empty buffer + 0 length data (an empty packet)
  m_Server.Send(
      {},
      0,
      boost::asio::ip::udp::endpoint(
          address, message->GetPort() /* TODO(anonimal): ensure port is BE */));
}

void SSUSession::SendRelayIntro(
    const SSUSession* session,
    const boost::asio::ip::udp::endpoint& from)
{
  if (!session)
    {
      LOG(error) << "SSUSession:" << GetFormattedSessionInfo() << __func__
                 << ": null session";
      return;  // TODO(anonimal): assert/throw?!...
    }

  // Alice's address always v4
  if (!from.address().is_v4())
    {
      LOG(error) << "SSUSession:" << GetFormattedSessionInfo() << __func__
                 << ": Alice's address must be IPv4";
      return;  // TODO(anonimal): assert/throw?!...
    }

  // Create message
  core::OutputByteStream message(
      SSUSize::RelayIntroBuffer + SSUSize::BufferMargin);

  // Skip header (written later)
  message.SkipBytes(SSUSize::HeaderMin);

  // Alice's IP Size
  message.Write<std::uint8_t>(4);

  // Alice's IP
  message.Write<std::uint32_t>(from.address().to_v4().to_ulong());

  // Alice's port
  message.Write<std::uint16_t>(from.port());

  // Challenge is unimplemented, challenge size is always zero
  message.SkipBytes(1);

  // Encrypt with Bob/Charlie keys
  FillHeaderAndEncrypt(
      SSUPayloadType::RelayIntro,
      message.Data(),
      SSUSize::RelayIntroBuffer,
      session->m_SessionKey,
      session->m_MACKey);

  LOG(debug) << "SSUSession: " << GetFormattedSessionInfo()
             << "sending RelayIntro";

  m_Server.Send(
      message.Data(), SSUSize::RelayIntroBuffer, session->GetRemoteEndpoint());
}

/**
 *
 * Payload type 6: Data
 *
 */

void SSUSession::ProcessData(SSUPacket* pkt) {
  auto packet = static_cast<SSUDataPacket*>(pkt);
  // TODO(EinMByte): Don't use raw data
  m_Data.ProcessMessage(packet->m_RawData, packet->m_RawDataLength);
  m_IsDataReceived = true;
}

void SSUSession::FlushData() {
  if (m_IsDataReceived) {
    m_Data.FlushReceivedMessage();
    m_IsDataReceived = false;
  }
}

/**
 *
 * Payload type 7: PeerTest
 *
 */

void SSUSession::ProcessPeerTest(
    SSUPacket* pkt,
    const boost::asio::ip::udp::endpoint& sender_endpoint) {
  auto packet = static_cast<SSUPeerTestPacket*>(pkt);
  if (packet->GetPort() && packet->GetIPAddress().is_unspecified()) {
    LOG(warning)
      << "SSUSession:" << GetFormattedSessionInfo() << "address unspecified";
    return;
  }
  auto peer_test = SSUPayloadType::PeerTest;
  switch (m_Server.GetPeerTestParticipant(packet->GetNonce())) {
    // existing test
    case PeerTestParticipant::Alice1: {
      if (m_Server.GetPeerTestSession(packet->GetNonce()) == shared_from_this()) {
        LOG(debug)
          << "SSUSession:" << GetFormattedSessionInfo()
          << "PeerTest from Bob. We are Alice";
        if (context.GetState() == RouterState::Testing)  // still not OK
          context.SetState(RouterState::Firewalled);
      } else {
        LOG(debug)
          << "SSUSession:" << GetFormattedSessionInfo()
          << "first PeerTest from Charlie. We are Alice";
        context.SetState(RouterState::OK);
        m_Server.UpdatePeerTest(
            packet->GetNonce(),
            PeerTestParticipant::Alice2);
        // We're Alice, send to Charlie
        SendPeerTest(
            packet->GetNonce(),
            sender_endpoint.address(),
            sender_endpoint.port(),
            packet->GetIntroKey(),
            true,
            false);
      }
      break;
    }
    case PeerTestParticipant::Alice2: {
      if (m_Server.GetPeerTestSession(packet->GetNonce()) == shared_from_this()) {
        LOG(debug)
          << "SSUSession:" << GetFormattedSessionInfo()
          << "PeerTest from Bob. We are Alice";
      } else {
        // PeerTest successive
        LOG(debug)
          << "SSUSession:" << GetFormattedSessionInfo()
          << "second PeerTest from Charlie. We are Alice";
        context.SetState(RouterState::OK);
      }
      break;
    }
    case PeerTestParticipant::Bob: {
      LOG(debug)
        << "SSUSession:" << GetFormattedSessionInfo()
        << "PeerTest from Charlie. We are Bob";
      // session with Alice from PeerTest
      auto session = m_Server.GetPeerTestSession(packet->GetNonce());
      if (session && session->m_State == SessionState::Established)
        session->Send(  // back to Alice
            peer_test,
            packet->m_RawData,
            packet->m_RawDataLength);
      m_Server.RemovePeerTest(packet->GetNonce());  // nonce has been used
      break;
    }
    case PeerTestParticipant::Charlie: {
      LOG(debug)
        << "SSUSession:" << GetFormattedSessionInfo()
        << "PeerTest from Alice. We are Charlie";
      // To Alice with her actual address and port
      SendPeerTest(
          packet->GetNonce(),
          sender_endpoint.address(),
          sender_endpoint.port(),
          packet->GetIntroKey());
      m_Server.RemovePeerTest(packet->GetNonce());  // nonce has been used
      break;
    }
    // test not found
    case PeerTestParticipant::Unknown: {
      if (m_State == SessionState::Established) {
        // new test
        if (packet->GetPort()) {
          LOG(debug)
            << "SSUSession:" << GetFormattedSessionInfo()
            << "PeerTest from Bob. We are Charlie";
          m_Server.NewPeerTest(packet->GetNonce(), PeerTestParticipant::Charlie);
          Send(  // back to Bob
              peer_test,
              packet->m_RawData,
              packet->m_RawDataLength);
          // To Alice with her address received from Bob
          SendPeerTest(
              packet->GetNonce(),
              packet->GetIPAddress(),
              packet->GetPort(),
              packet->GetIntroKey());
        } else {
          LOG(debug)
            << "SSUSession:" << GetFormattedSessionInfo()
            << "PeerTest from Alice. We are Bob";
          // Charlie
          auto session = m_Server.GetRandomEstablishedSession(shared_from_this());
          if (session) {
            m_Server.NewPeerTest(
                packet->GetNonce(),
                PeerTestParticipant::Bob,
                shared_from_this());
            // To Charlie with Alice's actual address
            session->SendPeerTest(
                packet->GetNonce(),
                sender_endpoint.address(),
                sender_endpoint.port(),
                packet->GetIntroKey(),
                false);
          }
        }
      } else {
        LOG(error)
          << "SSUSession:" << GetFormattedSessionInfo() << "unexpected PeerTest";
      }
    }
  }
}

// TODO(anonimal): interface refactor, check address type in caller implementation.
void SSUSession::SendPeerTest(
    const std::uint32_t nonce,
    const boost::asio::ip::address& address,
    const std::uint16_t port,
    const std::uint8_t* intro_key,
    const bool to_address,  // is true for Alice<->Charlie communications only
    const bool send_address)  // is false if message comes from Alice
{
  // Create message
  core::OutputByteStream message(
      SSUSize::PeerTestBuffer + SSUSize::BufferMargin);

  // Skip header (written later)
  message.SkipBytes(SSUSize::HeaderMin);

  // Nonce
  message.Write<std::uint32_t>(nonce);

  // Given Address
  if (send_address && !address.is_unspecified())
    {
      bool const is_IPv6(address.is_v6());

      // Size of address
      message.Write<std::uint8_t>(is_IPv6 ? 16 : 4);

      // Address
      message.WriteData(
          is_IPv6 ? address.to_v6().to_bytes().data()
                  : address.to_v4().to_bytes().data(),
          is_IPv6 ? 16 : 4);
    }
  else
    {
      message.SkipBytes(1);
    }

  // Given Port
  message.Write<std::uint16_t>(port);

  // Write introducer key
  if (to_address)
    {
      // Our (Alice's) intro key
      auto* const addr = context.GetRouterInfo().GetSSUAddress(
          context.GetRouterInfo().HasV6());
      assert(addr);
      message.WriteData(addr->key, sizeof(addr->key));
    }
  else
    {
      // Charlie's intro key
      message.WriteData(intro_key, 32);
    }

  // Write header and send
  if (to_address)
    {
      // Encrypts message with given intro key
      FillHeaderAndEncrypt(
          SSUPayloadType::PeerTest,
          message.Data(),
          SSUSize::PeerTestBuffer,
          intro_key,
          intro_key);

      boost::asio::ip::udp::endpoint ep(address, port);
      m_Server.Send(message.Data(), SSUSize::PeerTestBuffer, ep);
    }
  else
    {
      // Encrypts message with existing session key, uses existing session
      FillHeaderAndEncrypt(
          SSUPayloadType::PeerTest, message.Data(), SSUSize::PeerTestBuffer);

      Send(message.Data(), SSUSize::PeerTestBuffer);
    }
}

void SSUSession::SendPeerTest() {
  // we are Alice
  LOG(debug) << "SSUSession: <--" << GetFormattedSessionInfo() << "sending PeerTest";
  auto* const address =
      context.GetRouterInfo().GetSSUAddress(context.GetRouterInfo().HasV6());
  assert(address);
  auto nonce = kovri::core::Rand<std::uint32_t>();
  if (!nonce)
    nonce = 1;
  m_PeerTest = false;
  m_Server.NewPeerTest(nonce, PeerTestParticipant::Alice1, shared_from_this());
  SendPeerTest(
      nonce,
      {},  // address and port always zero for Alice
      0,  // ^
      address->key,
      false,
      false);
}

/**
 *
 * Payload type 8: SessionDestroyed
 *
 */

void SSUSession::SendSessionDestroyed()
{
  if (m_IsSessionKey)
    {
      // This message should not contain any data
      core::OutputByteStream message(
          SSUSize::SessionDestroyedBuffer + SSUSize::BufferMargin);

      // Write header and send (existing session)
      FillHeaderAndEncrypt(
          SSUPayloadType::SessionDestroyed,
          message.Data(),
          SSUSize::SessionDestroyedBuffer);
      try
        {
          LOG(debug) << "SSUSession:" << GetFormattedSessionInfo()
                     << "sending SessionDestroyed";

          Send(message.Data(), SSUSize::SessionDestroyedBuffer);
        }
      catch (const std::exception& ex)
        {
          LOG(error) << "SSUSession:" << GetFormattedSessionInfo() << __func__
                     << ": '" << ex.what() << "'";
        }
    }
}

// TODO(anonimal):
//   "An ACK packet with no acks", the function of a keep-alive message is currently
//   undocumented in I2P specifications. The only mention of keepalives in SSU is a
//   one-line comment under Data message types:
//     "If the number of fragments is zero, this is an ack-only or keepalive message."
//   Note: the Java implementation uses keepalives as a way to ping introducers.
void SSUSession::SendKeepAlive()
{
  if (m_State == SessionState::Established)
    {
      // TODO(anonimal):
      //   37 byte min header
      //   + 5 byte short I2NP header
      //   + 1 byte flag (zero)
      //   + 1 byte number of fragments (zero) = 44...
      core::OutputByteStream message(48 + SSUSize::BufferMargin);

      // Flag (zero) + num fragments (zero)
      message.SkipBytes(2);

      // Use existing session + send
      FillHeaderAndEncrypt(
          SSUPayloadType::Data,
          message.Data(),
          message.Size() - SSUSize::BufferMargin);

      LOG(debug) << "SSUSession:" << GetFormattedSessionInfo()
                 << "sending keep-alive";

      Send(message.Data(), message.Size() - SSUSize::BufferMargin);

      // Ensure session lifetime
      ScheduleTermination();
    }
}

// TODO(anonimal): refactor
void SSUSession::FillHeaderAndEncrypt(
    std::uint8_t payload_type,
    std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* aes_key,
    const std::uint8_t* mac_key,
    std::uint8_t flag) {
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    if (len < SSUSize::HeaderMin) {
      LOG(error)
        << "SSUSession:" << GetFormattedSessionInfo()
        << "unexpected SSU packet length " << len;
      return;
    }
    SSUSessionPacket pkt(buf, len);
    core::RandBytes(pkt.IV(), SSUSize::IV);
    pkt.PutFlag(flag | (payload_type << 4));  // MSB is 0
    pkt.PutTime(kovri::core::GetSecondsSinceEpoch());
    auto encrypted = pkt.Encrypted();
    auto encrypted_len = len - (encrypted - buf);
    kovri::core::CBCEncryption encryption(aes_key, pkt.IV());
    encryption.Encrypt(
        encrypted,
        encrypted_len,
        encrypted);
    // assume actual buffer size is 18 (16 + 2) bytes more
    // TODO(unassigned): ^ this is stupid and dangerous to assume that caller is responsible
    memcpy(buf + len, pkt.IV(), SSUSize::IV);
    core::OutputByteStream::Write<std::uint16_t>(
        buf + len + SSUSize::IV, encrypted_len);
    kovri::core::HMACMD5Digest(
        encrypted,
        encrypted_len + SSUSize::BufferMargin,
        mac_key,
        pkt.MAC());
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

// TODO(anonimal): refactor
void SSUSession::WriteAndEncrypt(
    SSUPacket* packet,
    std::uint8_t* buffer,
    std::size_t buffer_size,
    const std::uint8_t* aes_key,
    const std::uint8_t* mac_key) {
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    packet->GetHeader()->SetTime(kovri::core::GetSecondsSinceEpoch());
    SSUPacketBuilder builder(buffer, buffer_size);
    // Write header (excluding MAC)
    builder.WriteHeader(packet->GetHeader());
    // Write packet body
    builder.WritePacket(packet);
    // Encrypt everything after the MAC and IV
    std::uint8_t* encrypted =
      buffer
      + SSUSize::IV
      + SSUSize::MAC;
    auto encrypted_len = builder.Tellp() - encrypted;
    // Add padding
    std::size_t const padding_size =
        SSUPacketBuilder::GetPaddingSize(encrypted_len);
    if (padding_size)
      {
        std::vector<std::uint8_t> padding(padding_size);
        core::RandBytes(padding.data(), padding.size());
        builder.WriteData(padding.data(), padding.size());
        encrypted_len += padding.size();
      }
    kovri::core::CBCEncryption encryption(aes_key, packet->GetHeader()->GetIV());
    encryption.Encrypt(encrypted, encrypted_len, encrypted);
    // Compute HMAC of encryptedPayload + IV + (payloadLength ^ protocolVersion)
    // Currently, protocolVersion == 0
    kovri::core::OutputByteStream stream(
        encrypted + encrypted_len, buffer_size - (encrypted - buffer));
    stream.WriteData(
        packet->GetHeader()->GetIV(),
        SSUSize::IV);
    stream.Write<std::uint16_t>(encrypted_len);
    kovri::core::HMACMD5Digest(
        encrypted,
        encrypted_len + SSUSize::BufferMargin,
        mac_key,
        buffer);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

// TODO(anonimal): refactor
void SSUSession::FillHeaderAndEncrypt(
    std::uint8_t payload_type,
    std::uint8_t* buf,
    std::size_t len) {
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    if (len < SSUSize::HeaderMin) {
      LOG(error)
        << "SSUSession:" << GetFormattedSessionInfo()
        << "unexpected SSU packet length " << len;
      return;
    }
    SSUSessionPacket pkt(buf, len);
    kovri::core::RandBytes(pkt.IV(), SSUSize::IV);  // random iv
    m_SessionKeyEncryption.SetIV(pkt.IV());
    pkt.PutFlag(payload_type << 4);  // MSB is 0
    pkt.PutTime(kovri::core::GetSecondsSinceEpoch());
    auto encrypted = pkt.Encrypted();
    auto encrypted_len = len - (encrypted - buf);
    m_SessionKeyEncryption.Encrypt(
        encrypted,
        encrypted_len,
        encrypted);
    // assume actual buffer size is 18 (16 + 2) bytes more
    // TODO(unassigned): ^ this is stupid and dangerous to assume that caller is responsible
    memcpy(buf + len, pkt.IV(), SSUSize::IV);
    core::OutputByteStream::Write<std::uint16_t>(
        buf + len + SSUSize::IV, encrypted_len);
    kovri::core::HMACMD5Digest(
        encrypted,
        encrypted_len + SSUSize::BufferMargin,
        m_MACKey,
        pkt.MAC());
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

void SSUSession::Decrypt(
    std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* aes_key,
    const bool is_session)
{
  if (len < SSUSize::HeaderMin)
    {
      throw std::length_error(
          "SSUSession:" + GetFormattedSessionInfo() + __func__
          + ": unexpected SSU message length " + std::to_string(len));
    }

  // Parse message buffer and decrypt
  SSUSessionPacket message(buf, len);

  std::uint8_t* encrypted = message.Encrypted();
  // TOOD(anonimal): we should only need 2 bytes
  std::size_t encrypted_len = len - (encrypted - buf);
  assert(encrypted_len);

  // Set new key for this message
  if (!is_session)
    {
      core::CBCDecryption decryption;
      decryption.SetKey(aes_key);
      decryption.SetIV(message.IV());
      decryption.Decrypt(encrypted, encrypted_len, encrypted);
      return;
    }

  // Use existing session's AES and MAC key
  m_SessionKeyDecryption.SetIV(message.IV());
  m_SessionKeyDecryption.Decrypt(encrypted, encrypted_len, encrypted);
}

bool SSUSession::Validate(
    std::uint8_t* buf,
    std::size_t len,
    const std::uint8_t* mac_key) {
  if (len < SSUSize::HeaderMin) {
    LOG(error)
      << "SSUSession:" << GetFormattedSessionInfo()
      << __func__ << ": unexpected SSU packet length " << len;
    return false;
  }
  SSUSessionPacket pkt(buf, len);
  auto encrypted = pkt.Encrypted();
  auto encrypted_len = len - (encrypted - buf);
  // assume actual buffer size is 18 (16 + 2) bytes more (SSUSize::RawPacketBuffer)
  memcpy(buf + len, pkt.IV(), SSUSize::IV);
  core::OutputByteStream::Write<std::uint16_t>(
      buf + len + SSUSize::IV, encrypted_len);
  std::array<std::uint8_t, 16> digest;
  kovri::core::HMACMD5Digest(
      encrypted,
      encrypted_len + SSUSize::BufferMargin,
      mac_key,
      digest.data());
  return !memcmp(pkt.MAC(), digest.data(), digest.size());
}

void SSUSession::Connect() {
  if (m_State == SessionState::Unknown) {
    // set connect timer
    ScheduleConnectTimer();
    m_DHKeysPair = transports.GetNextDHKeysPair();
    SendSessionRequest();
  }
}

void SSUSession::WaitForConnect() {
  if (IsOutbound())
    LOG(warning)
      << "SSUSession:" << GetFormattedSessionInfo()
      << __func__ << " for outgoing session";  // TODO(anonimal): message
  else
    ScheduleConnectTimer();
}

void SSUSession::ScheduleConnectTimer() {
  m_Timer.cancel();  // TODO(anonimal): cancel is called within expires_from_now
  m_Timer.expires_from_now(
      boost::posix_time::seconds{
          static_cast<long>(SSUDuration::ConnectTimeout)});
  m_Timer.async_wait(
      std::bind(
          &SSUSession::HandleConnectTimer,
          shared_from_this(),
          std::placeholders::_1));
}

void SSUSession::HandleConnectTimer(
    const boost::system::error_code& ecode) {
  if (!ecode) {
    // timeout expired
    LOG(error)
      << "SSUSession:" << GetFormattedSessionInfo()
      << "session was not established after "
      << static_cast<std::size_t>(SSUDuration::ConnectTimeout) << " seconds";
    Failed();
  }
}

void SSUSession::Introduce(
    std::uint32_t introducer_tag,
    const std::uint8_t* introducer_key) {
  if (m_State == SessionState::Unknown) {
    // set connect timer
    m_Timer.expires_from_now(
        boost::posix_time::seconds{
            static_cast<long>(SSUDuration::ConnectTimeout)});
    m_Timer.async_wait(
        std::bind(
          &SSUSession::HandleConnectTimer,
          shared_from_this(),
          std::placeholders::_1));
  }
  SendRelayRequest(introducer_tag, introducer_key);
}

void SSUSession::WaitForIntroduction() {
  m_State = SessionState::Introduced;
  // set connect timer
  m_Timer.expires_from_now(
      boost::posix_time::seconds{
          static_cast<long>(SSUDuration::ConnectTimeout)});
  m_Timer.async_wait(
      std::bind(
        &SSUSession::HandleConnectTimer,
        shared_from_this(),
        std::placeholders::_1));
}

void SSUSession::Close() {
  m_State = SessionState::Closed;
  SendSessionDestroyed();
  transports.PeerDisconnected(shared_from_this());
  m_Data.Stop();
  m_Timer.cancel();
}

void SSUSession::Done() {
  GetService().post(
      std::bind(
        &SSUSession::Failed,
        shared_from_this()));
}

void SSUSession::Established() {
  // Remove SessionConfirmed data
  m_SessionConfirmData.clear();
  m_SessionConfirmData.shrink_to_fit();

  m_State = SessionState::Established;
  if (m_DHKeysPair) {
    m_DHKeysPair.reset(nullptr);
  }
  m_Data.Start();
  // send delivery status
  m_Data.Send(CreateDeliveryStatusMsg(0));
  // send database store
  m_Data.Send(CreateDatabaseStoreMsg());
  transports.PeerConnected(shared_from_this());
  if (m_PeerTest && (m_RemoteRouter && m_RemoteRouter->HasCap(RouterInfo::Cap::SSUTesting)))
    SendPeerTest();
  ScheduleTermination();
}

void SSUSession::Failed() {
  if (m_State != SessionState::Failed) {
    m_State = SessionState::Failed;
    m_Server.DeleteSession(shared_from_this());
  }
}

void SSUSession::ScheduleTermination() {
  m_Timer.cancel();
  m_Timer.expires_from_now(
      boost::posix_time::seconds{
          static_cast<long>(SSUDuration::TerminationTimeout)});
  m_Timer.async_wait(
      std::bind(
          &SSUSession::HandleTerminationTimer,
          shared_from_this(),
          std::placeholders::_1));
}

void SSUSession::HandleTerminationTimer(
    const boost::system::error_code& ecode) {
  if (ecode != boost::asio::error::operation_aborted) {
    LOG(error)
      << "SSUSession:" << GetFormattedSessionInfo() << "no activity for "
      << static_cast<std::size_t>(SSUDuration::TerminationTimeout) << " seconds";
    Failed();
  }
}

const std::uint8_t* SSUSession::GetIntroKey() const
{
  // Use remote key if we are client
  if (m_RemoteRouter)
    {
      LOG(debug) << "SSUSession: " << __func__ << ": using remote's key";
      auto* const address =
          m_RemoteRouter->GetSSUAddress(m_RemoteRouter->HasV6());
      assert(address);  // TODO(anonimal): SSU should be guaranteed
      return address->key;
    }

  // Use our key if we are server
  LOG(debug) << "SSUSession: " << __func__ << ": using our key";
  auto* const address =
      context.GetRouterInfo().GetSSUAddress(context.GetRouterInfo().HasV6());
  assert(address);  // TODO(anonimal): SSU should be guaranteed
  return address->key;
}

void SSUSession::SendI2NPMessages(
    const std::vector<std::shared_ptr<I2NPMessage>>& msgs) {
  GetService().post(
      std::bind(
          &SSUSession::PostI2NPMessages,
          shared_from_this(),
          msgs));
}

void SSUSession::PostI2NPMessages(
    std::vector<std::shared_ptr<I2NPMessage>> msgs) {
  if (m_State == SessionState::Established) {
    for (auto it : msgs)
      if (it)
        m_Data.Send(it);
  }
}

void SSUSession::Send(
    std::uint8_t type,
    const std::uint8_t* payload,
    std::size_t len) {
  std::array<std::uint8_t, SSUSize::RawPacketBuffer> buf{{}};
  auto msg_size = len + SSUSize::HeaderMin;
  auto padding_size = msg_size & 0x0F;  // %16
  if (padding_size > 0)
    msg_size += (16 - padding_size);
  if (msg_size > SSUSize::MTUv4) {
    LOG(warning)
      << "SSUSession:" << GetFormattedSessionInfo()
      << "<-- payload size " << msg_size << " exceeds MTU";
    return;
  }
  memcpy(buf.data() + SSUSize::HeaderMin, payload, len);
  // encrypt message with session key
  FillHeaderAndEncrypt(type, buf.data(), msg_size);
  Send(buf.data(), msg_size);
}

void SSUSession::Send(
    const std::uint8_t* buf,
    std::size_t size) {
  m_NumSentBytes += size;
  LOG(debug)
    << "SSUSession:" << GetFormattedSessionInfo()
    << "<-- " << size << " bytes transferred, "
    << GetNumSentBytes() << " total bytes sent";
  kovri::core::transports.UpdateSentBytes(size);
  m_Server.Send(buf, size, GetRemoteEndpoint());
}

}  // namespace core
}  // namespace kovri

