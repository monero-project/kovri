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

#include "client/api/datagram.h"

#include <string.h>

#include <vector>

#include "client/destination.h"

#include "core/crypto/hash.h"
#include "core/crypto/rand.h"
#include "core/crypto/util/compression.h"
#include "core/router_context.h"
#include "core/tunnel/tunnel_base.h"
#include "core/util/log.h"

namespace kovri {
namespace client {

DatagramDestination::DatagramDestination(
    kovri::client::ClientDestination& owner)
    : m_Owner(owner),
      m_Receiver(nullptr) {}

namespace {  // Helper facilities to transfer messages.

/// Deleter for a shared pointer
/// that can be cancelled or nullified.
template <typename T>
class CancellableDeleter {
 public:
  /// Deletes the payload if the deleter still active.
  void operator()(T* ptr) {
    if (!cancel_)
      delete ptr;
  }

  /// Deactivates the deleter.
  void cancel() {
    cancel_ = true;
  }

 private:
  bool cancel_ = false;  ///< The controlling flag.
};

/// Shared pointer with ``release`` semantics as unique_ptr.
template <typename T>
using ReleasableSharedPtr = std::shared_ptr<T>;

/// Helper function to make releasable shared_ptr with appropriate deleter.
//
/// @param payload  The payload for the handle.
template <typename T>
auto make_releasable_shared_ptr(T* payload) {
  return ReleasableSharedPtr<T>(payload, CancellableDeleter<T>());
}

/// @returns The released payload from the shared ptr.
template <typename T>
T* release(const ReleasableSharedPtr<T>& smart_ptr) {
  std::get_deleter<CancellableDeleter<T>>(smart_ptr)->cancel();
  return smart_ptr.get();
}

}  // namespace

void DatagramDestination::SendDatagramTo(
    const uint8_t* payload,
    size_t len,
    const kovri::data::IdentHash& ident,
    uint16_t from_port,
    uint16_t to_port) {
  uint8_t buf[MAX_DATAGRAM_SIZE];
  auto identity_len = m_Owner.GetIdentity().ToBuffer(buf, MAX_DATAGRAM_SIZE);
  uint8_t* signature = buf + identity_len;
  auto signature_len = m_Owner.GetIdentity().GetSignatureLen();
  uint8_t* buf1 = signature + signature_len;
  size_t header_len = identity_len + signature_len;
  memcpy(buf1, payload, len);
  if (m_Owner.GetIdentity().GetSigningKeyType()
      == kovri::data::SIGNING_KEY_TYPE_DSA_SHA1) {
    uint8_t hash[32];
    kovri::crypto::SHA256().CalculateDigest(hash, buf1, len);
    m_Owner.Sign(hash, 32, signature);
  } else {
    m_Owner.Sign(buf1, len, signature);
  }
  std::unique_ptr<I2NPMessage> msg
      = CreateDataMessage(buf, len + header_len, from_port, to_port);
  std::shared_ptr<const kovri::data::LeaseSet> remote
      = m_Owner.FindLeaseSet(ident);

  ReleasableSharedPtr<I2NPMessage> temp_msg
      = make_releasable_shared_ptr(msg.release());
  if (remote) {
    m_Owner.GetService().post([this, temp_msg, remote] {
      SendMsg(std::unique_ptr<I2NPMessage>(release(temp_msg)), remote);
    });
  } else {
    m_Owner.RequestDestination(
        ident,
        [this, temp_msg](const std::shared_ptr<kovri::data::LeaseSet>& remote) {
          HandleLeaseSetRequestComplete(
              remote, std::unique_ptr<I2NPMessage>(release(temp_msg)));
        });
  }
}

void DatagramDestination::HandleLeaseSetRequestComplete(
    std::shared_ptr<kovri::data::LeaseSet> remote,
    std::unique_ptr<I2NPMessage> msg) {
  if (remote)
    SendMsg(std::move(msg), remote);
}

void DatagramDestination::SendMsg(
    std::unique_ptr<I2NPMessage> msg,
    std::shared_ptr<const kovri::data::LeaseSet> remote) {
  auto outbound_tunnel = m_Owner.GetTunnelPool()->GetNextOutboundTunnel();
  auto leases = remote->GetNonExpiredLeases();
  if (!leases.empty() && outbound_tunnel) {
    std::vector<kovri::tunnel::TunnelMessageBlock> msgs;
    uint32_t i = kovri::crypto::RandInRange<uint32_t>(0, leases.size() - 1);
    auto garlic = m_Owner.WrapMessage(
        remote,
        ToSharedI2NPMessage(std::move(msg)),
        true);
    msgs.push_back(
        kovri::tunnel::TunnelMessageBlock{kovri::tunnel::e_DeliveryTypeTunnel,
                                        leases[i].tunnel_gateway,
                                        leases[i].tunnel_ID,
                                        garlic});
    outbound_tunnel->SendTunnelDataMsg(msgs);
  } else {
    if (outbound_tunnel)
      LogPrint(eLogWarn,
          "DatagramDestination: failed to send datagram: all leases expired");
    else
      LogPrint(eLogWarn,
          "DatagramDestination: failed to send datagram: no outbound tunnels");
  }
}

void DatagramDestination::HandleDatagram(
    uint16_t from_port,
    uint16_t to_port,
    const uint8_t* buf,
    size_t len) {
  kovri::data::IdentityEx identity;
  size_t identity_len = identity.FromBuffer(buf, len);
  const uint8_t* signature = buf + identity_len;
  size_t header_len = identity_len + identity.GetSignatureLen();
  bool verified = false;
  if (identity.GetSigningKeyType() == kovri::data::SIGNING_KEY_TYPE_DSA_SHA1) {
    uint8_t hash[32];
    kovri::crypto::SHA256().CalculateDigest(hash, buf + header_len, len - header_len);
    verified = identity.Verify(hash, 32, signature);
  } else {
    verified =
      identity.Verify(buf + header_len, len - header_len, signature);
  }
  if (verified) {
    auto it = m_ReceiversByPorts.find(to_port);
    if (it != m_ReceiversByPorts.end())
        it->second(
            identity, from_port, to_port, buf + header_len, len - header_len);
    else if (m_Receiver != nullptr)
        m_Receiver(
            identity, from_port, to_port, buf + header_len, len - header_len);
    else
        LogPrint(eLogWarn,
            "DatagramDestination: receiver for datagram is not set");
  } else {
    LogPrint(eLogWarn,
        "DatagramDestination: datagram signature verification failed");
  }
}

void DatagramDestination::HandleDataMessagePayload(
    uint16_t from_port,
    uint16_t to_port,
    const uint8_t* buf,
    size_t len) {
  // Gunzip it
  kovri::crypto::util::Gunzip decompressor;
  decompressor.Put(buf, len);
  uint8_t uncompressed[MAX_DATAGRAM_SIZE];
  auto uncompressed_len = decompressor.MaxRetrievable();
  if (uncompressed_len <= MAX_DATAGRAM_SIZE) {
    decompressor.Get(uncompressed, uncompressed_len);
    HandleDatagram(from_port, to_port, uncompressed, uncompressed_len);
  } else {
    LogPrint(eLogWarn,
        "DatagramDestination: the received datagram size ",
        uncompressed_len, " exceeds max size");
  }
}

std::unique_ptr<I2NPMessage> DatagramDestination::CreateDataMessage(
    const uint8_t* payload,
    size_t len,
    uint16_t from_port,
    uint16_t to_port) {
  std::unique_ptr<I2NPMessage> msg = NewI2NPMessage();
  kovri::crypto::util::Gzip compressor;  // default level
  compressor.Put(payload, len);
  std::size_t size = compressor.MaxRetrievable();
  uint8_t* buf = msg->GetPayload();
  htobe32buf(buf, size);  // length
  buf += 4;
  compressor.Get(buf, size);
  htobe16buf(buf + 4, from_port);  // source port
  htobe16buf(buf + 6, to_port);  // destination port
  buf[9] = kovri::client::PROTOCOL_TYPE_DATAGRAM;  // datagram protocol
  msg->len += size + 4;
  msg->FillI2NPMessageHeader(e_I2NPData);
  return msg;
}

}  // namespace client
}  // namespace kovri
