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

#include "client/api/datagram.h"

#include <string.h>

#include <vector>

#include "client/destination.h"

#include "core/crypto/hash.h"
#include "core/crypto/rand.h"
#include "core/crypto/util/compression.h"

#include "core/router/context.h"
#include "core/router/tunnel/base.h"

#include "core/util/log.h"

namespace kovri {
namespace client {

DatagramDestination::DatagramDestination(
    kovri::client::ClientDestination& owner)
    : m_Owner(owner),
      m_Receiver(nullptr),
      m_Exception(__func__) {}

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
    const std::uint8_t* payload,
    std::size_t len,
    const kovri::core::IdentHash& ident,
    std::uint16_t from_port,
    std::uint16_t to_port) {
  // TODO(anonimal): this try block should be larger or handled entirely by caller
  try {
    std::uint8_t buf[MAX_DATAGRAM_SIZE];
    auto identity_len = m_Owner.GetIdentity().ToBuffer(buf, MAX_DATAGRAM_SIZE);
    std::uint8_t* signature = buf + identity_len;
    auto signature_len = m_Owner.GetIdentity().GetSignatureLen();
    std::uint8_t* buf1 = signature + signature_len;
    std::size_t header_len = identity_len + signature_len;
    memcpy(buf1, payload, len);
    m_Owner.Sign(buf1, len, signature);
    std::unique_ptr<kovri::core::I2NPMessage> msg
        = CreateDataMessage(buf, len + header_len, from_port, to_port);
    std::shared_ptr<const kovri::core::LeaseSet> remote
        = m_Owner.FindLeaseSet(ident);

    ReleasableSharedPtr<kovri::core::I2NPMessage> temp_msg
        = make_releasable_shared_ptr(msg.release());
    if (remote) {
      m_Owner.GetService().post([this, temp_msg, remote] {
        SendMsg(std::unique_ptr<kovri::core::I2NPMessage>(release(temp_msg)), remote);
      });
    } else {
      m_Owner.RequestDestination(
          ident,
          [this, temp_msg](const std::shared_ptr<kovri::core::LeaseSet>& remote) {
            HandleLeaseSetRequestComplete(
                remote, std::unique_ptr<kovri::core::I2NPMessage>(release(temp_msg)));
          });
    }
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

void DatagramDestination::HandleLeaseSetRequestComplete(
    std::shared_ptr<kovri::core::LeaseSet> remote,
    std::unique_ptr<kovri::core::I2NPMessage> msg) {
  if (remote)
    SendMsg(std::move(msg), remote);
}

void DatagramDestination::SendMsg(
    std::unique_ptr<kovri::core::I2NPMessage> msg,
    std::shared_ptr<const kovri::core::LeaseSet> remote) {
  auto outbound_tunnel = m_Owner.GetTunnelPool()->GetNextOutboundTunnel();
  auto leases = remote->GetNonExpiredLeases();
  if (!leases.empty() && outbound_tunnel) {
    std::vector<kovri::core::TunnelMessageBlock> msgs;
    std::uint32_t i = kovri::core::RandInRange32(0, leases.size() - 1);
    auto garlic = m_Owner.WrapMessage(
        remote,
        ToSharedI2NPMessage(std::move(msg)),
        true);
    msgs.push_back(
        kovri::core::TunnelMessageBlock{kovri::core::e_DeliveryTypeTunnel,
                                        leases[i].tunnel_gateway,
                                        leases[i].tunnel_ID,
                                        garlic});
    outbound_tunnel->SendTunnelDataMsg(msgs);
  } else {
    if (outbound_tunnel)
      LOG(warning) << "DatagramDestination: failed to send: all leases expired";
    else
      LOG(warning) << "DatagramDestination: failed to send: no outbound tunnels";
  }
}

void DatagramDestination::HandleDatagram(
    std::uint16_t from_port,
    std::uint16_t to_port,
    const std::uint8_t* buf,
    std::size_t len) {
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    kovri::core::IdentityEx identity;
    std::size_t identity_len = identity.FromBuffer(buf, len);
    const std::uint8_t* signature = buf + identity_len;
    std::size_t header_len = identity_len + identity.GetSignatureLen();
    if (identity.Verify(buf + header_len, len - header_len, signature)) {
      auto it = m_ReceiversByPorts.find(to_port);
      if (it != m_ReceiversByPorts.end())
          it->second(
              identity, from_port, to_port, buf + header_len, len - header_len);
      else if (m_Receiver != nullptr)
          m_Receiver(
              identity, from_port, to_port, buf + header_len, len - header_len);
      else
          LOG(warning) << "DatagramDestination: receiver for datagram is not set";
    } else {
      LOG(warning)
        << "DatagramDestination: datagram signature verification failed";
    }
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

void DatagramDestination::HandleDataMessagePayload(
    std::uint16_t from_port,
    std::uint16_t to_port,
    const std::uint8_t* buf,
    std::size_t len) {
  // Gunzip it
  try {
    kovri::core::Gunzip decompressor;
    decompressor.Put(buf, len);
    std::uint8_t uncompressed[MAX_DATAGRAM_SIZE];
    auto uncompressed_len = decompressor.MaxRetrievable();
    if (uncompressed_len <= MAX_DATAGRAM_SIZE) {
      decompressor.Get(uncompressed, uncompressed_len);
      HandleDatagram(from_port, to_port, uncompressed, uncompressed_len);
    } else {
      LOG(warning)
        << "DatagramDestination: the received datagram size "
        << uncompressed_len << " exceeds max size";
    }
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
  }
}

std::unique_ptr<kovri::core::I2NPMessage> DatagramDestination::CreateDataMessage(
    const std::uint8_t* payload,
    std::size_t len,
    std::uint16_t from_port,
    std::uint16_t to_port) {
  std::unique_ptr<kovri::core::I2NPMessage> msg = kovri::core::NewI2NPMessage();
  kovri::core::Gzip compressor;  // default level
  try {
    compressor.Put(payload, len);
    std::size_t size = compressor.MaxRetrievable();
    std::uint8_t* buf = msg->GetPayload();
    htobe32buf(buf, size);  // length
    buf += 4;
    compressor.Get(buf, size);
    htobe16buf(buf + 4, from_port);  // source port
    htobe16buf(buf + 6, to_port);  // destination port
    buf[9] = kovri::client::PROTOCOL_TYPE_DATAGRAM;  // datagram protocol
    msg->len += size + 4;
    msg->FillI2NPMessageHeader(kovri::core::I2NPData);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
  }
  return msg;
}

}  // namespace client
}  // namespace kovri
