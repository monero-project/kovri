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

#include "datagram.h"

#include <string.h>

#include <vector>

#include "router_context.h"
#include "client/destination.h"
#include "crypto/hash.h"
#include "crypto/rand.h"
#include "crypto/util/compression.h"
#include "tunnel/tunnel_base.h"
#include "util/log.h"

namespace i2p {
namespace datagram {

DatagramDestination::DatagramDestination(
    i2p::client::ClientDestination& owner)
    : m_Owner(owner),
      m_Receiver(nullptr) {}

void DatagramDestination::SendDatagramTo(
    const uint8_t* payload,
    size_t len,
    const i2p::data::IdentHash& ident,
    uint16_t fromPort,
    uint16_t toPort) {
  uint8_t buf[MAX_DATAGRAM_SIZE];
  auto identityLen =
    m_Owner.GetIdentity().ToBuffer(buf, MAX_DATAGRAM_SIZE);
  uint8_t* signature = buf + identityLen;
  auto signatureLen = m_Owner.GetIdentity().GetSignatureLen();
  uint8_t* buf1 = signature + signatureLen;
  size_t headerLen = identityLen + signatureLen;
  memcpy(buf1, payload, len);
  if (m_Owner.GetIdentity().GetSigningKeyType() ==
      i2p::data::SIGNING_KEY_TYPE_DSA_SHA1) {
    uint8_t hash[32];
    i2p::crypto::SHA256().CalculateDigest(hash, buf1, len);
    m_Owner.Sign(hash, 32, signature);
  } else {
    m_Owner.Sign(buf1, len, signature);
  }
  auto msg =
    CreateDataMessage(buf, len + headerLen, fromPort, toPort);
  auto remote = m_Owner.FindLeaseSet(ident);
  if (remote)
    m_Owner.GetService().post(
        std::bind(
          &DatagramDestination::SendMsg,
          this, msg, remote));
  else
    m_Owner.RequestDestination(
        ident, std::bind(
          &DatagramDestination::HandleLeaseSetRequestComplete,
          this, std::placeholders::_1, msg));
}

void DatagramDestination::HandleLeaseSetRequestComplete(
    std::shared_ptr<i2p::data::LeaseSet> remote,
    I2NPMessage* msg) {
  if (remote)
    SendMsg(msg, remote);
  else
    DeleteI2NPMessage(msg);
}

void DatagramDestination::SendMsg(
    I2NPMessage* msg,
    std::shared_ptr<const i2p::data::LeaseSet> remote) {
  auto outboundTunnel = m_Owner.GetTunnelPool()->GetNextOutboundTunnel();
  auto leases = remote->GetNonExpiredLeases();
  if (!leases.empty() && outboundTunnel) {
    std::vector<i2p::tunnel::TunnelMessageBlock> msgs;
    uint32_t i = i2p::crypto::RandInRange<uint32_t>(0, leases.size() - 1);
    auto garlic = m_Owner.WrapMessage(remote, ToSharedI2NPMessage(msg), true);
    msgs.push_back(
        i2p::tunnel::TunnelMessageBlock {
        i2p::tunnel::e_DeliveryTypeTunnel,
        leases[i].tunnel_gateway,
        leases[i].tunnel_ID,
        garlic});
    outboundTunnel->SendTunnelDataMsg(msgs);
  } else {
    if (outboundTunnel)
      LogPrint(eLogWarn,
          "DatagramDestination: failed to send datagram: all leases expired");
    else
      LogPrint(eLogWarn,
          "DatagramDestination: failed to send datagram: no outbound tunnels");
    DeleteI2NPMessage(msg);
  }
}

void DatagramDestination::HandleDatagram(
    uint16_t fromPort,
    uint16_t toPort,
    const uint8_t* buf,
    size_t len) {
  i2p::data::IdentityEx identity;
  size_t identityLen = identity.FromBuffer(buf, len);
  const uint8_t* signature = buf + identityLen;
  size_t headerLen = identityLen + identity.GetSignatureLen();
  bool verified = false;
  if (identity.GetSigningKeyType() == i2p::data::SIGNING_KEY_TYPE_DSA_SHA1) {
    uint8_t hash[32];
    i2p::crypto::SHA256().CalculateDigest(hash, buf + headerLen, len - headerLen);
    verified = identity.Verify(hash, 32, signature);
  } else {
    verified =
      identity.Verify(buf + headerLen, len - headerLen, signature);
  }
  if (verified) {
    auto it = m_ReceiversByPorts.find(toPort);
    if (it != m_ReceiversByPorts.end())
        it->second(
            identity, fromPort, toPort, buf + headerLen, len - headerLen);
    else if (m_Receiver != nullptr)
        m_Receiver(
            identity, fromPort, toPort, buf + headerLen, len - headerLen);
    else
        LogPrint(eLogWarn,
            "DatagramDestination: receiver for datagram is not set");
  } else {
    LogPrint(eLogWarn,
        "DatagramDestination: datagram signature verification failed");
  }
}

void DatagramDestination::HandleDataMessagePayload(
    uint16_t fromPort,
    uint16_t toPort,
    const uint8_t* buf,
    size_t len) {
  // Gunzip it
  i2p::crypto::util::Gunzip decompressor;
  decompressor.Put(buf, len);
  uint8_t uncompressed[MAX_DATAGRAM_SIZE];
  auto uncompressedLen = decompressor.MaxRetrievable();
  if (uncompressedLen <= MAX_DATAGRAM_SIZE) {
    decompressor.Get(uncompressed, uncompressedLen);
    HandleDatagram(fromPort, toPort, uncompressed, uncompressedLen);
  } else {
    LogPrint(eLogWarn,
        "DatagramDestination: the received datagram size ",
        uncompressedLen, " exceeds max size");
  }
}

I2NPMessage* DatagramDestination::CreateDataMessage(
    const uint8_t* payload,
    size_t len,
    uint16_t fromPort,
    uint16_t toPort) {
  I2NPMessage* msg = NewI2NPMessage();
  i2p::crypto::util::Gzip compressor;  // default level
  compressor.Put(payload, len);
  std::size_t size = compressor.MaxRetrievable();
  uint8_t* buf = msg->GetPayload();
  htobe32buf(buf, size);  // length
  buf += 4;
  compressor.Get(buf, size);
  htobe16buf(buf + 4, fromPort);  // source port
  htobe16buf(buf + 6, toPort);  // destination port
  buf[9] = i2p::client::PROTOCOL_TYPE_DATAGRAM;  // datagram protocol
  msg->len += size + 4;
  msg->FillI2NPMessageHeader(e_I2NPData);
  return msg;
}

}  // namespace datagram
}  // namespace i2p

