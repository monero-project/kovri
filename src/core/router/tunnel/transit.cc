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
                                                                                            //
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

#include "core/router/tunnel/transit.h"

#include <string.h>

#include "core/router/context.h"
#include "core/router/i2np.h"
#include "core/router/transports/impl.h"
#include "core/router/tunnel/impl.h"

#include "core/util/i2p_endian.h"
#include "core/util/log.h"

namespace kovri {
namespace core {

TransitTunnel::TransitTunnel(
    std::uint32_t receive_tunnel_ID,
    const std::uint8_t* next_ident,
    std::uint32_t next_tunnel_ID,
    const std::uint8_t* layer_key,
    const std::uint8_t* iv_key)
    : m_TunnelID(receive_tunnel_ID),
      m_NextTunnelID(next_tunnel_ID),
      m_NextIdent(next_ident),
      m_Exception(__func__) {
  try {
    m_Encryption.SetKeys(layer_key, iv_key);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

void TransitTunnel::EncryptTunnelMsg(
    std::shared_ptr<const I2NPMessage> in,
    std::shared_ptr<I2NPMessage> out) {
  // TODO(anonimal): this try block should be handled entirely by caller
  try {
    m_Encryption.Encrypt(in->GetPayload() + 4, out->GetPayload() + 4);
  } catch (...) {
    m_Exception.Dispatch(__func__);
    // TODO(anonimal): review if we need to safely break control, ensure exception handling by callers
    throw;
  }
}

TransitTunnelParticipant::~TransitTunnelParticipant() {}

void TransitTunnelParticipant::HandleTunnelDataMsg(
    std::shared_ptr<const kovri::core::I2NPMessage> tunnel_msg) {
  auto new_msg = CreateEmptyTunnelDataMsg();
  EncryptTunnelMsg(tunnel_msg, new_msg);
  m_NumTransmittedBytes += tunnel_msg->GetLength();
  htobe32buf(new_msg->GetPayload(), GetNextTunnelID());
  new_msg->FillI2NPMessageHeader(I2NPTunnelData);
  m_TunnelDataMsgs.push_back(new_msg);
}

void TransitTunnelParticipant::FlushTunnelDataMsgs() {
  if (!m_TunnelDataMsgs.empty()) {
    auto num = m_TunnelDataMsgs.size();
    if (num > 1)
      LOG(debug)
        << "TransitTunnelParticipant: " << GetTunnelID()
        << "->" << GetNextTunnelID()
        << " " << num;
    kovri::core::transports.SendMessages(
        GetNextIdentHash(),
        m_TunnelDataMsgs);
    m_TunnelDataMsgs.clear();
  }
}

void TransitTunnel::SendTunnelDataMsg(
    std::shared_ptr<kovri::core::I2NPMessage>) {
  LOG(error)
    << "TransitTunnel: we are not a gateway for transit tunnel: " << m_TunnelID;
}

void TransitTunnel::HandleTunnelDataMsg(
    std::shared_ptr<const kovri::core::I2NPMessage>) {
  LOG(error)
    << "TransitTunnel: incoming tunnel message is not supported: " << m_TunnelID;
}

void TransitTunnelGateway::SendTunnelDataMsg(
    std::shared_ptr<kovri::core::I2NPMessage> msg) {
  TunnelMessageBlock block;
  block.delivery_type = e_DeliveryTypeLocal;
  block.data = msg;
  std::unique_lock<std::mutex> l(m_SendMutex);
  m_Gateway.PutTunnelDataMsg(block);
}

void TransitTunnelGateway::FlushTunnelDataMsgs() {
  std::unique_lock<std::mutex> l(m_SendMutex);
  m_Gateway.SendBuffer();
}

void TransitTunnelEndpoint::HandleTunnelDataMsg(
    std::shared_ptr<const kovri::core::I2NPMessage> tunnel_msg) {
  auto new_msg = CreateEmptyTunnelDataMsg();
  EncryptTunnelMsg(tunnel_msg, new_msg);
  LOG(debug) << "TransitTunnelEndpoint: endpoint for " << GetTunnelID();
  m_Endpoint.HandleDecryptedTunnelDataMsg(new_msg);
}

TransitTunnel* CreateTransitTunnel(
    std::uint32_t receive_tunnel_ID,
    const std::uint8_t* next_ident,
    std::uint32_t next_tunnel_ID,
    const std::uint8_t* layer_key,
    const std::uint8_t* iv_key,
    bool is_gateway,
    bool is_endpoint) {
  if (is_endpoint) {
    LOG(debug) << "TransitTunnel: endpoint " << receive_tunnel_ID << " created";
    return new TransitTunnelEndpoint(
        receive_tunnel_ID,
        next_ident,
        next_tunnel_ID,
        layer_key,
        iv_key);
  } else if (is_gateway) {
    LOG(debug) << "TransitTunnel: gateway: " << receive_tunnel_ID << " created";
    return new TransitTunnelGateway(
        receive_tunnel_ID,
        next_ident,
        next_tunnel_ID,
        layer_key,
        iv_key);
  } else {
    LOG(debug)
      << "TransitTunnel: " << receive_tunnel_ID << "->" << next_tunnel_ID << " created";
    return new TransitTunnelParticipant(
        receive_tunnel_ID,
        next_ident,
        next_tunnel_ID,
        layer_key,
        iv_key);
  }
}

}  // namespace core
}  // namespace kovri
