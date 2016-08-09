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

#include "transit_tunnel.h"

#include <string.h>

#include "i2np_protocol.h"
#include "router_context.h"
#include "tunnel.h"
#include "transport/transports.h"
#include "util/i2p_endian.h"
#include "util/log.h"

namespace i2p {
namespace tunnel {

TransitTunnel::TransitTunnel(
    uint32_t receiveTunnelID,
    const uint8_t* nextIdent,
    uint32_t nextTunnelID,
    const uint8_t* layerKey,
    const uint8_t* ivKey)
    : m_TunnelID(receiveTunnelID),
      m_NextTunnelID(nextTunnelID),
      m_NextIdent(nextIdent) {
  m_Encryption.SetKeys(layerKey, ivKey);
}

void TransitTunnel::EncryptTunnelMsg(
    std::shared_ptr<const I2NPMessage> in,
    std::shared_ptr<I2NPMessage> out) {
  m_Encryption.Encrypt(
      in->GetPayload() + 4,
      out->GetPayload() + 4);
}

TransitTunnelParticipant::~TransitTunnelParticipant() {}

void TransitTunnelParticipant::HandleTunnelDataMsg(
    std::shared_ptr<const i2p::I2NPMessage> tunnelMsg) {
  auto newMsg = CreateEmptyTunnelDataMsg();
  EncryptTunnelMsg(tunnelMsg, newMsg);
  m_NumTransmittedBytes += tunnelMsg->GetLength();
  htobe32buf(newMsg->GetPayload(), GetNextTunnelID());
  newMsg->FillI2NPMessageHeader(e_I2NPTunnelData);
  m_TunnelDataMsgs.push_back(newMsg);
}

void TransitTunnelParticipant::FlushTunnelDataMsgs() {
  if (!m_TunnelDataMsgs.empty()) {
    auto num = m_TunnelDataMsgs.size();
    if (num > 1)
      LogPrint(eLogDebug,
          "TransitTunnelParticipant: ", GetTunnelID(),
          "->", GetNextTunnelID(),
          " ", num);
    i2p::transport::transports.SendMessages(
        GetNextIdentHash(),
        m_TunnelDataMsgs);
    m_TunnelDataMsgs.clear();
  }
}

void TransitTunnel::SendTunnelDataMsg(
    std::shared_ptr<i2p::I2NPMessage>) {
  LogPrint(eLogError,
      "TransitTunnel: we are not a gateway for transit tunnel: ",
      m_TunnelID);
}

void TransitTunnel::HandleTunnelDataMsg(
    std::shared_ptr<const i2p::I2NPMessage>) {
  LogPrint(eLogError,
      "TransitTunnel: incoming tunnel message is not supported: ",
      m_TunnelID);
}

void TransitTunnelGateway::SendTunnelDataMsg(
    std::shared_ptr<i2p::I2NPMessage> msg) {
  TunnelMessageBlock block;
  block.deliveryType = e_DeliveryTypeLocal;
  block.data = msg;
  std::unique_lock<std::mutex> l(m_SendMutex);
  m_Gateway.PutTunnelDataMsg(block);
}

void TransitTunnelGateway::FlushTunnelDataMsgs() {
  std::unique_lock<std::mutex> l(m_SendMutex);
  m_Gateway.SendBuffer();
}

void TransitTunnelEndpoint::HandleTunnelDataMsg(
    std::shared_ptr<const i2p::I2NPMessage> tunnelMsg) {
  auto newMsg = CreateEmptyTunnelDataMsg();
  EncryptTunnelMsg(tunnelMsg, newMsg);
  LogPrint(eLogDebug,
      "TransitTunnelEndpoint: endpoint for ", GetTunnelID());
  m_Endpoint.HandleDecryptedTunnelDataMsg(newMsg);
}

TransitTunnel* CreateTransitTunnel(
    uint32_t receiveTunnelID,
    const uint8_t* nextIdent,
    uint32_t nextTunnelID,
    const uint8_t* layerKey,
    const uint8_t* ivKey,
    bool isGateway,
    bool isEndpoint) {
  if (isEndpoint) {
    LogPrint(eLogInfo,
        "TransitTunnel: endpoint ", receiveTunnelID, " created");
    return new TransitTunnelEndpoint(
        receiveTunnelID,
        nextIdent,
        nextTunnelID,
        layerKey,
        ivKey);
  } else if (isGateway) {
    LogPrint(eLogInfo,
        "TransitTunnel: gateway: ", receiveTunnelID, " created");
    return new TransitTunnelGateway(
        receiveTunnelID,
        nextIdent,
        nextTunnelID,
        layerKey,
        ivKey);
  } else {
    LogPrint(eLogInfo,
        "TransitTunnel: ", receiveTunnelID, "->", nextTunnelID, " created");
    return new TransitTunnelParticipant(
        receiveTunnelID,
        nextIdent,
        nextTunnelID,
        layerKey,
        ivKey);
  }
}

}  // namespace tunnel
}  // namespace i2p
