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

#ifndef SRC_CORE_TUNNEL_TRANSIT_TUNNEL_H_
#define SRC_CORE_TUNNEL_TRANSIT_TUNNEL_H_

#include <inttypes.h>

#include <memory>
#include <mutex>
#include <vector>

#include "i2np_protocol.h"
#include "tunnel_base.h"
#include "tunnel_endpoint.h"
#include "tunnel_gateway.h"
#include "crypto/tunnel.h"

namespace i2p {
namespace tunnel {

class TransitTunnel : public TunnelBase {
 public:
  TransitTunnel(
      uint32_t receiveTunnelID,
      const uint8_t* nextIdent,
      uint32_t nextTunnelID,
      const uint8_t* layerKey,
      const uint8_t* ivKey);

  virtual size_t GetNumTransmittedBytes() const {
    return 0;
  }

  uint32_t GetTunnelID() const {
    return m_TunnelID;
  }

  // implements TunnelBase
  void SendTunnelDataMsg(
      std::shared_ptr<i2p::I2NPMessage> msg);

  void HandleTunnelDataMsg(
      std::shared_ptr<const i2p::I2NPMessage> tunnelMsg);

  void EncryptTunnelMsg(
      std::shared_ptr<const I2NPMessage> in,
      std::shared_ptr<I2NPMessage> out);

  uint32_t GetNextTunnelID() const {
    return m_NextTunnelID;
  }

  const i2p::data::IdentHash& GetNextIdentHash() const {
    return m_NextIdent;
  }

 private:
  uint32_t m_TunnelID,
           m_NextTunnelID;
  i2p::data::IdentHash m_NextIdent;
  i2p::crypto::TunnelEncryption m_Encryption;
};

class TransitTunnelParticipant : public TransitTunnel {
 public:
  TransitTunnelParticipant(
      uint32_t receiveTunnelID,
      const uint8_t* nextIdent,
      uint32_t nextTunnelID,
      const uint8_t* layerKey,
      const uint8_t* ivKey)
      : TransitTunnel(
          receiveTunnelID,
          nextIdent,
          nextTunnelID,
          layerKey,
          ivKey),
      m_NumTransmittedBytes(0) {}
  ~TransitTunnelParticipant();

  size_t GetNumTransmittedBytes() const {
    return m_NumTransmittedBytes;
  }

  void HandleTunnelDataMsg(
      std::shared_ptr<const i2p::I2NPMessage> tunnelMsg);

  void FlushTunnelDataMsgs();

 private:
  size_t m_NumTransmittedBytes;
  std::vector<std::shared_ptr<i2p::I2NPMessage> > m_TunnelDataMsgs;
};

class TransitTunnelGateway : public TransitTunnel {
 public:
  TransitTunnelGateway(
      uint32_t receiveTunnelID,
      const uint8_t* nextIdent,
      uint32_t nextTunnelID,
      const uint8_t* layerKey,
      const uint8_t* ivKey)
      : TransitTunnel(
          receiveTunnelID,
          nextIdent,
          nextTunnelID,
          layerKey,
          ivKey),
      m_Gateway(this) {}

  void SendTunnelDataMsg(
      std::shared_ptr<i2p::I2NPMessage> msg);

  void FlushTunnelDataMsgs();

  size_t GetNumTransmittedBytes() const {
    return m_Gateway.GetNumSentBytes();
  }

 private:
  std::mutex m_SendMutex;
  TunnelGateway m_Gateway;
};

class TransitTunnelEndpoint : public TransitTunnel {
 public:
  TransitTunnelEndpoint(
      uint32_t receiveTunnelID,
      const uint8_t* nextIdent,
      uint32_t nextTunnelID,
      const uint8_t* layerKey,
      const uint8_t* ivKey)
      : TransitTunnel(
          receiveTunnelID,
          nextIdent,
          nextTunnelID,
          layerKey,
          ivKey),
      m_Endpoint(false) {}  // transit endpoint is always outbound

  void HandleTunnelDataMsg(
      std::shared_ptr<const i2p::I2NPMessage> tunnelMsg);

  size_t GetNumTransmittedBytes() const {
    return m_Endpoint.GetNumReceivedBytes();
  }

 private:
  TunnelEndpoint m_Endpoint;
};

TransitTunnel* CreateTransitTunnel(
    uint32_t receiveTunnelID,
    const uint8_t* nextIdent,
    uint32_t nextTunnelID,
    const uint8_t* layerKey,
    const uint8_t* ivKey,
    bool isGateway,
    bool isEndpoint);

}  // namespace tunnel
}  // namespace i2p

#endif  // SRC_CORE_TUNNEL_TRANSIT_TUNNEL_H_
