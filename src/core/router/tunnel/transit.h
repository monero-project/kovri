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

#include "core/crypto/tunnel.h"

#include "core/router/i2np.h"
#include "core/router/tunnel/base.h"
#include "core/router/tunnel/endpoint.h"
#include "core/router/tunnel/gateway.h"

namespace kovri {
namespace core {

class TransitTunnel : public TunnelBase {
 public:
  TransitTunnel(
      uint32_t receive_tunnel_ID,
      const uint8_t* next_ident,
      uint32_t next_tunnel_ID,
      const uint8_t* layer_key,
      const uint8_t* iv_key);

  virtual size_t GetNumTransmittedBytes() const {
    return 0;
  }

  uint32_t GetTunnelID() const {
    return m_TunnelID;
  }

  // implements TunnelBase
  void SendTunnelDataMsg(
      std::shared_ptr<kovri::I2NPMessage> msg);

  void HandleTunnelDataMsg(
      std::shared_ptr<const kovri::I2NPMessage> tunnel_msg);

  void EncryptTunnelMsg(
      std::shared_ptr<const I2NPMessage> in,
      std::shared_ptr<I2NPMessage> out);

  uint32_t GetNextTunnelID() const {
    return m_NextTunnelID;
  }

  const kovri::core::IdentHash& GetNextIdentHash() const {
    return m_NextIdent;
  }

 private:
  uint32_t m_TunnelID,
           m_NextTunnelID;
  kovri::core::IdentHash m_NextIdent;
  kovri::core::TunnelEncryption m_Encryption;
};

class TransitTunnelParticipant : public TransitTunnel {
 public:
  TransitTunnelParticipant(
      uint32_t receive_tunnel_ID,
      const uint8_t* next_ident,
      uint32_t next_tunnel_ID,
      const uint8_t* layer_key,
      const uint8_t* iv_key)
      : TransitTunnel(
          receive_tunnel_ID,
          next_ident,
          next_tunnel_ID,
          layer_key,
          iv_key),
      m_NumTransmittedBytes(0) {}
  ~TransitTunnelParticipant();

  size_t GetNumTransmittedBytes() const {
    return m_NumTransmittedBytes;
  }

  void HandleTunnelDataMsg(
      std::shared_ptr<const kovri::I2NPMessage> tunnelMsg);

  void FlushTunnelDataMsgs();

 private:
  size_t m_NumTransmittedBytes;
  std::vector<std::shared_ptr<kovri::I2NPMessage> > m_TunnelDataMsgs;
};

class TransitTunnelGateway : public TransitTunnel {
 public:
  TransitTunnelGateway(
      uint32_t receive_tunnel_ID,
      const uint8_t* next_ident,
      uint32_t next_tunnel_ID,
      const uint8_t* layer_key,
      const uint8_t* iv_key)
      : TransitTunnel(
          receive_tunnel_ID,
          next_ident,
          next_tunnel_ID,
          layer_key,
          iv_key),
      m_Gateway(this) {}

  void SendTunnelDataMsg(
      std::shared_ptr<kovri::I2NPMessage> msg);

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
      uint32_t receive_tunnel_ID,
      const uint8_t* next_ident,
      uint32_t next_tunnel_ID,
      const uint8_t* layer_key,
      const uint8_t* iv_key)
      : TransitTunnel(
          receive_tunnel_ID,
          next_ident,
          next_tunnel_ID,
          layer_key,
          iv_key),
      m_Endpoint(false) {}  // transit endpoint is always outbound

  void HandleTunnelDataMsg(
      std::shared_ptr<const kovri::I2NPMessage> tunnel_msg);

  size_t GetNumTransmittedBytes() const {
    return m_Endpoint.GetNumReceivedBytes();
  }

 private:
  TunnelEndpoint m_Endpoint;
};

TransitTunnel* CreateTransitTunnel(
    uint32_t receive_tunnel_ID,
    const uint8_t* next_ident,
    uint32_t next_tunnel_ID,
    const uint8_t* layer_key,
    const uint8_t* iv_key,
    bool is_gateway,
    bool is_endpoint);

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_TUNNEL_TRANSIT_H_
