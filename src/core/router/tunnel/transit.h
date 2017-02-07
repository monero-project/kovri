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

#ifndef SRC_CORE_ROUTER_TRANSIT_TUNNEL_H_
#define SRC_CORE_ROUTER_TRANSIT_TUNNEL_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "core/crypto/tunnel.h"

#include "core/router/i2np.h"
#include "core/router/tunnel/base.h"
#include "core/router/tunnel/endpoint.h"
#include "core/router/tunnel/gateway.h"

#include "core/util/exception.h"

namespace kovri {
namespace core {

class TransitTunnel : public TunnelBase {
 public:
  TransitTunnel(
      std::uint32_t receive_tunnel_ID,
      const std::uint8_t* next_ident,
      std::uint32_t next_tunnel_ID,
      const std::uint8_t* layer_key,
      const std::uint8_t* iv_key);

  virtual std::size_t GetNumTransmittedBytes() const {
    return 0;
  }

  std::uint32_t GetTunnelID() const {
    return m_TunnelID;
  }

  // implements TunnelBase
  void SendTunnelDataMsg(
      std::shared_ptr<kovri::core::I2NPMessage> msg);

  void HandleTunnelDataMsg(
      std::shared_ptr<const kovri::core::I2NPMessage> tunnel_msg);

  void EncryptTunnelMsg(
      std::shared_ptr<const I2NPMessage> in,
      std::shared_ptr<I2NPMessage> out);

  std::uint32_t GetNextTunnelID() const {
    return m_NextTunnelID;
  }

  const kovri::core::IdentHash& GetNextIdentHash() const {
    return m_NextIdent;
  }

 private:
  std::uint32_t m_TunnelID,
           m_NextTunnelID;
  kovri::core::IdentHash m_NextIdent;
  kovri::core::TunnelEncryption m_Encryption;
  core::Exception m_Exception;
};

class TransitTunnelParticipant : public TransitTunnel {
 public:
  TransitTunnelParticipant(
      std::uint32_t receive_tunnel_ID,
      const std::uint8_t* next_ident,
      std::uint32_t next_tunnel_ID,
      const std::uint8_t* layer_key,
      const std::uint8_t* iv_key)
      : TransitTunnel(
          receive_tunnel_ID,
          next_ident,
          next_tunnel_ID,
          layer_key,
          iv_key),
      m_NumTransmittedBytes(0) {}
  ~TransitTunnelParticipant();

  std::size_t GetNumTransmittedBytes() const {
    return m_NumTransmittedBytes;
  }

  void HandleTunnelDataMsg(
      std::shared_ptr<const kovri::core::I2NPMessage> tunnel_msg);

  void FlushTunnelDataMsgs();

 private:
  std::size_t m_NumTransmittedBytes;
  std::vector<std::shared_ptr<kovri::core::I2NPMessage> > m_TunnelDataMsgs;
};

class TransitTunnelGateway : public TransitTunnel {
 public:
  TransitTunnelGateway(
      std::uint32_t receive_tunnel_ID,
      const std::uint8_t* next_ident,
      std::uint32_t next_tunnel_ID,
      const std::uint8_t* layer_key,
      const std::uint8_t* iv_key)
      : TransitTunnel(
          receive_tunnel_ID,
          next_ident,
          next_tunnel_ID,
          layer_key,
          iv_key),
      m_Gateway(this) {}

  void SendTunnelDataMsg(
      std::shared_ptr<kovri::core::I2NPMessage> msg);

  void FlushTunnelDataMsgs();

  std::size_t GetNumTransmittedBytes() const {
    return m_Gateway.GetNumSentBytes();
  }

 private:
  std::mutex m_SendMutex;
  TunnelGateway m_Gateway;
};

class TransitTunnelEndpoint : public TransitTunnel {
 public:
  TransitTunnelEndpoint(
      std::uint32_t receive_tunnel_ID,
      const std::uint8_t* next_ident,
      std::uint32_t next_tunnel_ID,
      const std::uint8_t* layer_key,
      const std::uint8_t* iv_key)
      : TransitTunnel(
          receive_tunnel_ID,
          next_ident,
          next_tunnel_ID,
          layer_key,
          iv_key),
      m_Endpoint(false) {}  // transit endpoint is always outbound

  void HandleTunnelDataMsg(
      std::shared_ptr<const kovri::core::I2NPMessage> tunnel_msg);

  std::size_t GetNumTransmittedBytes() const {
    return m_Endpoint.GetNumReceivedBytes();
  }

 private:
  TunnelEndpoint m_Endpoint;
};

TransitTunnel* CreateTransitTunnel(
    std::uint32_t receive_tunnel_ID,
    const std::uint8_t* next_ident,
    std::uint32_t next_tunnel_ID,
    const std::uint8_t* layer_key,
    const std::uint8_t* iv_key,
    bool is_gateway,
    bool is_endpoint);

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_TUNNEL_TRANSIT_H_
