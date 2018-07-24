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

#ifndef SRC_CORE_ROUTER_TUNNEL_CONFIG_H_
#define SRC_CORE_ROUTER_TUNNEL_CONFIG_H_

#include <array>
#include <memory>
#include <cstdint>
#include <vector>
#include <sstream>

#include "core/crypto/rand.h"
#include "core/crypto/tunnel.h"
#include "core/router/info.h"

#include "core/util/exception.h"

namespace kovri {
namespace core {

/// @class TunnelAESRecordAttributes
/// @brief AES-related attributes for build request record
/// @warning *Must* be initialized with random data
struct TunnelAESRecordAttributes {
  TunnelAESRecordAttributes();
  std::array<std::uint8_t, 32> layer_key, IV_key, reply_key;
  std::array<std::uint8_t, 16> reply_IV;
};

/// @class TunnelHopConfig
class TunnelHopConfig {
 public:
  explicit TunnelHopConfig(
      std::shared_ptr<const RouterInfo> router);

  /// @brief Creates a build request record for tunnel build message
  void CreateBuildRequestRecord(
      std::uint8_t* record,
      std::uint32_t reply_msg_ID);

  const std::shared_ptr<const RouterInfo>& GetCurrentRouter() const noexcept;

  void SetNextRouter(
      std::shared_ptr<const RouterInfo> router,
      std::uint32_t tunnel_id = Rand<std::uint32_t>(),
      bool is_endpoint = false);

  const std::shared_ptr<const RouterInfo>& GetNextRouter() const noexcept;

  void SetNextHop(TunnelHopConfig* hop);
  TunnelHopConfig* GetNextHop() const noexcept;

  TunnelHopConfig* GetPreviousHop() const noexcept;

  void SetReplyHop(const TunnelHopConfig* hop);

  std::uint32_t GetTunnelID() const;
  std::uint32_t GetNextTunnelID() const noexcept;

  const TunnelAESRecordAttributes& GetAESAttributes() const;

  void SetIsGateway(bool value) noexcept;
  bool IsGateway() const noexcept;

  void SetIsEndpoint(bool value) noexcept;
  bool IsEndpoint() const noexcept;

  TunnelDecryption& GetDecryption() noexcept;

  // TODO(anonimal): review type
  void SetRecordIndex(int record) noexcept;
  int GetRecordIndex() const noexcept;

 private:
  /// @brief Current router (hop) in path
  std::shared_ptr<const RouterInfo> m_CurrentRouter;

  /// @brief Tunnel ID of current router (hop)
  std::uint32_t m_TunnelID;

  /// @brief AES-related attributes for request record
  TunnelAESRecordAttributes m_AESRecordAttributes;

  /// @brief Next router (hop) in path
  std::shared_ptr<const RouterInfo> m_NextRouter;

  /// @brief Tunnel ID of next router (hop)
  std::uint32_t m_NextTunnelID;

  /// @brief Previous hop in tunnel
  TunnelHopConfig *m_PreviousHop;

  /// @brief Next hop in tunnel
  TunnelHopConfig *m_NextHop;

  /// @brief Is router (hop) a tunnel gateway?
  bool m_IsGateway;

  /// @brief Is router (hop) a tunnel endpoint?
  bool m_IsEndpoint;

  // TODO(anonimal): review type
  /// @brief Record number within tunnel build message
  int m_RecordIndex;

  /// @brief Decryption implementation
  TunnelDecryption m_Decryption;

  core::Exception m_Exception;
};

class TunnelConfig : public std::enable_shared_from_this<TunnelConfig> {
 public:
  TunnelConfig(
      std::vector<std::shared_ptr<const kovri::core::RouterInfo> > peers,
      std::shared_ptr<const TunnelConfig> reply_tunnel_config = nullptr);
  ~TunnelConfig();

  TunnelHopConfig* GetFirstHop() const;

  TunnelHopConfig* GetLastHop() const;

  int GetNumHops() const;

  bool IsInbound() const;

  std::vector<std::shared_ptr<const kovri::core::RouterInfo> > GetPeers() const;

  void Print(
      std::stringstream& s) const;

  std::shared_ptr<TunnelConfig> Invert() const;

  std::shared_ptr<TunnelConfig> Clone(
      std::shared_ptr<const TunnelConfig> reply_tunnel_config = nullptr) const;

 private:
  // this constructor can't be called from outside
  TunnelConfig()
      : m_FirstHop(nullptr),
        m_LastHop(nullptr) {}

 private:
  TunnelHopConfig *m_FirstHop, *m_LastHop;
};

}  // namespace core
}  // namespace kovri

#endif  // SRC_CORE_ROUTER_TUNNEL_CONFIG_H_
