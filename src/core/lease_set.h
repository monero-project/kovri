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

#ifndef SRC_CORE_LEASE_SET_H_
#define SRC_CORE_LEASE_SET_H_

#include <array>
#include <cstdint>
#include <memory>
#include <vector>

#include "identity.h"

namespace i2p {
// TODO(unassigned): remove this forward declaration after cleaning up core/tunnel
namespace tunnel { class TunnelPool; }
namespace data {

struct Lease {
  IdentHash tunnel_gateway;
  std::uint32_t tunnel_ID;
  std::uint64_t end_date;
  bool operator<(const Lease& other) const {
    if (end_date != other.end_date)
      return end_date > other.end_date;
    else
      return tunnel_ID < other.tunnel_ID;
  }
};

const int MAX_LS_BUFFER_SIZE = 3072;

class LeaseSet : public RoutingDestination {
 public:
  LeaseSet(
      const std::uint8_t* buf,
      std::size_t len);

  explicit LeaseSet(
      const i2p::tunnel::TunnelPool& pool);

  ~LeaseSet() {}

  void Update(
      const std::uint8_t* buf,
      std::size_t len);

  const IdentityEx& GetIdentity() const {
    return m_Identity;
  }

  const std::uint8_t* GetBuffer() const {
    const auto buf = m_Buffer.get();
    return buf;
  }

  std::size_t GetBufferLen() const {
    return m_BufferLen;
  }

  bool IsValid() const {
    return m_IsValid;
  }

  // implements RoutingDestination
  const IdentHash& GetIdentHash() const {
    return m_Identity.GetIdentHash();
  }

  const std::vector<Lease>& GetLeases() const {
    return m_Leases;
  }

  const std::vector<Lease> GetNonExpiredLeases(
      bool with_threshold = true) const;

  bool HasExpiredLeases() const;

  bool HasNonExpiredLeases() const;

  const std::uint8_t* GetEncryptionPublicKey() const {
    return m_EncryptionKey.data();
  }

  bool IsDestination() const {
    return true;
  }

 private:
  void ReadFromBuffer();

 private:
  bool m_IsValid;
  std::vector<Lease> m_Leases;
  IdentityEx m_Identity;
  std::array<std::uint8_t, 256> m_EncryptionKey;
  std::unique_ptr<std::uint8_t[]> m_Buffer;
  std::size_t m_BufferLen;
};

}  // namespace data
}  // namespace i2p

#endif  // SRC_CORE_LEASE_SET_H_
