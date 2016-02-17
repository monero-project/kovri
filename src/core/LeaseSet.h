/**
 * Copyright (c) 2013-2016, The Kovri I2P Router Project
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Parts of the project are originally copyright (c) 2013-2015 The PurpleI2P Project
 */

#ifndef SRC_CORE_LEASESET_H_
#define SRC_CORE_LEASESET_H_

#include <inttypes.h>
#include <string.h>
#include <vector>
#include "Identity.h"

namespace i2p {
namespace tunnel {
class TunnelPool;
}
namespace data {

struct Lease {
  IdentHash tunnelGateway;
  uint32_t tunnelID;
  uint64_t endDate;
  bool operator< (const Lease& other) const {
    if (endDate != other.endDate)
      return endDate > other.endDate;
    else
      return tunnelID < other.tunnelID;
  }
};

const int MAX_LS_BUFFER_SIZE = 3072;

class LeaseSet : public RoutingDestination {
 public:
  LeaseSet(
      const uint8_t* buf,
      size_t len);
  explicit LeaseSet(
      const i2p::tunnel::TunnelPool& pool);
  ~LeaseSet() { delete[] m_Buffer; }

  void Update(
      const uint8_t* buf,
      size_t len);

  const IdentityEx& GetIdentity() const {
    return m_Identity;
  }

  const uint8_t* GetBuffer() const {
    return m_Buffer;
  }

  size_t GetBufferLen() const {
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
      bool withThreshold = true) const;

  bool HasExpiredLeases() const;

  bool HasNonExpiredLeases() const;

  const uint8_t* GetEncryptionPublicKey() const {
    return m_EncryptionKey;
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
  uint8_t m_EncryptionKey[256];
  uint8_t* m_Buffer;
  size_t m_BufferLen;
};

}  // namespace data
}  // namespace i2p

#endif  // SRC_CORE_LEASESET_H_
