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

#include "lease_set.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "net_db.h"
#include "crypto/rand.h"
#include "tunnel/tunnel_pool.h"
#include "util/i2p_endian.h"
#include "util/log.h"
#include "util/timestamp.h"

namespace i2p {
namespace data {

LeaseSet::LeaseSet(
    const std::uint8_t* buf,
    std::size_t len)
    : m_IsValid(true) {
  m_Buffer = std::make_unique<std::uint8_t[]>(len);
  memcpy(m_Buffer.get(), buf, len);
  m_BufferLen = len;
  ReadFromBuffer();
}

LeaseSet::LeaseSet(
    const i2p::tunnel::TunnelPool& pool)
    : m_IsValid(true) {
  // header
  const i2p::data::LocalDestination* local_destination = pool.GetLocalDestination();
  if (!local_destination) {
    m_Buffer.reset(nullptr);
    m_BufferLen = 0;
    m_IsValid = false;
    LogPrint(eLogError,
        "LeaseSet: destination for local LeaseSet doesn't exist");
    return;
  }
  m_Buffer = std::make_unique<std::uint8_t[]>(MAX_LS_BUFFER_SIZE);
  m_BufferLen = local_destination->GetIdentity().ToBuffer(
      m_Buffer.get(),
      MAX_LS_BUFFER_SIZE);
  memcpy(
      m_Buffer.get() + m_BufferLen,
      local_destination->GetEncryptionPublicKey(),
      256);
  m_BufferLen += 256;
  auto signing_key_len = local_destination->GetIdentity().GetSigningPublicKeyLen();
  memset(m_Buffer.get() + m_BufferLen, 0, signing_key_len);
  m_BufferLen += signing_key_len;
  auto tunnels = pool.GetInboundTunnels(5);  // 5 tunnels maximum
  m_Buffer[m_BufferLen] = tunnels.size();  // num leases
  m_BufferLen++;
  // leases
  for (auto it : tunnels) {
    memcpy(m_Buffer.get() + m_BufferLen, it->GetNextIdentHash(), 32);
    m_BufferLen += 32;  // gateway id
    htobe32buf(m_Buffer.get() + m_BufferLen, it->GetNextTunnelID());
    m_BufferLen += 4;  // tunnel id
    std::uint64_t ts =
      it->GetCreationTime() +
      i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT -
      i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD;  // 1 minute before expiration
    ts *= 1000;  // in milliseconds
    ts += i2p::crypto::RandInRange<std::size_t>(0, 5);  // + random milliseconds
    htobe64buf(m_Buffer.get() + m_BufferLen, ts);
    m_BufferLen += 8;  // end date
  }
  // signature
  local_destination->Sign(
      m_Buffer.get(),
      m_BufferLen,
      m_Buffer.get() + m_BufferLen);
  m_BufferLen += local_destination->GetIdentity().GetSignatureLen();
  LogPrint(eLogInfo,
      "LeaseSet: local LeaseSet of ", tunnels.size(), " leases created");
  ReadFromBuffer();
}

void LeaseSet::Update(
    const std::uint8_t* buf,
    std::size_t len) {
  m_Leases.clear();
  if (len > m_BufferLen) {
    m_Buffer = std::make_unique<std::uint8_t[]>(len);
  }
  memcpy(m_Buffer.get(), buf, len);
  m_BufferLen = len;
  ReadFromBuffer();
}

void LeaseSet::ReadFromBuffer() {
  std::size_t size = m_Identity.FromBuffer(m_Buffer.get(), m_BufferLen);
  memcpy(m_EncryptionKey.data(), m_Buffer.get() + size, 256);
  size += 256;  // encryption key
  size += m_Identity.GetSigningPublicKeyLen();  // unused signing key
  std::uint8_t num = m_Buffer[size];
  size++;  // num
  LogPrint(eLogDebug, "LeaseSet: num=", static_cast<int>(num));
  if (!num)
    m_IsValid = false;
  // process leases
  const std::uint8_t* leases = m_Buffer.get() + size;
  for (int i = 0; i < num; i++) {
    Lease lease;
    lease.tunnel_gateway = leases;
    leases += 32;  // gateway
    lease.tunnel_ID = bufbe32toh(leases);
    leases += 4;  // tunnel ID
    lease.end_date = bufbe64toh(leases);
    leases += 8;  // end date
    m_Leases.push_back(lease);
    // check if lease's gateway is in our netDb
    if (!netdb.FindRouter(lease.tunnel_gateway)) {
      // if not found request it
      LogPrint(eLogInfo, "LeaseSet: lease's tunnel gateway not found, requesting");
      netdb.RequestDestination(lease.tunnel_gateway);
    }
  }
  // verify
  if (!m_Identity.Verify(m_Buffer.get(), leases - m_Buffer.get(), leases)) {
    LogPrint(eLogWarn, "LeaseSet: verification failed");
    m_IsValid = false;
  }
}

const std::vector<Lease> LeaseSet::GetNonExpiredLeases(
    bool with_threshold) const {
  auto ts = i2p::util::GetMillisecondsSinceEpoch();
  std::vector<Lease> leases;
  for (auto& it : m_Leases) {
    auto end_date = it.end_date;
    if (!with_threshold)
      end_date -= i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD * 1000;
    if (ts < end_date)
      leases.push_back(it);
  }
  return leases;
}

bool LeaseSet::HasExpiredLeases() const {
  auto ts = i2p::util::GetMillisecondsSinceEpoch();
  for (auto& it : m_Leases)
    if (ts >= it.end_date)
      return true;
  return false;
}

bool LeaseSet::HasNonExpiredLeases() const {
  auto ts = i2p::util::GetMillisecondsSinceEpoch();
  for (auto& it : m_Leases)
    if (ts < it.end_date)
      return true;
  return false;
}

}  // namespace data
}  // namespace i2p
