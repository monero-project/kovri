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

#ifndef SRC_CORE_NET_DB_REQUESTS_H_
#define SRC_CORE_NET_DB_REQUESTS_H_

#include <map>
#include <memory>
#include <mutex>
#include <set>

#include "i2np_protocol.h"
#include "identity.h"
#include "router_info.h"

namespace i2p {
namespace data {

class RequestedDestination {
 public:
  typedef std::function<void (std::shared_ptr<RouterInfo>)> RequestComplete;

  RequestedDestination(
      const IdentHash& destination,
      bool isExploratory = false)
      : m_Destination(destination),
        m_IsExploratory(isExploratory),
        m_CreationTime(0) {}
  ~RequestedDestination() {
    if (m_RequestComplete)
      m_RequestComplete(nullptr);
  }

  const IdentHash& GetDestination() const {
    return m_Destination;
  }

  int GetNumExcludedPeers() const {
    return m_ExcludedPeers.size();
  }

  const std::set<IdentHash>& GetExcludedPeers() {
    return m_ExcludedPeers;
  }

  void ClearExcludedPeers();

  bool IsExploratory() const {
    return m_IsExploratory;
  }

  bool IsExcluded(
      const IdentHash& ident) const {
    return m_ExcludedPeers.count (ident);
  }

  uint64_t GetCreationTime() const {
    return m_CreationTime;
  }

  std::shared_ptr<I2NPMessage> CreateRequestMessage(
      std::shared_ptr<const RouterInfo>,
      std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel);
  std::shared_ptr<I2NPMessage> CreateRequestMessage(
      const IdentHash& floodfill);

  void SetRequestComplete(
      const RequestComplete& requestComplete) {
    m_RequestComplete = requestComplete;
  }

  bool IsRequestComplete() const {
    return m_RequestComplete != nullptr;
  }

  void Success(std::shared_ptr<RouterInfo> r);
  void Fail();

 private:
  IdentHash m_Destination;
  bool m_IsExploratory;
  std::set<IdentHash> m_ExcludedPeers;
  uint64_t m_CreationTime;
  RequestComplete m_RequestComplete;
};

class NetDbRequests {
 public:
  void Start();
  void Stop();

  std::shared_ptr<RequestedDestination> CreateRequest(
      const IdentHash& destination,
      bool isExploratory,
      RequestedDestination::RequestComplete requestComplete = nullptr);

  void RequestComplete(
      const IdentHash& ident,
      std::shared_ptr<RouterInfo> r);

  std::shared_ptr<RequestedDestination> FindRequest(
      const IdentHash& ident) const;

  void ManageRequests();

 private:
  std::mutex m_RequestedDestinationsMutex;
  std::map<IdentHash, std::shared_ptr<RequestedDestination> >
    m_RequestedDestinations;
};

}  // namespace data
}  // namespace i2p

#endif  // SRC_CORE_NET_DB_REQUESTS_H_
