#include "lua/NetDB.hpp"
#include "NetworkDatabase.h"

namespace i2lua
{
  const i2p::data::RouterInfo* FindRouterByHash(const std::string & hash) {
    i2p::data::IdentHash rh;
    rh.FromBase64(hash);
    auto ri = i2p::data::netdb.GetRouterByHash(rh);
    if (ri) {
      return ri.get();
    } else {
      return nullptr;
    }
  }

}
