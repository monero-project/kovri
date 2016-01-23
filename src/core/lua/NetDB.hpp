#ifndef SRC_CORE_LUA_NETDB_HPP_
#define SRC_CORE_LUA_NETDB_HPP_
#include <string>
#include "RouterInfo.h"

namespace i2p
{
namespace lua
{
  const i2p::data::RouterInfo* FindRouterByHash(const std::string & hash);
}
}

#endif
