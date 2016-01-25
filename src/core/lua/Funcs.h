#ifndef SRC_CORE_LUA_FUNCS_H_
#define SRC_CORE_LUA_FUNCS_H_

 
#include <lua.hpp>
namespace i2p
{
namespace lua
{
// initialize the i2p router parameters
int Init(lua_State* L);
// run the i2p router
int Start(lua_State* L);
// set a hook function that does tunnel building strategy
int SetTunnelBuildStrategy(lua_State* L);
// get a RI given its hash as a string 
int GetRouterInfoByHash(lua_State* L);
// get a random RI
int GetRandomRouterInfo(lua_State* L);
// sleep until router is done
int Wait(lua_State* L);
// stop execution of kovri router immediately
int Stop(lua_State* L);
// sleep for n milliseconds
int Sleep(lua_State* L);

luaL_Reg funcs[] = {
  {"Init", Init},
  {"Start", Start},
  {"SetBuildStrategy", SetTunnelBuildStrategy},
  {"GetRouterByHash", GetRouterInfoByHash},
  {"GetRandomHash", GetRandomRouterInfo},
  {"Stop", Stop},
  {"Wait", Wait},
  {"Sleep", Sleep},
  {0, 0}
};
}
}
#endif
