#ifndef SRC_CORE_LUA_FUNCS_H_
#define SRC_CORE_LUA_FUNCS_H_

 
#include <lua.hpp>
// initialize the i2p router parameters
int kovri_init(lua_State* L);
// run the i2p router
int kovri_start(lua_State* L);
// set a hook function that does tunnel building strategy
int kovri_set_tunnel_build_strategy(lua_State* L);
// get a RI given its hash as a string 
int kovri_get_ri_by_hash(lua_State* L);
// get a random RI
int kovri_get_ri_random(lua_State* L);

luaL_Reg funcs[] = {
  {"startRouter", kovri_start},
  {"setBuildStrategy", kovri_set_tunnel_build_strategy},
  {"getRouterByHash", kovri_get_ri_by_hash},
  {"getRandomHash", kovri_get_ri_random},
  {0, 0}
};

#endif
