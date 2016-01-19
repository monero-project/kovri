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
// sleep until router is done
int kovri_wait(lua_State* L);
// stop execution of kovri router immediately
int kovri_stop(lua_State* L);


luaL_Reg funcs[] = {
  {"Init", kovri_init},
  {"Start", kovri_start},
  {"SetBuildStrategy", kovri_set_tunnel_build_strategy},
  {"GetRouterByHash", kovri_get_ri_by_hash},
  {"GetRandomHash", kovri_get_ri_random},
  {"Stop", kovri_stop},
  {"Wait", kovri_wait},
  {0, 0}
};

#endif
