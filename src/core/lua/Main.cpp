#include "Funcs.h"
#include <boost/asio.hpp>
#include <string>

#include "NetworkDatabase.h"
#include "RouterContext.h"
#include "transport/Transports.h"
#include "tunnel/Tunnel.h"
//
// entry point for luajit i2p router
//
int main(int argc, char * argv[]) {
  (void) argc;
  (void) argv;
  lua_State* l = luaL_newstate();
  luaL_openlibs(l);
  luaL_register(l, "i2lua", funcs);
}

int kovri_init(lua_State* L) {
  int n = lua_gettop(L); // num of args
  if (n != 1) {
    lua_pushliteral(L, "incorrect number of arguments");
    lua_error(L);
  } else {
    
    std::string host = "0.0.0.0";
    int port = 0;
    bool v6 = false;
    bool floodfill = false;
    if (!lua_isnumber(L, 1)) {
      lua_pushliteral(L, "invalid argument, not an int");
      lua_error(L);
    } else {
      lua_Number l_port = lua_tonumber(L, 1);
      port = (int)l_port;
      if ( port > 0 ) {
        i2p::context.UpdatePort(port);
        i2p::context.UpdateAddress(boost::asio::ip::address::from_string(host));
        i2p::context.SetSupportsV6(v6);
        i2p::context.SetFloodfill(floodfill);
        i2p::context.SetHighBandwidth();
      } else {
        lua_pushliteral(L, "invalid argument, not an int");
        lua_error(L);
      }
    }
  }
  return 0;
}
  
int kovri_start(lua_State* L) {
  try {
    
    i2p::data::netdb.Start();
    i2p::transport::transports.Start();
    i2p::tunnel::tunnels.Start();
     
  } catch( std::runtime_error & ex ) {
    lua_pushstring(L, ex.what());
    lua_error(L);
  }
  return 0;
}

//TODO: implement
int kovri_set_tunnel_build_strategy(lua_State* L) {
  (void) L;
  return 0;
}


int kovri_get_ri_random(lua_State* L) {
  auto ptr = i2p::data::netdb.GetRandomRouter();
  const void * vptr = ptr.get();
  lua_pushlightuserdata(L, (void*)vptr);
  return 1;
}

// TODO: implement
int kovri_get_ri_by_hash(lua_State* L) {
  (void) L;
  return 0;
}
