#include "Funcs.h"

#include <signal.h>

#include <boost/asio.hpp>

#include <future>
#include <iostream>
#include <string>

#include "NetworkDatabase.h"
#include "RouterContext.h"
#include "transport/Transports.h"
#include "tunnel/Tunnel.h"
#include "util/Log.h"

std::promise<void> complete;

void handle_sigint(int sig) {
  (void)sig;
  try {
    complete.set_value();
  } catch( std::future_error & ex) {
    (void) ex;
  }
}

//
// entry point for luajit i2p router
//
int main(int argc, char * argv[]) {

  if (argc == 2) {
    auto glog = kovri::log::Log::Get();
    // no log spam
    glog->Stop();
    lua_State* l = luaL_newstate();
    luaL_openlibs(l);
    luaL_register(l, "i2lua", funcs);
    int err = luaL_loadfile(l, argv[1]);
    if (err == LUA_ERRSYNTAX) {
      std::cout << "invalid syntax in " << argv[1];
    } else if ( err == LUA_ERRFILE) {
      std::cout << "failed to open " << argv[1];
    } else if ( err == LUA_ERRMEM) {
      std::cout << "out of memory when processing " << argv[1];
    } else if ( err ) {
      std::cout << "error " << err << " while processing " << argv[1];
    } else {
      signal(SIGINT, handle_sigint);
      err = lua_pcall(l, 0, LUA_MULTRET, 0);
      if ( err ) {
        if ( err == LUA_ERRRUN ) {
          std::cout << "runtime error while executing " << argv[1] << std::endl;
          const char * msg  = lua_tostring(l, lua_gettop(l));
          std::cout << msg << std::endl;
        } else if ( err == LUA_ERRMEM ) {
          std::cout << "out of memory while executing " << argv[1];
        } else if ( err == LUA_ERRERR ) {
          std::cout << "error handler died while executing " << argv[1];
        } else {
          std::cout << "error " << err << " while executing " << argv[1];
        }
        
      }
    }
    std::cout << std::endl;
    try {
      i2p::tunnel::tunnels.Stop();
      i2p::transport::transports.Stop();
      i2p::data::netdb.Stop();
    } catch ( std::exception & ex ) {
      std::cout << "exception while ending router: " << ex.what() << std::endl;
    }
    lua_close(l);
    return err;
  } else {
    std::cout << "usage: " << argv[0] << " runtime.lua" << std::endl;
    return 1;
  }
}

int kovri_init(lua_State* L) {
  int n = lua_gettop(L); // num of args
  if (n != 1) {
    lua_pushliteral(L, "invalid number of arguments, expected 1");
    return lua_error(L);
  } else {
    std::string host("0.0.0.0");
    int port = 0;
    bool v6 = false;
    bool floodfill = false;
    if (!lua_isnumber(L, 1)) {
      return luaL_argerror(L, 1, "not an integer");
    } else {
      lua_Integer l_port = lua_tointeger(L, 1);
      port = (int)l_port;
      if ( port > 0 ) {
        char * err_msg = nullptr;
        try {
          i2p::context.Init("router.keys", "router.info");
          i2p::context.UpdatePort(port);
          i2p::context.UpdateAddress(boost::asio::ip::address::from_string(host));
          i2p::context.SetSupportsV6(v6);
          i2p::context.SetFloodfill(floodfill);
          i2p::context.SetHighBandwidth();
        } catch (std::exception & ex) {
          err_msg = (char*) ex.what();
        }
        if (err_msg) {
          return luaL_error(L, "error initializing: %s", err_msg);
        }
      } else {
        return luaL_argerror(L, 1, "port <= 0");
      }
    }
  }
  lua_pushnil(L);
  return 1;
}
  
int kovri_start(lua_State* L) {
  char * err = nullptr;
  try {
    if( i2p::data::netdb.Start() ) {
      i2p::transport::transports.Start();
      i2p::tunnel::tunnels.Start();
    } else {
      return luaL_error(L, "failed to initialize netdb");
    }
  } catch( std::runtime_error & ex ) {
    err = (char*) ex.what();
  }
  if (err) {
    return luaL_error(L, "error while initializing: %s", err);
  }
  lua_pushnil(L);
  return 1;
}

//TODO: implement
int kovri_set_tunnel_build_strategy(lua_State* L) {
  (void) L;
  return 0;
}


int kovri_get_ri_random(lua_State* L) {
  auto ptr = i2p::data::netdb.GetRandomRouter();
  if (ptr) {
    const void * vptr = ptr.get();
    lua_pushlightuserdata(L, (void*)vptr);
  } else {
    lua_pushnil(L);
  }
  return 1;
}

// TODO: implement
int kovri_get_ri_by_hash(lua_State* L) {
  (void) L;
  return 0;
}

int kovri_stop(lua_State* L) {
  char * msg = nullptr;
  try {
    complete.set_value();
  } catch ( std::future_error & err) {
    msg = (char*) err.what();
  }
  if (msg) {
    return luaL_error(L, "error stopping: %s", msg);
  }
  lua_pushnil(L);
  return 1;
}

int kovri_wait(lua_State* L) {
  complete.get_future().wait();
  lua_pushnil(L);
  return 1;
}
