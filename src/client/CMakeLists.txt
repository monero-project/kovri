cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(kovri-client CXX)

add_library(kovri-client
  instance.cc
  address_book/impl.cc
  address_book/storage.cc
  api/datagram.cc
  api/i2p_control/data.cc
  api/i2p_control/server.cc
  api/i2p_control/session.cc
  api/streaming.cc
  context.cc
  destination.cc
  proxy/http.cc
  proxy/socks.cc
  reseed.cc
  service.cc
  tunnel.cc
  util/config.cc
  util/http.cc
  util/json.cc
  util/parse.cc
  util/zip.cc
  address_book/impl.h
  address_book/storage.h
  api/datagram.h
  api/i2p_control/data.h
  api/i2p_control/server.h
  api/i2p_control/session.h
  api/streaming.h
  context.h
  destination.h
  instance.h
  proxy/http.h
  proxy/socks.h
  reseed.h
  service.h
  tunnel.h
  util/config.h
  util/http.h
  util/json.h
  util/parse.h
  util/zip.h)

target_include_directories(kovri-client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(kovri-client PRIVATE 
  kovri-core
  kovri-private
  cppnetlib::uri
  PUBLIC
  cppnetlib::client-connections)

if (MSVC)
  cotire(kovri-client)
endif()

install(
  TARGETS kovri-client
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_BINDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR})

# vim: noai:ts=2:sw=2
