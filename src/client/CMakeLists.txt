include_directories("../")

set(CLIENT_SRC
  "address_book/impl.cc"
  "address_book/storage.cc"
  "api/datagram.cc"
  "api/i2p_control/impl.cc"
  "api/i2p_control/server.cc"
  "api/streaming.cc"
  "context.cc"
  "destination.cc"
  "proxy/http.cc"
  "proxy/socks.cc"
  "reseed.cc"
  "service.cc"
  "tunnel.cc"
  "util/http.cc"
  "util/zip.cc")

if(WITH_LIBRARY)
  add_library(${CLIENT_NAME} ${CLIENT_SRC})
  target_link_libraries(
    ${CLIENT_NAME} ${CORE_NAME}
    ${Boost_LIBRARIES} ${CryptoPP_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  install(
    TARGETS ${CLIENT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# vim: noai:ts=2:sw=2
