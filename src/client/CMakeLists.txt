set(CLIENT_SRC
  "address_book.cc"
  "address_book_storage.cc"
  "client_context.cc"
  "datagram.cc"
  "destination.cc"
  "i2p_control/i2p_control.cc"
  "i2p_control/i2p_control_server.cc"
  "i2p_service.cc"
  "i2p_tunnel/http_proxy.cc"
  "i2p_tunnel/i2p_tunnel.cc"
  "i2p_tunnel/socks.cc"
  "reseed.cc"
  "streaming.cc"
  "util/http.cc"
  "util/zip.cc")

include_directories(
  "."
  "../"
  "../core/")

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
