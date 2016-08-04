set(CLIENT_SRC
  "Datagram.cc"
  "I2PControl/I2PControl.cc"
  "I2PControl/I2PControlServer.cc"
  "I2PTunnel/HTTPProxy.cc"
  "I2PTunnel/I2PTunnel.cc"
  "I2PTunnel/SOCKS.cc"
  "Streaming.cc"
  "AddressBook.cc"
  "Destination.cc"
  "ClientContext.cc"
  "I2PService.cc")

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
