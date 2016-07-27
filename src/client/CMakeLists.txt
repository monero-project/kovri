set(CLIENT_SRC
  "Datagram.cpp"
  "I2PControl/I2PControl.cpp"
  "I2PControl/I2PControlServer.cpp"
  "I2PTunnel/HTTPProxy.cpp"
  "I2PTunnel/I2PTunnel.cpp"
  "I2PTunnel/SOCKS.cpp"
  "Streaming.cpp"
  "AddressBook.cpp"
  "Destination.cpp"
  "ClientContext.cpp"
  "I2PService.cpp")

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
