set(CLIENT_SRC
  "AddressBook.cpp"
  "Destination.cpp"
  "ClientContext.cpp"
  "Daemon.cpp"
  "I2PService.cpp"
  "util/Config.cpp"
  "util/Filesystem.cpp")

include_directories(
  "."
  "../"
  "../core/")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND CLIENT_SRC "DaemonLinux.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  list(APPEND CLIENT_SRC "DaemonLinux.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  list(APPEND CLIENT_SRC "DaemonLinux.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  list(APPEND CLIENT_SRC "DaemonLinux.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND CLIENT_SRC "DaemonWin32.cpp")
  list(APPEND CLIENT_SRC "Win32Service.cpp")
endif()

if(WITH_LIBRARY)
  add_library(${CLIENT_NAME} ${CLIENT_SRC})
  target_link_libraries(
    ${CLIENT_NAME} ${API_NAME} ${CORE_NAME}
    ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  install(
    TARGETS ${CLIENT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_BINDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# vim: noai:ts=2:sw=2
