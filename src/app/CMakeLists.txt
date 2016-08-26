set(APP_SRC
  "main.cc"
  "daemon.cc"
  "util/config.cc"
  "util/filesystem.cc")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND APP_SRC "daemon_linux.cc")
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  list(APPEND APP_SRC "daemon_linux.cc")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  list(APPEND APP_SRC "daemon_linux.cc")
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  list(APPEND APP_SRC "daemon_linux.cc")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND APP_SRC "daemon_win32.cc")
  list(APPEND APP_SRC "Win32Service.cc")
endif()

include_directories(
  "."
  "../"
  "../core/"
  "../client/")

if(WITH_BINARY)
  add_executable(${APP_NAME} ${APP_SRC})
  target_link_libraries(
    ${APP_NAME}
    ${CLIENT_NAME} ${CORE_NAME}
    ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  if(NOT MSVC) # FIXME: incremental linker file name (.ilk) collision for dll & exe
    set_target_properties(
      ${APP_NAME} PROPERTIES OUTPUT_NAME "${PROJECT_NAME}")
    if(WITH_STATIC)
      set_target_properties(${APP_NAME} PROPERTIES LINK_FLAGS "-static" )
    endif()
  endif()
  if(WITH_HARDENING AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_target_properties(${APP_NAME} PROPERTIES LINK_FLAGS "-z relro -z now")
  endif()
  # FindBoost pulls pthread for thread which is broken for static linking
  # (at least on Ubuntu 15.04)
  list(GET Boost_LIBRARIES -1 LAST_Boost_LIBRARIES)
  if(${LAST_Boost_LIBRARIES} MATCHES ".*pthread.*")
    list(REMOVE_AT Boost_LIBRARIES -1)
  endif()
  if(MSVC)
    install(FILES
      $<TARGET_PDB_FILE:${APP_NAME}> DESTINATION "bin" CONFIGURATIONS DEBUG)
  endif()
endif()

# vim: noai:ts=2:sw=2
