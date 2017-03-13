include_directories("../")

set(UTIL_SRC
  "su3file.cc"
  "routerinfo.cc"
  "base.cc"
  "main.cc")

if(WITH_BINARY)
  add_executable(${UTIL_NAME} ${UTIL_SRC})
  target_link_libraries(
    ${UTIL_NAME}
    ${CLIENT_NAME} ${CORE_NAME}
    ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  set_target_properties(${UTIL_NAME} PROPERTIES OUTPUT_NAME "${UTIL_NAME}")
  if(WITH_STATIC)
    if(NOT MINGW)
      set_target_properties(${UTIL_NAME} PROPERTIES LINK_FLAGS "-static-libgcc -static-libstdc++")
    endif()
    if(CLANG AND NOT (ARM OR ANDROID) )
      set_target_properties(${UTIL_NAME} PROPERTIES LINK_FLAGS "-lstdc++")
      if(FREEBSD)
        set_target_properties(${UTIL_NAME} PROPERTIES LINK_FLAGS "-lm -lc++")
      endif()
    endif()
    # Note: On FreeBSD 10.3-RELEASE-p4 and 11, GCC 4.9.4+/Clang 3.6+ apparently started to *silently* drop -static-libgcc -static-libstdc++ during linkage so, we add -static here
    if(FREEBSD OR MINGW)
      set_target_properties(${UTIL_NAME} PROPERTIES LINK_FLAGS "-static")
    endif()
  endif()
  if(MINGW)
    target_link_libraries(${UTIL_NAME} wsock32 iphlpapi ws2_32)
  endif()
  # FindBoost pulls pthread for thread which is broken for static linking
  # (at least on Ubuntu 15.04)
  list(GET Boost_LIBRARIES -1 LAST_Boost_LIBRARIES)
  if(${LAST_Boost_LIBRARIES} MATCHES ".*pthread.*")
    list(REMOVE_AT Boost_LIBRARIES -1)
  endif()

  install(TARGETS ${UTIL_NAME} DESTINATION bin)

endif()

# vim: noai:ts=2:sw=2
