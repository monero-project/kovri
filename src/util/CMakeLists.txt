include_directories("../")

set(UTIL_SRC
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
