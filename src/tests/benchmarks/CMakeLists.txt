set(BENCHMARKS_SRC
  "Crypto.cpp"
)

include_directories("../../core/")

if(WITH_BENCHMARKS)
    add_executable(${BENCHMARKS_NAME} ${BENCHMARKS_SRC})
    target_link_libraries(
	${BENCHMARKS_NAME} ${CORE_NAME} ${DL_LIB} ${Boost_LIBRARIES} ${CRYPTO++_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
    )
    install(TARGETS
	${BENCHMARKS_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()
