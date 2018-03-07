cmake_minimum_required (VERSION 2.8)

project (time-example)

set (EXE_TIME_EXAMPLE time-example)
set (SRC_TIME_EXAMPLE artik_time_example.c)

add_executable (${EXE_TIME_EXAMPLE} ${SRC_TIME_EXAMPLE})

target_include_directories ( ${EXE_TIME_EXAMPLE}
                            PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
)

target_link_libraries (${EXE_TIME_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_TIME_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
