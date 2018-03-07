cmake_minimum_required (VERSION 2.8)

project (loop-example)

set (EXE_LOOP_EXAMPLE loop-example)
set (SRC_LOOP_EXAMPLE artik_loop_example.c)

add_executable (${EXE_LOOP_EXAMPLE} ${SRC_LOOP_EXAMPLE})

target_include_directories ( ${EXE_LOOP_EXAMPLE}
                            PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
)

target_link_libraries (${EXE_LOOP_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_LOOP_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
