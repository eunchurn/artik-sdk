cmake_minimum_required (VERSION 2.8)

project (security-example)

set (EXE_SECURITY_EXAMPLE security-example)
set (SRC_SECURITY_EXAMPLE artik_security_example.c)

add_executable (${EXE_SECURITY_EXAMPLE} ${SRC_SECURITY_EXAMPLE})

target_include_directories ( ${EXE_SECURITY_EXAMPLE}
							PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
)

target_link_libraries (${EXE_SECURITY_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_SECURITY_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
