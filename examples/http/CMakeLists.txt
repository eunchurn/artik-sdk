cmake_minimum_required (VERSION 2.8)

project (http-example)

set (EXE_HTTP_EXAMPLE http-example)
set (SRC_HTTP_EXAMPLE artik_http_example.c)

add_executable (${EXE_HTTP_EXAMPLE} ${SRC_HTTP_EXAMPLE})

target_include_directories ( ${EXE_HTTP_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_CONNECTIVITY_INCLUDE_DIR}
)

target_link_libraries (${EXE_HTTP_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_HTTP_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
