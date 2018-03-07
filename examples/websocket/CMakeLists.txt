cmake_minimum_required (VERSION 2.8)

project (websocket-example)

set (EXE_WEBSOCKET_EXAMPLE websocket-example)
set (SRC_WEBSOCKET_EXAMPLE artik_websocket_example.c)

add_executable (${EXE_WEBSOCKET_EXAMPLE} ${SRC_WEBSOCKET_EXAMPLE})

target_include_directories ( ${EXE_WEBSOCKET_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_CONNECTIVITY_INCLUDE_DIR}
)

target_link_libraries (${EXE_WEBSOCKET_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_WEBSOCKET_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
