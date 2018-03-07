cmake_minimum_required (VERSION 2.8)

project (network-example)

set (EXE_NETWORK_EXAMPLE network-example)
set (SRC_NETWORK_EXAMPLE artik_network_example.c)

add_executable (${EXE_NETWORK_EXAMPLE} ${SRC_NETWORK_EXAMPLE})

target_include_directories ( ${EXE_NETWORK_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_CONNECTIVITY_INCLUDE_DIR})

target_link_libraries (${EXE_NETWORK_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_NETWORK_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
