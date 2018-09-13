cmake_minimum_required (VERSION 2.8)

project (coap-example)

set (EXE_COAP_EXAMPLE coap-example)
set (SRC_COAP_EXAMPLE artik_coap_example.c)

add_executable (${EXE_COAP_EXAMPLE} ${SRC_COAP_EXAMPLE})

target_include_directories ( ${EXE_COAP_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_COAP_INCLUDE_DIR}
)

target_link_libraries (${EXE_COAP_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_COAP_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
