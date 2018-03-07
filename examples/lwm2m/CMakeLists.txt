cmake_minimum_required (VERSION 2.8)

project (lwm2m-example)

set (EXE_LWM2M_EXAMPLE lwm2m-example)
set (SRC_LWM2M_EXAMPLE artik_lwm2m_example.c)

add_executable (${EXE_LWM2M_EXAMPLE} ${SRC_LWM2M_EXAMPLE})

target_include_directories ( ${EXE_LWM2M_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_LWM2M_INCLUDE_DIR}
							 PUBLIC ${ARTIK_CONNECTIVITY_INCLUDE_DIR})

target_link_libraries (${EXE_LWM2M_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_LWM2M_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
