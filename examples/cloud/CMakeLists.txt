cmake_minimum_required (VERSION 2.8)

project (cloud-example)

set (EXE_CLOUD_EXAMPLE cloud-example)
set (SRC_CLOUD_EXAMPLE artik_cloud_example.c)

add_executable (${EXE_CLOUD_EXAMPLE} ${SRC_CLOUD_EXAMPLE})

target_include_directories ( ${EXE_CLOUD_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_CONNECTIVITY_INCLUDE_DIR}
)

target_link_libraries (${EXE_CLOUD_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_CLOUD_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")