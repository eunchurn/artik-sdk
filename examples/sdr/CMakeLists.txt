cmake_minimum_required (VERSION 2.8)

project (sdr-example)

set (EXE_SDR_EXAMPLE sdr-example)
set (SRC_SDR_EXAMPLE artik_sdr_example.c)

add_executable (${EXE_SDR_EXAMPLE} ${SRC_SDR_EXAMPLE})

target_include_directories ( ${EXE_SDR_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_CONNECTIVITY_INCLUDE_DIR}
)

target_link_libraries (${EXE_SDR_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_SDR_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
