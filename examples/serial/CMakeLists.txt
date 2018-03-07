cmake_minimum_required (VERSION 2.8)

project (serial-example)

set (EXE_SERIAL_EXAMPLE serial-example)
set (SRC_SERIAL_EXAMPLE artik_serial_example.c)

add_executable (${EXE_SERIAL_EXAMPLE} ${SRC_SERIAL_EXAMPLE})

target_include_directories ( ${EXE_SERIAL_EXAMPLE}
							PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							PUBLIC ${ARTIK_SYSTEMIO_INCLUDE_DIR}
)

target_link_libraries (${EXE_SERIAL_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_SERIAL_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
