cmake_minimum_required (VERSION 2.8)

project (bluetooth-example)

set (EXE_BLUETOOTH_EXAMPLE bluetooth-example)
set (SRC_BLUETOOTH_EXAMPLE artik_bluetooth_example.c)

add_executable (${EXE_BLUETOOTH_EXAMPLE} ${SRC_BLUETOOTH_EXAMPLE})

target_include_directories ( ${EXE_BLUETOOTH_EXAMPLE}
							PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							PUBLIC ${ARTIK_BLUETOOTH_INCLUDE_DIR}
)

target_link_libraries (${EXE_BLUETOOTH_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_BLUETOOTH_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
