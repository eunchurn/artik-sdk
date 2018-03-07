cmake_minimum_required (VERSION 2.8)

project (wifi-example)

set (EXE_WIFI_EXAMPLE wifi-example)
set (SRC_WIFI_EXAMPLE artik_wifi_example.c)

add_executable (${EXE_WIFI_EXAMPLE} ${SRC_WIFI_EXAMPLE})

target_include_directories ( ${EXE_WIFI_EXAMPLE}
							PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							PUBLIC ${ARTIK_WIFI_INCLUDE_DIR}
)

target_link_libraries (${EXE_WIFI_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_WIFI_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
