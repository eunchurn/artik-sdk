cmake_minimum_required (VERSION 2.8)

project (sensor-example)

set (EXE_SENSOR_EXAMPLE sensor-example)
set (SRC_SENSOR_EXAMPLE artik_sensor_example.c)

add_executable (${EXE_SENSOR_EXAMPLE} ${SRC_SENSOR_EXAMPLE})

target_include_directories ( ${EXE_SENSOR_EXAMPLE}
							PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							PUBLIC ${ARTIK_SENSOR_INCLUDE_DIR}
							PUBLIC ${ARTIK_SYSTEMIO_INCLUDE_DIR}
)

target_link_libraries (${EXE_SENSOR_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_SENSOR_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
