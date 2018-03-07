cmake_minimum_required (VERSION 2.8)

project (i2c-example)

set (EXE_I2C_EXAMPLE i2c-example)
set (SRC_I2C_EXAMPLE artik_i2c_example.c)

add_executable (${EXE_I2C_EXAMPLE} ${SRC_I2C_EXAMPLE})

target_include_directories ( ${EXE_I2C_EXAMPLE}
							PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							PUBLIC ${ARTIK_SYSTEMIO_INCLUDE_DIR}
							PUBLIC ${ARTIK_SENSOR_INCLUDE_DIR}
)

target_link_libraries (${EXE_I2C_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_I2C_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
