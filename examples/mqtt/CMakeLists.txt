cmake_minimum_required (VERSION 2.8)

project (mqtt-example)

set (EXE_MQTT_EXAMPLE mqtt-example)
set (SRC_MQTT_EXAMPLE artik_mqtt_example.c)

add_executable (${EXE_MQTT_EXAMPLE} ${SRC_MQTT_EXAMPLE})

target_include_directories ( ${EXE_MQTT_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_MQTT_INCLUDE_DIR}
)

target_link_libraries (${EXE_MQTT_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_MQTT_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
