cmake_minimum_required (VERSION 2.8)

project (pwm-example)

set (EXE_PWM_EXAMPLE pwm-example)
set (SRC_PWM_EXAMPLE artik_pwm_example.c)

add_executable (${EXE_PWM_EXAMPLE} ${SRC_PWM_EXAMPLE})

target_include_directories ( ${EXE_PWM_EXAMPLE}
							PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							PUBLIC ${ARTIK_SYSTEMIO_INCLUDE_DIR}
)

target_link_libraries (${EXE_PWM_EXAMPLE} ${ARTIK_BASE_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} )

install (TARGETS ${EXE_PWM_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
