cmake_minimum_required (VERSION 2.8)

project (gpio-example)

set (EXE_GPIO_EXAMPLE gpio-example)
set (SRC_GPIO_EXAMPLE artik_gpio_example.c)

add_executable (${EXE_GPIO_EXAMPLE} ${SRC_GPIO_EXAMPLE})

target_include_directories ( ${EXE_GPIO_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_SYSTEMIO_INCLUDE_DIR})

target_link_libraries (${EXE_GPIO_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_GPIO_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
