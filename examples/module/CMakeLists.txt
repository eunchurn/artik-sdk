cmake_minimum_required (VERSION 2.8)

project (module-example)

set (EXE_MODULE_EXAMPLE module-example)
set (SRC_MODULE_EXAMPLE artik_module_example.c)

add_executable (${EXE_MODULE_EXAMPLE} ${SRC_MODULE_EXAMPLE})

target_include_directories ( ${EXE_MODULE_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR})

target_link_libraries (${EXE_MODULE_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_MODULE_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
