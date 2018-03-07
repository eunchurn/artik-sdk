cmake_minimum_required (VERSION 2.8)

project (media-example)

set (EXE_MEDIA_EXAMPLE media-example)
set (SRC_MEDIA_EXAMPLE artik_media_example.c)

add_executable (${EXE_MEDIA_EXAMPLE} ${SRC_MEDIA_EXAMPLE})

target_include_directories ( ${EXE_MEDIA_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_MEDIA_INCLUDE_DIR})

target_link_libraries (${EXE_MEDIA_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_MEDIA_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
