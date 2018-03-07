cmake_minimum_required (VERSION 2.8)

project (spi-example)

set (EXE_SPI_EXAMPLE spi-example)
set (SRC_SPI_EXAMPLE artik_spi_example.c)

add_executable (${EXE_SPI_EXAMPLE} ${SRC_SPI_EXAMPLE})

target_include_directories ( ${EXE_SPI_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_SYSTEMIO_INCLUDE_DIR}
)

target_link_libraries (${EXE_SPI_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_SPI_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")
