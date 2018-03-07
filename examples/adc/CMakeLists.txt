cmake_minimum_required (VERSION 2.8)

project (adc-example)

set (EXE_ADC_EXAMPLE adc-example)
set (SRC_ADC_EXAMPLE artik_adc_example.c)

add_executable (${EXE_ADC_EXAMPLE} ${SRC_ADC_EXAMPLE})

target_include_directories ( ${EXE_ADC_EXAMPLE}
							 PUBLIC ${ARTIK_BASE_INCLUDE_DIR}
							 PUBLIC ${ARTIK_SYSTEMIO_INCLUDE_DIR}
)

target_link_libraries (${EXE_ADC_EXAMPLE} ${ARTIK_BASE_LIBRARIES})

install (TARGETS ${EXE_ADC_EXAMPLE} RUNTIME DESTINATION "${CMAKE_INSTALL_LIBDIR}/artik-sdk/examples")