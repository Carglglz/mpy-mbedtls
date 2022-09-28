add_library(usermod_mbedtls INTERFACE)

target_sources(usermod_mbedtls INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/mod_mbedtls.c
)

target_include_directories(usermod_mbedtls INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(usermod INTERFACE usermod_mbedtls)
