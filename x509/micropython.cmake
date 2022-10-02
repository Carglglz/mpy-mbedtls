add_library(usermod_x509 INTERFACE)

target_sources(usermod_x509 INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/mod_x509.c
)

target_include_directories(usermod_x509 INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(usermod INTERFACE usermod_x509)
