set(TARGET_NAME pfdtool)
file(GLOB SOURCES src/*.c)

if(WIN32)
    list(APPEND SOURCES getopt/getopt.c)
endif()

add_executable(${TARGET_NAME} ${SOURCES})
target_link_libraries(${TARGET_NAME} PRIVATE libpfdtool)
target_link_libraries(${TARGET_NAME} PRIVATE libpfdtool)

if(WIN32)
    target_include_directories(${TARGET_NAME} PRIVATE getopt)
    target_compile_definitions(${TARGET_NAME} PRIVATE STATIC_GETOPT)
endif()

if(MSVC)
    target_compile_definitions(${TARGET_NAME} PRIVATE _CRT_NONSTDC_NO_WARNINGS _CRT_SECURE_NO_WARNINGS)
endif()

configure_file(bin/games.conf ${CMAKE_BINARY_DIR}/bin/games.conf COPYONLY)
configure_file(bin/global.conf ${CMAKE_BINARY_DIR}/bin/global.conf COPYONLY)
