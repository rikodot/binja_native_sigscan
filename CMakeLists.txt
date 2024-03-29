cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

project(sigscan CXX C)

add_library(${PROJECT_NAME} SHARED
    sigscan.cpp)
    
set(HEADLESS 1)
find_path(
    BN_API_PATH
    NAMES binaryninjaapi.h
    HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
    REQUIRED
)
add_subdirectory(${BN_API_PATH} api)

target_link_libraries(${PROJECT_NAME}
    binaryninjaapi)

set_target_properties(${PROJECT_NAME} PROPERTIES
    CXX_STANDARD 17
    CXX_VISIBILITY_PRESET hidden
    CXX_STANDARD_REQUIRED ON
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out/bin)

bn_install_plugin(${PROJECT_NAME})
