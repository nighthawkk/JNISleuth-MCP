cmake_minimum_required(VERSION 3.22)
project(core_crypto LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(core-crypto SHARED
    src/main/cpp/native-lib.cpp
)

find_library(LOG_LIB log)
if(LOG_LIB)
    target_link_libraries(core-crypto PRIVATE ${LOG_LIB})
endif()

# Strip symbols in release mode to emulate obfuscated/stripped JNI libraries
set_target_properties(core-crypto PROPERTIES
    LINK_FLAGS_RELEASE "-s -Wl,--gc-sections"
)
