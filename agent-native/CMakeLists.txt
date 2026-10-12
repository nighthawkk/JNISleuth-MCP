cmake_minimum_required(VERSION 3.22)
project(jnisleuth_agent LANGUAGES C CXX ASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(jnisleuth_agent SHARED
    src/elf_utils.cpp
    src/jni_hook.cpp
)

find_library(LOG_LIB log)
if(LOG_LIB)
    target_link_libraries(jnisleuth_agent PRIVATE ${LOG_LIB} dl pthread)
else()
    target_link_libraries(jnisleuth_agent PRIVATE dl pthread)
endif()

if(DEFINED DOBBY_LIBRARY_PATH)
    target_compile_definitions(jnisleuth_agent PRIVATE JNISLEUTH_HAS_EXTERNAL_DOBBY=1)
    target_link_libraries(jnisleuth_agent PRIVATE ${DOBBY_LIBRARY_PATH})
endif()
