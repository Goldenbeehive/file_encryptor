cmake_minimum_required(VERSION 3.10)
project(CryptoFileEncryptor)

set(CMAKE_CXX_STANDARD 17)

if(CMAKE_COMPILER_IS_GNUCXX)
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

file(GLOB_RECURSE SOURCES
    src/*.cpp
)

add_executable(file_encryptor ${SOURCES})

enable_testing()
add_subdirectory(tests)