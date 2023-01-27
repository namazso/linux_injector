cmake_minimum_required(VERSION 3.17)
project(linux_injector)

set(CMAKE_CXX_STANDARD 11)

add_executable(linux_injector main.cpp)

target_compile_options("${PROJECT_NAME}" PRIVATE -fno-exceptions -fno-rtti)
