cmake_minimum_required(VERSION 3.20)
project(linux_injector)

set(CMAKE_CXX_STANDARD 17)

add_executable(linux_injector main.cpp)

target_link_libraries("${PROJECT_NAME}" dl)
