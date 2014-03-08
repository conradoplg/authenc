cmake_minimum_required(VERSION 2.8) 
project(AUTHENC C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -W -std=c99 -Werror")

include_directories("include")

file(GLOB_RECURSE LIB_SRCS "src/*.c")

add_library(authenc ${LIB_SRCS})

enable_testing()

add_executable(test_bc_aes test/test_bc_aes.c)
target_link_libraries(test_bc_aes authenc)
add_executable(test_ac_gcm test/test_ac_gcm.c)
target_link_libraries(test_ac_gcm authenc)
