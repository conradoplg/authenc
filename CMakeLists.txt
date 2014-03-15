cmake_minimum_required(VERSION 2.8) 
project(AUTHENC C ASM)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -W -std=c99 -Werror")

include_directories("include")

set(BACKEND "ref" CACHE STRING "Backend to use.")

file(GLOB LIB_SRCS "src/*.c")
file(GLOB_RECURSE BACKEND_SRCS "src/${BACKEND}/*.c" "src/${BACKEND}/*.S" "src/${BACKEND}/*.s")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/${BACKEND}/CMakeLists.txt")
	add_subdirectory("src/${BACKEND}/")
endif() 

list(APPEND LIB_SRCS ${BACKEND_SRCS})
add_library(authenc ${LIB_SRCS})

enable_testing()

add_executable(test_bc_aes test/test_bc_aes.c)
target_link_libraries(test_bc_aes authenc)
add_executable(test_sc_aesctr test/test_sc_aesctr.c)
target_link_libraries(test_sc_aesctr authenc)
add_executable(test_ac_gcm test/test_ac_gcm.c)
target_link_libraries(test_ac_gcm authenc)
