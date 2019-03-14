cmake_minimum_required(VERSION 3.5.1)
project (shareipc)

# shared library var
set(LIB_SHARED ${CMAKE_PROJECT_NAME})

# static library var
set(LIB_STATIC ${CMAKE_PROJECT_NAME}_static)

# select library to use for tests
set(USE_STATIC YES)

# set the output dir for tests
set (BIN_DIR ${CMAKE_SOURCE_DIR}/bin)

# install lib dir
set (OUT_LIB_DIR /usr/lib)

# install include dir
set (OUT_INC_DIR /usr/include)

# src include directory
set(SRC_INC_DIR includes)

# add include dirs for compile
include_directories(includes)

# default compile options
add_compile_options(-Wall -O2)

# build the library
add_subdirectory(src)

# build the tests
add_subdirectory(tests)
