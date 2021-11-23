cmake_minimum_required(VERSION 3.21)
project(Shell)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")

add_definitions(-DUNICODE)

set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--image-base=0x02000000")

add_executable(loader loader.cpp PETools.h PETools.cpp shell.h shell.cpp)
add_executable(packer packer.cpp PETools.h PETools.cpp)
add_executable(unpacker unpacker.cpp PETools.h PETools.cpp shell.h shell.cpp)