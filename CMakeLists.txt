cmake_minimum_required(VERSION 3.27 FATAL_ERROR)

project(idaxex)

set(CMAKE_CXX_STANDARD 17)

include($ENV{IDASDK}/ida-cmake/common.cmake)

set(LOADER_NAME    idaxex)
set(LOADER_SOURCES idaloader.cpp idaloader_xbe.cpp xbe.cpp xex.cpp lzx.cpp namegen.cpp namegen_xtlid.cpp 3rdparty/aes.c 3rdparty/excrypt/src/excrypt_sha.c 3rdparty/mspack/lzxd.c 3rdparty/mspack/system.c)
set(LOADER_INCLUDE_DIRECTORIES 3rdparty/excrypt/src $ENV{IDASDK}/ldr/pe)
add_compile_definitions(IDALDR=1)

generate()
disable_ida_warnings(idaxex)
