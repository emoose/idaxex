cmake_minimum_required(VERSION 3.27 FATAL_ERROR)

project(idaxex)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

# Enable AES NI intrinsic
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")

include($ENV{IDASDK}/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

ida_add_loader(idaxex SOURCES
  idaloader.cpp
  idaloader_xbe.cpp
  namegen.cpp
  namegen_xtlid.cpp
  formats/xbe.cpp
  formats/xex.cpp
  3rdparty/excrypt/src/excrypt_aes.c
  3rdparty/excrypt/src/rijndael.c
  3rdparty/excrypt/src/excrypt_sha.c
  3rdparty/lzx.cpp
  3rdparty/mspack/lzxd.c
  3rdparty/mspack/system.c
  3rdparty/XbSymbolDatabase/src/lib/libXbSymbolDatabase.c
  3rdparty/XbSymbolDatabase/src/OOVPADatabase/D3D8_OOVPA.c
  3rdparty/XbSymbolDatabase/src/OOVPADatabase/D3D8LTCG_OOVPA.c
  3rdparty/XbSymbolDatabase/src/OOVPADatabase/DSound_OOVPA.c
  3rdparty/XbSymbolDatabase/src/OOVPADatabase/JVS_OOVPA.c
  3rdparty/XbSymbolDatabase/src/OOVPADatabase/XActEng_OOVPA.c
  3rdparty/XbSymbolDatabase/src/OOVPADatabase/Xapi_OOVPA.c
  3rdparty/XbSymbolDatabase/src/OOVPADatabase/XGraphic_OOVPA.c
  3rdparty/XbSymbolDatabase/src/OOVPADatabase/XNet_OOVPA.c
  3rdparty/XbSymbolDatabase/src/OOVPADatabase/XOnline_OOVPA.c)

target_include_directories(idaxex PUBLIC
  3rdparty/excrypt/src 
  3rdparty/XbSymbolDatabase/include 
  3rdparty/XbSymbolDatabase/src/OOVPADatabase 
  $ENV{IDASDK}/ldr/pe)
target_compile_definitions(idaxex PUBLIC IDALDR=1)

if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  target_compile_definitions(idaxex PUBLIC XE_PLATFORM_MAC=1)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_compile_options(idaxex PUBLIC -Wno-non-pod-varargs)
endif()