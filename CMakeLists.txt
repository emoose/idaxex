cmake_minimum_required(VERSION 3.25 FATAL_ERROR)

# ---------------------------------------------------------------------------
# IDA SDK
#
# The loader builds against the official IDA SDK
# (https://github.com/HexRaysSA/ida-sdk), vendored as the 3rdparty/ida-sdk
# submodule. That repository ships its own CMake package
# (find_package(idasdk)) together with the link stub libraries, so no separate
# SDK download or IDASDK environment variable is needed -- just make sure the
# submodules are checked out (git submodule update --init --recursive).
# ---------------------------------------------------------------------------
set(IDAXEX_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/ida-sdk")

if(NOT EXISTS "${IDAXEX_SDK_ROOT}/src/include/pro.h")
  message(FATAL_ERROR
    "IDA SDK submodule not found at ${IDAXEX_SDK_ROOT}. "
    "Run: git submodule update --init --recursive")
endif()

# idasdk_init.cmake resolves the SDK, makes find_package(idasdk) reachable, and
# pre-selects MSVC on Windows. It must be included before project().
set(ENV{IDASDK} "${IDAXEX_SDK_ROOT}/src")
include("${IDAXEX_SDK_ROOT}/src/cmake/idasdk_init.cmake")

project(idaxex CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)
option(IDAXEX_STRICT_WARNINGS
  "Enable strict compiler warnings for compatibility validation" OFF)

# `cmake --build` writes the loader into the build tree (build/bin/loaders/).
# `cmake --install` (below) is what copies it into IDA's directory. This must
# be set before find_package(), which bakes the output location into
# ida_add_loader().
if(NOT DEFINED IDABIN AND NOT DEFINED ENV{IDABIN})
  set(IDABIN "${CMAKE_BINARY_DIR}/bin")
endif()

find_package(idasdk REQUIRED)

ida_add_loader(idaxex
  SOURCES
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
    3rdparty/XbSymbolDatabase/src/OOVPADatabase/XOnline_OOVPA.c
  INCLUDES
    3rdparty/excrypt/src
    3rdparty/XbSymbolDatabase/include
    3rdparty/XbSymbolDatabase/src/OOVPADatabase
  DEFINES
    IDALDR=1
)

# excrypt's AES path uses x86 AES-NI intrinsics (wmmintrin.h); enable them on
# x86/x64 only. MSVC exposes the intrinsics without an explicit switch.
if((IDA_X64 OR IDA_X86) AND NOT MSVC)
  target_compile_options(idaxex PRIVATE $<$<COMPILE_LANGUAGE:C,CXX>:-maes>)
endif()
target_compile_options(idaxex PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-non-pod-varargs>)

if(IDAXEX_STRICT_WARNINGS)
  target_compile_options(idaxex PRIVATE
    $<$<COMPILE_LANG_AND_ID:C,MSVC>:/W4>
    $<$<COMPILE_LANG_AND_ID:C,MSVC>:/wd4201>
    $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/W4>
    $<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/wd4201>
    $<$<COMPILE_LANG_AND_ID:C,GNU,Clang,AppleClang>:-Wall>
    $<$<COMPILE_LANG_AND_ID:C,GNU,Clang,AppleClang>:-Wextra>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Wall>
    $<$<COMPILE_LANG_AND_ID:CXX,GNU,Clang,AppleClang>:-Wextra>
  )
else()
  ida_disable_warnings(idaxex)
endif()

# `cmake --install build` installs the loader so IDA picks it up automatically.
# Default the install prefix to IDA's per-user directory (loaders/ subdir):
#   ~/.idapro/loaders                     on Linux/macOS
#   %APPDATA%\Hex-Rays\IDA Pro\loaders    on Windows
# Pass -DCMAKE_INSTALL_PREFIX=<dir> to install elsewhere (e.g. an IDA
# installation directory); the loader always lands in <prefix>/loaders.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  if(WIN32)
    set(_idaxex_userdir "$ENV{APPDATA}/Hex-Rays/IDA Pro")
  else()
    set(_idaxex_userdir "$ENV{HOME}/.idapro")
  endif()
  set(CMAKE_INSTALL_PREFIX "${_idaxex_userdir}" CACHE PATH
      "Install location (IDA directory)" FORCE)
endif()

install(FILES "$<TARGET_FILE:idaxex>" DESTINATION "loaders")

# xex1tool: standalone command-line companion (does not use the IDA SDK).
add_subdirectory(xex1tool)
