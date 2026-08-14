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

set(IDAXEX_FIRST_PARTY_SOURCES
  idaloader.cpp
  idaloader_xbe.cpp
  namegen.cpp
  namegen_xtlid.cpp
  formats/xbe.cpp
  formats/xex.cpp
)

set(IDAXEX_THIRD_PARTY_SOURCES
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
)

ida_add_loader(idaxex
  SOURCES
    ${IDAXEX_FIRST_PARTY_SOURCES}
    ${IDAXEX_THIRD_PARTY_SOURCES}
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
  # ida_add_loader() suppresses warnings for the complete mixed-source target.
  # Remove that target-wide switch, then enable strict checks only for code
  # maintained in this repository. Vendored sources keep their own warning
  # policy and cannot obscure new first-party warnings.
  get_target_property(_idaxex_compile_options idaxex COMPILE_OPTIONS)
  if(_idaxex_compile_options)
    list(FILTER _idaxex_compile_options EXCLUDE REGEX "^(/w|/W0|-w)$")
    set_property(TARGET idaxex PROPERTY COMPILE_OPTIONS
      "${_idaxex_compile_options}")
  endif()

  set_property(SOURCE ${IDAXEX_FIRST_PARTY_SOURCES} APPEND PROPERTY
    COMPILE_OPTIONS
      $<$<CXX_COMPILER_ID:MSVC>:/W4>
      $<$<CXX_COMPILER_ID:MSVC>:/wd4201>
      $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall>
      $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wextra>
  )
  set_property(SOURCE ${IDAXEX_THIRD_PARTY_SOURCES} APPEND PROPERTY
    COMPILE_OPTIONS
      $<$<CXX_COMPILER_ID:MSVC>:/W0>
      $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-w>
  )
  unset(_idaxex_compile_options)
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
