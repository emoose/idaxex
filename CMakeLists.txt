cmake_minimum_required(VERSION 3.27 FATAL_ERROR)

project(idaxex)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

if(DEFINED ENV{IDASDK})
  file(TO_CMAKE_PATH "$ENV{IDASDK}" _IDASDK_ROOT)
  set(_IDASDK_BOOTSTRAP "")
  if(EXISTS "${_IDASDK_ROOT}/src/cmake/bootstrap.cmake")
    set(_IDASDK_BOOTSTRAP "${_IDASDK_ROOT}/src/cmake/bootstrap.cmake")
  elseif(EXISTS "${_IDASDK_ROOT}/ida-cmake/bootstrap.cmake")
    set(_IDASDK_BOOTSTRAP "${_IDASDK_ROOT}/ida-cmake/bootstrap.cmake")
  endif()

  if(NOT _IDASDK_BOOTSTRAP)
    message(FATAL_ERROR "Could not find ida-cmake bootstrap under $ENV{IDASDK}")
  endif()

  include("${_IDASDK_BOOTSTRAP}")
  find_package(idasdk REQUIRED)

  foreach(_IDAXEX_QT_HELPER_TARGET IN ITEMS
      build_qt
      qt6_external
      qt6_external-download
      qt6_external-configure
      qt6_external-build
      qt6_external-install
    )
    if(TARGET ${_IDAXEX_QT_HELPER_TARGET})
      set_target_properties(${_IDAXEX_QT_HELPER_TARGET} PROPERTIES
        EXCLUDE_FROM_ALL TRUE
        EXCLUDE_FROM_DEFAULT_BUILD TRUE
        EXCLUDE_FROM_DEFAULT_BUILD_DEBUG TRUE
        EXCLUDE_FROM_DEFAULT_BUILD_RELEASE TRUE
        EXCLUDE_FROM_DEFAULT_BUILD_RELWITHDEBINFO TRUE
        EXCLUDE_FROM_DEFAULT_BUILD_MINSIZEREL TRUE
      )
    endif()
  endforeach()
else()
  message(FATAL_ERROR "Set IDASDK to an IDA SDK root before configuring idaxex")
endif()

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
    ${_IDASDK_ROOT}/src/ldr/pe
    ${_IDASDK_ROOT}/ldr/pe
  DEFINES
    IDALDR=1
)

target_compile_options(idaxex PRIVATE
  $<$<AND:$<NOT:$<C_COMPILER_ID:MSVC>>,$<COMPILE_LANGUAGE:C>>:-maes>
  $<$<AND:$<NOT:$<CXX_COMPILER_ID:MSVC>>,$<COMPILE_LANGUAGE:CXX>>:-maes>
  $<$<CXX_COMPILER_ID:Clang>:-Wno-non-pod-varargs>
  $<$<CXX_COMPILER_ID:AppleClang>:-Wno-non-pod-varargs>
)

ida_disable_warnings(idaxex)
