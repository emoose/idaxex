cmake_minimum_required(VERSION 3.25)

# xex1tool is a standalone command-line tool and does NOT use the IDA SDK. It
# can be built on its own (cmake -S xex1tool -B xex1tool/build) or as part of
# the loader build via add_subdirectory() from the repo-root CMakeLists.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(xex1tool CXX C)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
option(IDAXEX_STRICT_WARNINGS
  "Enable strict compiler warnings for compatibility validation" OFF)

set(XEX1TOOL_FIRST_PARTY_SOURCES
  ../xex1tool.cpp
  ../namegen.cpp
  ../formats/xdbf.cpp
  ../formats/xex.cpp
)

set(XEX1TOOL_THIRD_PARTY_SOURCES
  ../3rdparty/excrypt/src/excrypt_aes.c
  ../3rdparty/excrypt/src/rijndael.c
  ../3rdparty/excrypt/src/excrypt_bn.c
  ../3rdparty/excrypt/src/excrypt_bn_mod.cpp
  ../3rdparty/excrypt/src/excrypt_bn_sig.c
  ../3rdparty/excrypt/src/excrypt_mem.cpp
  ../3rdparty/excrypt/src/excrypt_rc4.c
  ../3rdparty/excrypt/src/excrypt_rotsum.c
  ../3rdparty/excrypt/src/excrypt_sha.c
  ../3rdparty/lzx.cpp
  ../3rdparty/mspack/lzxd.c
  ../3rdparty/mspack/system.c
)

add_executable(xex1tool
  ${XEX1TOOL_FIRST_PARTY_SOURCES}
  ${XEX1TOOL_THIRD_PARTY_SOURCES}
)

target_include_directories(xex1tool PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../3rdparty/excrypt/src")

# excrypt's AES path uses x86 AES-NI intrinsics (wmmintrin.h); enable them on
# x86/x64 only. MSVC exposes the intrinsics without an explicit switch.
set(_xex1tool_x86 FALSE)
if(CMAKE_OSX_ARCHITECTURES)
  if(CMAKE_OSX_ARCHITECTURES MATCHES "x86_64|i386")
    set(_xex1tool_x86 TRUE)
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|i[3-6]86|x86")
  set(_xex1tool_x86 TRUE)
endif()
if(_xex1tool_x86 AND NOT MSVC)
  target_compile_options(xex1tool PRIVATE -maes)
endif()

# formats/xex.cpp passes byte-swapped be<> wrappers (trivially copyable) through
# printf-style varargs; clang flags this as an error by default. The loader
# target suppresses the same warning.
target_compile_options(xex1tool PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang>:-Wno-non-pod-varargs>)

if(IDAXEX_STRICT_WARNINGS)
  set_property(SOURCE ${XEX1TOOL_FIRST_PARTY_SOURCES} APPEND PROPERTY
    COMPILE_OPTIONS
      $<$<CXX_COMPILER_ID:MSVC>:/W4>
      $<$<CXX_COMPILER_ID:MSVC>:/wd4201>
      $<$<CXX_COMPILER_ID:MSVC>:/wd4127>
      $<$<CXX_COMPILER_ID:MSVC>:/wd4702>
      $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall>
      $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wextra>
  )
  set_property(SOURCE ${XEX1TOOL_THIRD_PARTY_SOURCES} APPEND PROPERTY
    COMPILE_OPTIONS
      $<$<CXX_COMPILER_ID:MSVC>:/W0>
      $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-w>
  )
endif()
