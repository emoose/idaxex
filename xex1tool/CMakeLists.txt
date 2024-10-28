cmake_minimum_required(VERSION 3.10)

project(xex1tool)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(xex1tool ../xex1tool.cpp ../xex.cpp ../namegen.cpp ../lzx.cpp ../xdbf/xdbf.cc ../3rdparty/excrypt/src/excrypt_aes.c ../3rdparty/excrypt/src/rijndael.c ../3rdparty/excrypt/src/excrypt_bn.c ../3rdparty/excrypt/src/excrypt_bn_mod.cpp ../3rdparty/excrypt/src/excrypt_bn_key.cpp ../3rdparty/excrypt/src/excrypt_bn_sig.c ../3rdparty/excrypt/src/excrypt_mem.cpp ../3rdparty/excrypt/src/excrypt_rc4.c ../3rdparty/excrypt/src/excrypt_rotsum.c ../3rdparty/excrypt/src/excrypt_sha.c ../3rdparty/mspack/lzxd.c ../3rdparty/mspack/system.c)

target_include_directories(xex1tool PRIVATE ${PROJECT_SOURCE_DIR}/../3rdparty/excrypt/src)
