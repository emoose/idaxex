#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>

#define U8V(data) ((uint8_t)(data) & 0xFF)
#define ROTL8(data, bits) (U8V((data) << (bits)) | ((data) >> (8 - (bits))))

#define U16V(data) ((uint16_t)(data) & 0xFFFF)
#define ROTL16(data, bits) (U16V((data) << (bits)) | ((data) >> (16 - (bits))))

#define U32V(data) ((uint32_t)(data) & 0xFFFFFFFF)
#define ROTL32(data, bits) (U32V((data) << (bits)) | ((data) >> (32 - (bits))))

#define ROTL64(data, bits) (((data) << (bits)) | ((data) >> (64 - (bits))))

typedef int BOOL;

#include "excrypt_aes.h"
#include "excrypt_bn.h"
#include "excrypt_des.h"
#include "excrypt_md5.h"
#include "excrypt_mem.h"
#include "excrypt_parve.h"
#include "excrypt_rc4.h"
#include "excrypt_rotsum.h"
#include "excrypt_sha.h"

#ifdef __cplusplus
}
#endif
