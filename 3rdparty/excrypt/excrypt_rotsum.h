#pragma once
// RotSum functions
// these aren't exported by kernel, but do get used by some bootloaders, & inside XeCrypt internally

typedef struct _EXCRYPT_ROTSUM_STATE
{
  uint64_t data[4];
} EXCRYPT_ROTSUM_STATE;
static_assert(sizeof(EXCRYPT_ROTSUM_STATE) == 0x20, "sizeof(EXCRYPT_ROTSUM_STATE) != 0x20");

typedef struct _EXCRYPT_ROTSUM4_STATE
{
  uint64_t data[2];
} EXCRYPT_ROTSUM4_STATE;
static_assert(sizeof(EXCRYPT_ROTSUM4_STATE) == 0x10, "sizeof(EXCRYPT_ROTSUM4_STATE) != 0x10");

void ExCryptRotSum(EXCRYPT_ROTSUM_STATE* result, const uint64_t* input, uint32_t input_qwords);
void ExCryptRotSum4(EXCRYPT_ROTSUM4_STATE* result, uint32_t* input, uint32_t input_dwords);
