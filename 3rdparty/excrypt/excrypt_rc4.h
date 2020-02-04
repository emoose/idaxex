#pragma once

typedef struct _EXCRYPT_RC4_STATE
{
  uint8_t S[256];
  uint8_t i;
  uint8_t j;
} EXCRYPT_RC4_STATE;
static_assert(sizeof(EXCRYPT_RC4_STATE) == 0x102, "sizeof(EXCRYPT_RC4_STATE) != 0x160");

void ExCryptRc4Key(EXCRYPT_RC4_STATE* state, const uint8_t* key, uint32_t key_size);
void ExCryptRc4Ecb(EXCRYPT_RC4_STATE* state, uint8_t* buf, uint32_t buf_size);
void ExCryptRc4(const uint8_t* key, uint32_t key_size, uint8_t* buf, uint32_t buf_size);
