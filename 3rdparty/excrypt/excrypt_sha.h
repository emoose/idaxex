#pragma once
// SHA1 hash & HMAC algorithm

typedef struct _EXCRYPT_SHA_STATE
{
  uint32_t count;
  uint32_t state[5];
  uint8_t buffer[64];
} EXCRYPT_SHA_STATE;
static_assert(sizeof(EXCRYPT_SHA_STATE) == 0x58, "sizeof(EXCRYPT_SHA_STATE) != 0x58");

void ExCryptShaInit(EXCRYPT_SHA_STATE* state);
void ExCryptShaUpdate(EXCRYPT_SHA_STATE* state, const uint8_t* input, uint32_t input_size);
void ExCryptShaFinal(EXCRYPT_SHA_STATE* state, uint8_t* output, uint32_t output_size);
void ExCryptSha(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size);

void ExCryptRotSumSha(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  uint8_t* output, uint32_t output_size);

typedef struct _EXCRYPT_HMACSHA_STATE
{
  EXCRYPT_SHA_STATE ShaState[2];
} EXCRYPT_HMACSHA_STATE;
static_assert(sizeof(EXCRYPT_HMACSHA_STATE) == 0xB0, "sizeof(EXCRYPT_HMACSHA_STATE) != 0xB0");

void ExCryptHmacShaInit(EXCRYPT_HMACSHA_STATE* state, const uint8_t* key, uint32_t key_size);
void ExCryptHmacShaUpdate(EXCRYPT_HMACSHA_STATE* state, const uint8_t* input, uint32_t input_size);
void ExCryptHmacShaFinal(EXCRYPT_HMACSHA_STATE* state, uint8_t* output, uint32_t output_size);
void ExCryptHmacSha(const uint8_t* key, uint32_t key_size, const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size);
uint8_t ExCryptHmacShaVerify(const uint8_t* key, uint32_t key_size, const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, const uint8_t* compare_buf, uint32_t compare_buf_size);
