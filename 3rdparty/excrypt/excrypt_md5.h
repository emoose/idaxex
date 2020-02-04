#pragma once
// MD5 hash & HMAC algorithm

typedef struct _EXCRYPT_MD5_STATE
{
  uint32_t count;
  uint32_t state[4];
  uint8_t buffer[64];
} EXCRYPT_MD5_STATE;

void ExCryptMd5Init(EXCRYPT_MD5_STATE* state);
void ExCryptMd5Update(EXCRYPT_MD5_STATE* state, const uint8_t* input, uint32_t input_size);
void ExCryptMd5Final(EXCRYPT_MD5_STATE* state, uint8_t* output, uint32_t output_size);
void ExCryptMd5(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size, const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size);

typedef struct _EXCRYPT_HMACMD5_STATE
{
  EXCRYPT_MD5_STATE Md5State[2];
} EXCRYPT_HMACMD5_STATE;

void ExCryptHmacMd5Init(EXCRYPT_HMACMD5_STATE* state, const uint8_t* key, uint32_t key_size);
void ExCryptHmacMd5Update(EXCRYPT_HMACMD5_STATE* state, const uint8_t* input, uint32_t input_size);
void ExCryptHmacMd5Final(EXCRYPT_HMACMD5_STATE* state, uint8_t* output, uint32_t output_size);
void ExCryptHmacMd5(const uint8_t* key, uint32_t key_size, const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size);
