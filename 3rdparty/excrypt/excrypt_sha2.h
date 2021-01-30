/*
---------------------------------------------------------------------------
Copyright (c) 1998-2010, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 20/12/2007
*/

#ifndef _SHA2_H
#define _SHA2_H

#include <stdlib.h>

/* define for bit or byte oriented SHA   */
#if 1
#  define SHA2_BITS 0   /* byte oriented */
#else
#  define SHA2_BITS 1   /* bit oriented  */
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

  /* Note that the following function prototypes are the same */
  /* for both the bit and byte oriented implementations.  But */
  /* the length fields are in bytes or bits as is appropriate */
  /* for the version used.  Bit sequences are arrays of bytes */
  /* in which bit sequence indexes increase from the most to  */
  /* the least significant end of each byte.  The value 'len' */
  /* in sha<nnn>_hash for the byte oriented versions of SHA2  */
  /* is limited to 2^29 bytes, but multiple calls will handle */
  /* longer data blocks.                                      */

#define SHA256_DIGEST_SIZE  32
#define SHA256_BLOCK_SIZE   64

#define SHA384_DIGEST_SIZE  48
#define SHA384_BLOCK_SIZE  128

#define SHA512_DIGEST_SIZE  64
#define SHA512_BLOCK_SIZE  128

/* type to hold the SHA256 (and SHA224) context */

  typedef struct
  {
    uint32_t count;
    uint32_t hash[SHA256_DIGEST_SIZE >> 2];
    uint32_t wbuf[SHA256_BLOCK_SIZE >> 2];
  } EXCRYPT_SHA256_STATE;

  /* type to hold the SHA384 (and SHA512) context */

  typedef struct
  {
    uint64_t count;
    uint64_t hash[SHA512_DIGEST_SIZE >> 3];
    uint64_t wbuf[SHA512_BLOCK_SIZE >> 3];
  } EXCRYPT_SHA512_STATE;

  typedef EXCRYPT_SHA512_STATE  EXCRYPT_SHA384_STATE;

  void ExCryptSha256Init(EXCRYPT_SHA256_STATE* state);
  void ExCryptSha256Update(EXCRYPT_SHA256_STATE* state, const uint8_t* input, uint32_t input_size);
  void ExCryptSha256Final(EXCRYPT_SHA256_STATE* state, uint8_t* output, uint32_t output_size);
  void ExCryptSha256(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
    const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size);

  void ExCryptSha384Init(EXCRYPT_SHA384_STATE* state);
  void ExCryptSha384Update(EXCRYPT_SHA384_STATE* state, const uint8_t* input, uint32_t input_size);
  void ExCryptSha384Final(EXCRYPT_SHA384_STATE* state, uint8_t* output, uint32_t output_size);
  void ExCryptSha384(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
    const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size);

  void ExCryptSha512Init(EXCRYPT_SHA512_STATE* state);
  void ExCryptSha512Update(EXCRYPT_SHA512_STATE* state, const uint8_t* input, uint32_t input_size);
  void ExCryptSha512Final(EXCRYPT_SHA512_STATE* state, uint8_t* output, uint32_t output_size);
  void ExCryptSha512(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
    const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size);

  void ExCryptSha224Init(EXCRYPT_SHA256_STATE* state);
#if defined(__cplusplus)
}
#endif

#endif