#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>  // size_t
#include <stdint.h>  // uint8_t
#include <stdbool.h> // bool

// Header Definitions
// Bit 0 : 0 = symmetric, 1 = asymmetric
// Bit 1 : 0 = private, 1 = public
// Bit 2-4 : Encryption Algorithm (AES, RSA, ECC, etc.)
// Bit 5-7: Encryption Key Length (128, 192, 256, etc.)

// Bit 0
#define AT_KEYSTORE_DEF_SYMMETRIC 0b0
#define AT_KEYSTORE_DEF_ASYMMETRIC 0b1

// Bit 1
#define AT_KEYSTORE_DEF_PRIVATE 0b00
#define AT_KEYSTORE_DEF_PUBLIC 0b10

// Bits 2-4
#define AT_KEYSTORE_DEF_AES 0b000 00

#define AT_KEYSTORE_DEF_RSA 0b000 00
#define AT_KEYSTORE_DEF_ECC 0b001 00

// Bits 5-7
#define AT_KEYSTORE_KEYLEN_AES_128 0b000 000 00
#define AT_KEYSTORE_KEYLEN_AES_192 0b001 000 00
#define AT_KEYSTORE_KEYLEN_AES_256 0b010 000 00

#define AT_KEYSTORE_KEYLEN_RSA_2048 0b000 000 00
#define AT_KEYSTORE_KEYLEN_RSA_4096 0b001 000 00

#define AT_KEYSTORE_KEYLEN_ECC_112 0b000 000 00
#define AT_KEYSTORE_KEYLEN_ECC_224 0b001 000 00

// Bits 0-1
#define AT_KEYSTORE_TYPE_ASYMMETRIC_PRIVATE (uint8_t)(AT_KEYSTORE_TYPE_ASYMMETRIC | AT_KEYSTORE_TYPE_PRIVATE)
#define AT_KEYSTORE_TYPE_ASYMMETRIC_PUBLIC (uint8_t)(AT_KEYSTORE_TYPE_ASYMMETRIC | AT_KEYSTORE_TYPE_PUBLIC)

// Bits 0-4
#define AT_KEYSTORE_TYPE_AES (uint8_t)(AT_KEYSTORE_ALGORITHM_AES | AT_KEYSTORE_TYPE_SYMMETRIC)

#define AT_KEYSTORE_TYPE_RSA_PRIVATE (uint8_t)(AT_KEYSTORE_ALGORITHM_RSA | AT_KEYSTORE_TYPE_ASYMMETRIC_PRIVATE)
#define AT_KEYSTORE_TYPE_RSA_PUBLIC (uint8_t)(AT_KEYSTORE_ALGORITHM_RSA | AT_KEYSTORE_TYPE_ASYMMETRIC_PUBLIC)

#define AT_KEYSTORE_TYPE_ECC_PRIVATE (uint8_t)(AT_KEYSTORE_ALGORITHM_ECC | AT_KEYSTORE_TYPE_ASYMMETRIC_PRIVATE)
#define AT_KEYSTORE_TYPE_ECC_PUBLIC (uint8_t)(AT_KEYSTORE_ALGORITHM_ECC | AT_KEYSTORE_TYPE_ASYMMETRIC_PUBLIC)

// Bits 0-7
#define AT_KEYSTORE_TYPE_AES_128 (uint8_t)(AT_KEYSTORE_TYPE_AES | AT_KEYSTORE_KEYLEN_AES_128)
#define AT_KEYSTORE_TYPE_AES_192 (uint8_t)(AT_KEYSTORE_TYPE_AES | AT_KEYSTORE_KEYLEN_AES_192)
#define AT_KEYSTORE_TYPE_AES_256 (uint8_t)(AT_KEYSTORE_TYPE_AES | AT_KEYSTORE_KEYLEN_AES_256)

#define AT_KEYSTORE_TYPE_RSA_2048_PRIVATE (uint8_t)(AT_KEYSTORE_TYPE_RSA_PRIVATE | AT_KEYSTORE_KEYLEN_RSA_2048)
#define AT_KEYSTORE_TYPE_RSA_2048_PUBLIC (uint8_t)(AT_KEYSTORE_TYPE_RSA_PUBLIC | AT_KEYSTORE_KEYLEN_RSA_2048)
#define AT_KEYSTORE_TYPE_RSA_4096_PRIVATE (uint8_t)(AT_KEYSTORE_TYPE_RSA_PRIVATE | AT_KEYSTORE_KEYLEN_RSA_4096)
#define AT_KEYSTORE_TYPE_RSA_4096_PUBLIC (uint8_t)(AT_KEYSTORE_TYPE_RSA_PUBLIC | AT_KEYSTORE_KEYLEN_RSA_4096)

#define AT_KEYSTORE_TYPE_ECC_112_PRIVATE (uint8_t)(AT_KEYSTORE_TYPE_ECC_PRIVATE | AT_KEYSTORE_KEYLEN_ECC_112)
#define AT_KEYSTORE_TYPE_ECC_112_PUBLIC (uint8_t)(AT_KEYSTORE_TYPE_ECC_PUBLIC | AT_KEYSTORE_KEYLEN_ECC_112)
#define AT_KEYSTORE_TYPE_ECC_224_PRIVATE (uint8_t)(AT_KEYSTORE_TYPE_ECC_PRIVATE | AT_KEYSTORE_KEYLEN_ECC_224)
#define AT_KEYSTORE_TYPE_ECC_224_PUBLIC (uint8_t)(AT_KEYSTORE_TYPE_ECC_PUBLIC | AT_KEYSTORE_KEYLEN_ECC_224)

  typedef struct
  {
    uint8_t header;
    size_t klen;
    char *key;
  } AtEncryptionKey;

  // TODO optimize keypair for n,e,d,p,q

  typedef struct
  {
    AtEncryptionKey *pubKey;
    AtEncryptionKey *privKey;
  } AtEncryptionKeyPair;

  typedef union
  {
    AtEncryptionKey *key;
    AtEncryptionKeyPair *keyPair;
  } AtEncryptionKeyEntry;

  typedef struct
  {
    size_t size;
    char *names[32];
    bool *type; // AT_KEYSTORE_DEF_SYMMETRIC | AT_KEYSTORE_DEF_ASYMMETRIC
    AtEncryptionKeyEntry *entry;
  } AtEncryptionKeyStore;

#ifdef __cplusplus
}
#endif
