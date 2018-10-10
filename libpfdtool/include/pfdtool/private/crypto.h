#ifndef libpfdtool_crypto_h__
#define libpfdtool_crypto_h__

#include <pfdtool/private/crypto_defines.h>

//
// AES
//

#ifndef CRYPT_AES_DEFAULT
#error No AES implementation specified
#endif

#if (CRYPT_AES_DEFAULT == CRYPT_AES_POLARSSL)
#include <polarssl/aes.h>
#elif (CRYPT_AES_DEFAULT == CRYPT_AES_MBEDTLS)
#include <mbedtls/aes.h>
typedef mbedtls_aes_context aes_context;
#else
#error Invalid AES implementation specified
#endif

#if (CRYPT_AES_DEFAULT != CRYPT_AES_POLARSSL)
#define AES_ENCRYPT     1
#define AES_DECRYPT     0

#ifdef __cplusplus
extern "C" {
#endif
int aes_setkey_enc(aes_context *ctx, const unsigned char *key, unsigned int keysize);
int aes_setkey_dec(aes_context *ctx, const unsigned char *key, unsigned int keysize);
int aes_crypt_cbc(aes_context *ctx, int mode, size_t length, unsigned char iv[16], const unsigned char *input, unsigned char *output);
int aes_crypt_ecb(aes_context *ctx, int mode, const unsigned char input[16], unsigned char output[16]);
#ifdef __cplusplus
};
#endif
#endif

//
// SHA
//

// Note:
// SHA1 != HMAC, but since only HMAC-SHA1 will be used in our program, we can cheat

#ifndef CRYPT_SHA_DEFAULT
#error No SHA-1 implementation specified
#endif

#if CRYPT_SHA_DEFAULT == CRYPT_SHA_NATIVE && !defined(WIN32)
#error Native SHA implementation is currently only available for Windows
#endif

#if (CRYPT_SHA_DEFAULT == CRYPT_SHA_POLARSSL)
#include <polarssl/sha1.h>
#elif (CRYPT_SHA_DEFAULT == CRYPT_SHA_MBEDTLS)
#include <mbedtls/md.h>
typedef mbedtls_md_context_t sha1_context;
#elif (CRYPT_SHA_DEFAULT == CRYPT_SHA_NATIVE)
typedef struct {
	void* ctx;
} native_hmac_sha1_context;
typedef native_hmac_sha1_context sha1_context;
#else
#error Invalid SHA-1 implementation specified
#endif

#if (CRYPT_SHA_DEFAULT != CRYPT_SHA_POLARSSL)
#ifdef __cplusplus
extern "C" {
#endif
void sha1_hmac(const unsigned char *key, size_t keylen, const unsigned char *input, size_t ilen, unsigned char output[20]);
void sha1_hmac_starts(sha1_context *ctx, const unsigned char *key, size_t keylen);
void sha1_hmac_update(sha1_context *ctx, const unsigned char *input, size_t ilen);
void sha1_hmac_finish(sha1_context *ctx, unsigned char output[20]);
#ifdef __cplusplus
};
#endif
#endif

#endif // libpfdtool_crypto_h__
