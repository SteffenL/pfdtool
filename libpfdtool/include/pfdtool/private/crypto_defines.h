#ifndef libpfdtool_crypto_defines_h__
#define libpfdtool_crypto_defines_h__

// Use PolarSSL for AES
#define CRYPT_AES_POLARSSL 1
// Use mbed TLS (formerly PolarSSL) for AES
#define CRYPT_AES_MBEDTLS 2

// Use PolarSSL for HMAC-SHA1
#define CRYPT_SHA_POLARSSL 1
// Use mbed TLS for HMAC-SHA1
#define CRYPT_SHA_MBEDTLS 2
// Use native crypto for HMAC-SHA1
#define CRYPT_SHA_NATIVE 3

#endif // libpfdtool_crypto_defines_h__
