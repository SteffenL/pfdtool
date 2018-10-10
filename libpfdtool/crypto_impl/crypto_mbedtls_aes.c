#include <pfdtool/private/crypto.h>

int aes_setkey_enc(aes_context *ctx, const unsigned char *key, unsigned int keysize)
{
	return mbedtls_aes_setkey_enc(ctx, key, keysize);
}

int aes_setkey_dec(aes_context *ctx, const unsigned char *key, unsigned int keysize)
{
	return mbedtls_aes_setkey_dec(ctx, key, keysize);
}

int aes_crypt_cbc(
	aes_context *ctx,
	int mode,
	size_t length,
	unsigned char iv[16],
	const unsigned char *input,
	unsigned char *output)
{
	return mbedtls_aes_crypt_cbc(ctx, mode, length, iv, input, output);
}

int aes_crypt_ecb(
	aes_context *ctx,
	int mode,
	const unsigned char input[16],
	unsigned char output[16])
{
	return mbedtls_aes_crypt_ecb(ctx, mode, input, output);
}
