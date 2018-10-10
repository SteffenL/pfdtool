#include <pfdtool/private/crypto.h>

void sha1_hmac(
	const unsigned char *key, size_t keylen,
	const unsigned char *input, size_t ilen,
	unsigned char output[20])
{
	sha1_context sha1;
	sha1_hmac_starts(&sha1, key, keylen);
	sha1_hmac_update(&sha1, input, ilen);
	sha1_hmac_finish(&sha1, output);
};

void sha1_hmac_starts(sha1_context *ctx, const unsigned char *key, size_t keylen)
{
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    if (!md_info) {
        return;
    }

    mbedtls_md_init(ctx);
    if (mbedtls_md_setup(ctx, md_info, 1) != 0) {
        return;
    }

    if (mbedtls_md_hmac_starts(ctx, key, keylen) != 0) {
        return;
    }
}

void sha1_hmac_update(sha1_context *ctx, const unsigned char *input, size_t ilen)
{
    mbedtls_md_hmac_update(ctx, input, ilen);
}

void sha1_hmac_finish(sha1_context *ctx, unsigned char output[20])
{
    int a = mbedtls_md_hmac_finish(ctx, output);
    mbedtls_md_free(ctx);
}
