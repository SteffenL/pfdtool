// Code mostly by RoseDevil
// http://www.rohitab.com/discuss/topic/39777-hmac-md5sha1/

#include <pfdtool/private/crypto.h>

#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <WinCrypt.h>

typedef struct{
	BLOBHEADER header;
	DWORD len;
	BYTE key[0];
}my_blob;

typedef struct{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;
	HCRYPTHASH hHmacHash;
	DWORD dwDataLen;
	my_blob* kb;
	HMAC_INFO HmacInfo;
	DWORD kbSize;
}ctx_type;

void native_hmac_sha1_free(native_hmac_sha1_context* ctx)
{
	if (!ctx || !ctx->ctx) {
		return;
	}

	ctx_type* ctx_ = (ctx_type*)ctx->ctx;
	free(ctx_->kb);
	if(ctx_->hHmacHash)
		CryptDestroyHash(ctx_->hHmacHash);
	if(ctx_->hKey)
		CryptDestroyKey(ctx_->hKey);
	if(ctx_->hHash)
		CryptDestroyHash(ctx_->hHash);	
	if(ctx_->hProv)
		CryptReleaseContext(ctx_->hProv, 0);
	free(ctx_);
}

void native_hmac_sha1_set_key(native_hmac_sha1_context* ctx, const unsigned char *key, size_t keylen)
{
	int err = 0;

	ctx_type* ctx_ = (ctx_type*)ctx->ctx;

	ctx_->HmacInfo.HashAlgid = CALG_SHA1;
	ctx_->dwDataLen = 20;

	ctx_->kbSize = sizeof(my_blob) + keylen;

	ctx_->kb = (my_blob*)malloc(ctx_->kbSize);
	ctx_->kb->header.bType = PLAINTEXTKEYBLOB;
	ctx_->kb->header.bVersion = CUR_BLOB_VERSION;
	ctx_->kb->header.reserved = 0;
	ctx_->kb->header.aiKeyAlg = CALG_RC2;
	memcpy(&ctx_->kb->key, key, keylen);
	ctx_->kb->len = keylen;

	do {
		if (!CryptAcquireContext(&ctx_->hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL,CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET)){
			err = 1;
			break;
		}

		if (!CryptImportKey(ctx_->hProv,  (BYTE*)ctx_->kb, ctx_->kbSize, 0, CRYPT_IPSEC_HMAC_KEY, &ctx_->hKey)){
			err = 1;
			break;
		}

		if (!CryptCreateHash(ctx_->hProv, CALG_HMAC, ctx_->hKey, 0, &ctx_->hHmacHash)){
			err = 1;
			break;
		}

		if (!CryptSetHashParam(ctx_->hHmacHash, HP_HMAC_INFO, (BYTE*)&ctx_->HmacInfo, 0)){
			err = 1;
			break;
		}
	} while(0);

	if (err) {
		native_hmac_sha1_free(ctx);
	}
}

void native_hmac_sha1_update(native_hmac_sha1_context* ctx, const unsigned char* data, size_t dataLen)
{
	ctx_type* ctx_ = (ctx_type*)ctx->ctx;
	if (!CryptHashData(ctx_->hHmacHash, data, dataLen, 0)){
		native_hmac_sha1_free(ctx);
	}
}

void native_hmac_sha1_final(native_hmac_sha1_context* ctx, unsigned char* hash)
{
	ctx_type* ctx_ = (ctx_type*)ctx->ctx;
	if (!CryptGetHashParam(ctx_->hHmacHash, HP_HASHVAL, hash, &ctx_->dwDataLen, 0)){
		native_hmac_sha1_free(ctx);
	}
}

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
	memset(ctx, 0, sizeof(sha1_context));
	ctx->ctx = (ctx_type*)malloc(sizeof(ctx_type));
	ZeroMemory(ctx->ctx, sizeof(ctx_type));
	native_hmac_sha1_set_key(ctx, key, keylen);
}

void sha1_hmac_update(sha1_context *ctx, const unsigned char *input, size_t ilen)
{
	native_hmac_sha1_update(ctx, input, ilen);
}

void sha1_hmac_finish(sha1_context *ctx, unsigned char output[20])
{
	native_hmac_sha1_final(ctx, output);
	native_hmac_sha1_free(ctx);
}
