/**
 * @file MD5.c
 * @date 11.03.2017
 * @author Christian Hülsmann (christian_huelsmann@gmx.de)
 */

#include "MD5.h"
#include <Wincrypt.h>


BOOLEAN MD5_Init(struct MD5_Context* Context)
{
	if (!CryptAcquireContext(&Context->hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		return FALSE;
	}
	if (!CryptCreateHash(Context->hProv, CALG_MD5, 0, 0, &Context->hHash))
	{
		CryptReleaseContext(Context->hProv, 0);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN MD5_Update(struct MD5_Context* Context, const PBYTE Buf, DWORD BufSize)
{
	if (!CryptHashData(Context->hHash, Buf, BufSize, 0))
	{
		CryptReleaseContext(Context->hProv, 0);
		CryptDestroyHash(Context->hHash);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN MD5_Final(struct MD5_Context* Context)
{
	BOOLEAN ret = FALSE;
	DWORD hashLen = MD5_DIGEST_SIZE;

	if (CryptGetHashParam(Context->hHash, HP_HASHVAL, Context->digest, &hashLen, 0))
	{
		ret = TRUE;
	}
	CryptDestroyHash(Context->hHash);
	CryptReleaseContext(Context->hProv, 0);

	return ret;
}

BOOLEAN MD5_Calculate(const PBYTE Buf, DWORD BufSize, PBYTE Digest)
{
	struct MD5_Context context;
	ZeroMemory(&context, sizeof(context));
	
	if (!Init(&context) || !Update(&context, Buf, BufSize) || !Final(&context))
	{
		return FALSE;
	}
	
	CopyMemory(Digest, context.digest, MD5_DIGEST_SIZE);
	return TRUE;
}
