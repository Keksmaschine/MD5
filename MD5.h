/**
 * @file MD5.h
 * @date 11.03.2017
 * @author Christian Hülsmann (christian_huelsmann@gmx.de)
 */

#ifndef MD5_H
#define MD5_H

#include <Windows.h>

// Size of an MD5 digest in bytes
#define MD5_DIGEST_SIZE 16


// Context structure for MD5 hashing
struct MD5_Context
{
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	BYTE digest[MD5_DIGEST_SIZE];
};


/**
 * Initializes the MD5_Context structure for calculating MD5 hashes.
 * @param	Context	MD5_Context structure to initialize
 * @return			TRUE if successfull, otherwise FALSE
 */
BOOLEAN MD5_Init(struct MD5_Context* Context);

/**
 * Hashes data in order to calculate and MD5 hash.
 * @param	Context	MD5_Context structure
 * @param	Buf		Data to hash
 * @param	BufSize	Size of the buffer Buf
 * @return			TRUE if successfull, otherwise FALSE
 */
BOOLEAN MD5_Update(struct MD5_Context* Context, const PBYTE Buf, DWORD BufSize);

/**
 * Finalizes the MD5 hash.
 * @param	Context	MD5_Context structure
 * @return			TRUE if successfull, otherwise FALSE
 */
BOOLEAN MD5_Final(struct MD5_Context* Context);

/**
 * Calculates an MD5 hash of a buffer in one pass.
 * @param	Buf		Buffer to calculate the hash for
 * @param	BufSize	Size of the buffer Buf
 * @param	Digest	Byte array which receives the MD5 digest if the function succeeds,
 *					it has to be at least of size MD5_DIGEST_SIZE
 * @return			TRUE if successfull, otherwise FALSE
 */
BOOLEAN MD5_Calculate(const PBYTE Buf, DWORD BufSize, PBYTE Digest);


#endif // #ifndef MD5_H
