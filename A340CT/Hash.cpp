#include "md5.h"

void Hashed()
{
	MD5 md5;
	

	// print the digest for a binary file on disk.
	puts(md5.digestFile("C://test.txt"));
}

