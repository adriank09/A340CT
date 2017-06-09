
#include "osrng.h"
#include "ccm.h"
#include "aes.h"
#include "vmac.h"
#include "filters.h"
#include "iterhash.h"
#include "secblock.h"

using std::string;
using std::stringstream;
using std::cout;
using std::endl;

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::CBC_Mode;
using CryptoPP::AES;
using CryptoPP::VMAC;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::IteratedHashBase;
using CryptoPP::SecByteBlock;


void MACed()
{
	string ciphertext("");
	string plaintext("Why hello there, I'm plaintext, what might you be?");
	byte digestBytes[16];
	byte digestBytes2[16];
	AutoSeededRandomPool prng;

	SecByteBlock key(AES::BLOCKSIZE);
	SecByteBlock iv(AES::BLOCKSIZE);

	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());

	VMAC<AES> vmac;
	cout << vmac.StaticAlgorithmName() << endl;
	cout << "DIgest Size: " << vmac.DigestSize() << endl;

	//VMAC Computation
	vmac.SetKeyWithIV(key, key.size(), iv.BytePtr());
	vmac.CalculateDigest(digestBytes, (byte *)plaintext.c_str(), plaintext.length());

	//VMAC Verification
	vmac.SetKeyWithIV(key, key.size(), iv.BytePtr());
	vmac.CalculateDigest(digestBytes2, (byte *)plaintext.c_str(), plaintext.length());

	for (int i = 0; i < 16; i++) {

		if (digestBytes[i] != digestBytes2[i]) {

			cout << "VMAC VERIFICATION FAILED!" << endl;
			exit(1);
		}
	}

	cout << "VMAC VERIFIED!" << endl;

}

