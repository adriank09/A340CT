#include <iostream>
#include <cstdio>
#include <string>
#include <cstdlib>
#include <sstream>
#include <iomanip>

#include "cryptlib.h"
#include "md5.h"
#include "osrng.h"
#include "ccm.h"
#include "aes.h"
#include "vmac.h"
#include "filters.h"
#include "iterhash.h"
#include "secblock.h"
#include "salsa.h"
#include "hex.h"
#include "modes.h"
#include "des.h"

using std::cout;
using std::cerr;
using std::string;
using std::endl;
using std::cin;
using std::exit;
using std::hex;

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Exception;
using CryptoPP::AES;
using CryptoPP::AESEncryption;
using CryptoPP::AESDecryption;
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::CBC_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::AES;
using CryptoPP::VMAC;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::IteratedHashBase;
using CryptoPP::SecByteBlock;
using CryptoPP::Salsa20;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

void Hash()
{
	 MD5 md5;

	// print the digest for a binary file on disk.
	// prints the MD5-ed text
	puts(md5.digestFile("C://test//test.txt"));
}

void MAC(byte* key, byte* iv, std::string plaintext= "Why hello there, I'm plaintext, what might you be?")
{
	string ciphertext("");
	byte digestBytes[16];
	byte digestBytes2[16];
	AutoSeededRandomPool prng;

	//SecByteBlock key(AES::BLOCKSIZE);
	//SecByteBlock iv(AES::BLOCKSIZE);

	prng.GenerateBlock(key, 16);
	prng.GenerateBlock(iv, 16);

	VMAC<AES> vmac;
	cout << vmac.StaticAlgorithmName() << endl;
	cout << "DIgest Size: " << vmac.DigestSize() << endl;

	//VMAC Computation
	vmac.SetKeyWithIV(key, 16, iv);
	vmac.CalculateDigest(digestBytes, (byte *)plaintext.c_str(), plaintext.length());

	//VMAC Verification
	vmac.SetKeyWithIV(key, 16, iv);
	vmac.CalculateDigest(digestBytes2, (byte *)plaintext.c_str(), plaintext.length());

	for (int i = 0; i < 16; i++) {

		if (digestBytes[i] != digestBytes2[i]) {

			cout << "VMAC VERIFICATION FAILED!" << endl;
			exit(1);
		}
	}

	cout << "VMAC VERIFIED!" << endl;

}

void StreamCipher(byte* key, byte* iv, std::string plainText= "My Plaintext!! My Dear plaintext!!")
{
	string ciphertextStr(""), plaintextStr(plainText);
	byte *plaintextBytes = (byte *)plaintextStr.c_str();
	byte *ciphertextBytes = new byte[plaintextStr.length()];

	//Encryption
	Salsa20::Encryption salsa;
	salsa.SetKeyWithIV(key, 32, iv);
	salsa.ProcessData(ciphertextBytes, plaintextBytes, plaintextStr.length());
	ciphertextStr.assign((char *)ciphertextBytes);

	//Output plaintext/ciphertext for sanity check
	cout << "Plaintext: " << plaintextStr << endl;
	cout << "Ciphertext: " << ciphertextStr << endl;

	//Reset plaintext (for sanity again)
	plaintextStr.assign("");

	//Reset Key & IV
	salsa.SetKeyWithIV(key, 32, iv);

	//Decryption
	salsa.ProcessData(plaintextBytes, ciphertextBytes, ciphertextStr.length());
	plaintextStr.assign((char *)plaintextBytes);

	//Output newly decrypted plaintext
	cout << "Plaintext Again: " << plaintextStr << endl << endl;

	delete ciphertextBytes;
}

void BlockCipher(byte* key, byte* iv, std::string plain="Test")
{
	//HMODULE DLL = LoadLibrary(_T("cryptopp.dll"));
	//
	// Key and IV setup
	//AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-
	//bit). This key is secretly exchanged between two parties before communication
	//begins. DEFAULT_KEYLENGTH= 16 bytes
	string cipher, encoded, recovered;

	string plaintext;
	string ciphertext;
	string decryptedtext;
	cout << "Please enter plaintext: " << endl;
	getline(cin, plaintext);
	cout << endl << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext;
	cout << endl << endl;

	CryptoPP::AES::Encryption aesEncryption(key, 16);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
	stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length() + 1);
	stfEncryptor.MessageEnd();
	cout << "cipher text plain: " << ciphertext << endl;
	cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;
	cout << endl;
	cout << endl;
	cout << "cipher text In HEX FORM: ";
	for (int i = 0; i < ciphertext.size(); i++) {

		cout << "0x" << hex << (0xFF & static_cast<byte>(ciphertext[i])) << " ";
	}
	cout << endl;
	cout << endl;
	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(ciphertext, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text In HEX FORM (Modified):: " << encoded << endl;
	cout << endl;
	cout << endl;
	char *name2;
	name2 = (char*)malloc(encoded.length() + 1); // don't forget to free!!!!
												 //s2 = Database_row_count; // I forget if the string class can implicitly be converted to char*
												 //s2[0] = '1';
	strcpy(name2, encoded.c_str());

	const char* hex_str = name2;

	string result_string;
	unsigned int ch;
	for (; std::sscanf(hex_str, "%2x", &ch) == 1; hex_str += 2)
		result_string += ch;
	cout << "HEX FORM to cipher text :: ";
	cout << result_string << '\n';
	cout << endl;
	cout << endl;
	/*********************************\
	\*********************************/


	CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(result_string.c_str()), result_string.size());
	stfDecryptor.MessageEnd();
	cout << "Decrypted Text: " << std::endl;
	cout << decryptedtext;
	cout << std::endl << std::endl;
}

void Keygen(SecByteBlock key, byte* iv)
{
	char plainText[] = "Hello! How are you.";
	int messageLen = (int)strlen(plainText) + 1;

	//////////////////////////////////////////////////////////////////////////
	// Encrypt

	CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
	cfbEncryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);

	cout << "Encrypted plain text:" << plainText << endl;

	//////////////////////////////////////////////////////////////////////////
	// Decrypt

	CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
	cfbDecryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);

	cout << "Decrypted plain text:" << plainText << endl;


}

int main()
{
	// Select key length
	// Choice: AES::DEFAULT_KEYLENGTH, AES::MAX_KEYLENGTH, AES::MIN_KEYLENGTH, AES::KEYLENGTH_MULTIPLE

	AutoSeededRandomPool rnd;
	
	// Generate a random key
	SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
	rnd.GenerateBlock(key, key.size());

	// Generate a random IV
	byte iv[AES::BLOCKSIZE];
	rnd.GenerateBlock(iv, AES::BLOCKSIZE);

	byte scKey[AES::MAX_KEYLENGTH];
	rnd.GenerateBlock(scKey, AES::MAX_KEYLENGTH);

	byte scIV[AES::KEYLENGTH_MULTIPLE];
	rnd.GenerateBlock(scIV, AES::KEYLENGTH_MULTIPLE);

	//MAC(key, iv); // success
	//StreamCipher(scKey, scIV); // fail
	BlockCipher(key, iv); // success
	
	// let user choose what to do here...

	return 0;
}