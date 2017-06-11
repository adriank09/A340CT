#include <iostream>
#include <fstream>
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

using namespace std;

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

void Hash(string plaintext)
{
	MD5 md5;

	// prints the MD5-ed text
	char* plain = new char[plaintext.length() + 1];
	strcpy(plain, plaintext.c_str());
	char* hash_value = md5.digestString(plain);

	cout << "Hash value: " << hash_value << endl;
}

void MAC(byte* key, byte* iv, int key_length, int iv_length, std::string plaintext)
{
	string ciphertext("");
	byte* digestBytes = new byte[key_length];
	byte* digestBytes2 = new byte[key_length];
	AutoSeededRandomPool prng;

	prng.GenerateBlock(key, key_length);
	prng.GenerateBlock(iv, iv_length);

	VMAC<AES> vmac;
	cout << vmac.StaticAlgorithmName() << endl;
	cout << "DIgest Size: " << vmac.DigestSize() << endl;

	//VMAC Computation
	vmac.SetKeyWithIV(key, key_length, iv);
	vmac.CalculateDigest(digestBytes, (byte *)plaintext.c_str(), plaintext.length());

	//VMAC Verification
	vmac.SetKeyWithIV(key, key_length, iv);
	vmac.CalculateDigest(digestBytes2, (byte *)plaintext.c_str(), plaintext.length());

	for (int i = 0; i < 16; i++) {

		if (digestBytes[i] != digestBytes2[i]) {

			cout << "VMAC VERIFICATION FAILED!" << endl;
			exit(1);
		}
	}

	cout << "VMAC VERIFIED!" << endl;

}

void StreamCipher(byte key[], byte iv[], int keylen, std::string plainText)
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

void BlockCipher(byte* key, byte* iv, int keylength, std::string plain)
{
	//HMODULE DLL = LoadLibrary(_T("cryptopp.dll"));
	//
	// Key and IV setup
	//AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-
	//bit). This key is secretly exchanged between two parties before communication
	//begins. DEFAULT_KEYLENGTH= 16 bytes
	string cipher, encoded, recovered;

	string plaintext = plain;
	string ciphertext;
	string decryptedtext;

	cout << endl << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
	cout << plaintext;
	cout << endl << endl;

	CryptoPP::AES::Encryption aesEncryption(key, keylength);
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


	CryptoPP::AES::Decryption aesDecryption(key, keylength);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
	stfDecryptor.Put(reinterpret_cast<const unsigned char*>(result_string.c_str()), result_string.size());
	stfDecryptor.MessageEnd();
	cout << "Decrypted Text: " << std::endl;
	cout << decryptedtext;
	cout << std::endl << std::endl;
}

int main()
{
	// Select key length
	// Choice: AES::DEFAULT_KEYLENGTH, AES::MAX_KEYLENGTH, AES::MIN_KEYLENGTH, AES::KEYLENGTH_MULTIPLE

	int keylen, ivlen; // User input
	byte *key, *iv; // ptr
	AutoSeededRandomPool rnd; // rnd

	cout << "Choose key length [1-Default length(16), 2-Minimum length(16), 3-Max length(32), 4-Multiple(8)]: ";
	cin >> keylen;

	if (keylen < 0 || keylen > 4) {
		cerr << "Key length invalid. Exiting..." << endl;
		return -1;
	}

	cout << "Choose IV length [1-Default length(16), 2-Minimum length(16), 3-Max length(32), 4-Multiple(8)]: ";
	cin >> ivlen;

	if (ivlen < 0 || ivlen > 4) {
		cerr << "IV length invalid. Exiting..." << endl;
		return -1;
	}

	int key_length = 1, iv_length = 1;
	switch (keylen) {
	case 1:
		key_length = AES::DEFAULT_KEYLENGTH;
		break;
	case 2:
		key_length = AES::MIN_KEYLENGTH;
		break;
	case 3:
		key_length = AES::MAX_KEYLENGTH;
		break;
	case 4:
		key_length = AES::KEYLENGTH_MULTIPLE;
		break;
	}

	switch (ivlen) {
	case 1:
		iv_length = AES::DEFAULT_KEYLENGTH;
		break;
	case 2:
		iv_length = AES::MIN_KEYLENGTH;
		break;
	case 3:
		iv_length = AES::MAX_KEYLENGTH;
		break;
	case 4:
		iv_length = AES::KEYLENGTH_MULTIPLE;
		break;
	}

	// Flush the input
	cin.ignore();

	// Generate a random key
	key = new byte[key_length];
	rnd.GenerateBlock(key, key_length);

	// Generate a random IV
	iv = new byte[iv_length];
	rnd.GenerateBlock(iv, iv_length);

	cout << "Key and IV of specified length has been generated." << endl;

	ifstream myReadFile;
	myReadFile.open("text.txt");

	string plaintext;
	if (myReadFile.is_open()) {
		while (!myReadFile.eof()) {
			getline(myReadFile, plaintext);
		}
		myReadFile.close();
	}
	else {
		cerr << "File 'text.txt' is not present! Exiting..." << endl;
		return -1;
	}


	int choice = 0;
	cout << "Select an encryption method as seen below:" << endl;
	cout << "1. Hash Function" << endl;
	cout << "2. VMAC" << endl;
	cout << "3. Stream Cipher" << endl;
	cout << "4. Block Cipher" << endl;
	cout << "Enter choice: ";
	cin >> choice;
	do {
		if (choice < 1 || choice > 4)
		{
			cout << "Invalid input. Please enter a valid choice:" << endl;
			cin >> choice;
		}
	} while (choice < 1 || choice > 4);

	// again, to flush the input
	cin.ignore();

	switch (choice) {
	case 1:
		Hash(plaintext);
		break;
	case 2:
		MAC(key, iv, key_length, iv_length, plaintext);
		break;
	case 3:
		StreamCipher(key, iv, key_length, plaintext);
		break;
	case 4:
		BlockCipher(key, iv, key_length, plaintext);
		break;
	}

	system("Pause");

	return 0;
}