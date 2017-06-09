// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include <string>

#include "osrng.h"
#include "cryptlib.h"
#include "salsa.h"

using CryptoPP::AutoSeededRandomPool;
using CryptoPP::Exception;
using CryptoPP::Salsa20;
using std::string;
using namespace std;

void StreamCiphered()
{
	AutoSeededRandomPool prng;

	string ciphertextStr(""), plaintextStr("My Plaintext!! My Dear plaintext!!");
	byte *plaintextBytes = (byte *)plaintextStr.c_str();
	byte *ciphertextBytes = new byte[plaintextStr.length()];

	//Key and IV Generation/Initialization
	byte key[32];
	byte iv[8];
	prng.GenerateBlock(key, 32);
	prng.GenerateBlock(iv, 8);

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

