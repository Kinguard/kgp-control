#include "PasswordFile.h"

#include <libutils/Exceptions.h>

#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/osrng.h>

#include <cstdio>
#include <strings.h>
#include <arpa/inet.h>

#include <fstream>

using namespace Utils;
using namespace CryptoPP;

static constexpr uint8_t OPI_KEY_VERSION = 0x01;

typedef struct _opi_key{
	uint16_t	version;
	uint8_t		iv[16];
	uint16_t	length;
	uint8_t		key[8192];
} opi_key;

static uint8_t pkey[32] = {
	0x91, 0x70, 0x71, 0xcd, 0xf6, 0xfd, 0xbf, 0x41,
	0xf6, 0x34, 0xe4, 0x3a, 0x5a, 0xe9, 0x9d, 0x99,
	0xb5, 0x79, 0xb6, 0x30, 0xab, 0x08, 0x11, 0x83,
	0x58, 0xfe, 0xca, 0xbd, 0x4e, 0x71, 0x50, 0x38
};

string PasswordFile::Read(const string &path)
{
	opi_key key;

	ifstream ifs(path, ios_base::binary);

	if( ! ifs )
	{
		throw ErrnoException("Could not read file");
	}

	ifs.read( (char*) &key, sizeof(opi_key) );

	if( ! ifs )
	{
		throw ErrnoException("Failed to read password file");
	}

	ifs.close();

	key.length = ntohs( key.length );
	key.version = ntohs( key.version );

	string plain;

	CBC_Mode< AES >::Decryption d( pkey, sizeof(pkey), key.iv );

	string source( (const char*) key.key, key.length);
	StringSource s( source , true,
			new StreamTransformationFilter( d,
					new StringSink(plain)
					)
			);

	return plain;
}

void PasswordFile::Write(const string& path, const string &password)
{
	AutoSeededRandomPool rng;
	opi_key key;

	if( password.size() > sizeof(opi_key::key ) )
	{
		throw runtime_error("Password to long");
	}

	rng.GenerateBlock( (unsigned char*) &key , sizeof(opi_key));
	rng.GenerateBlock( (unsigned char*) &key.iv, sizeof(opi_key::iv));

	CBC_Mode< AES >::Encryption e( pkey, sizeof(pkey), key.iv );

	string ciphered;

	StringSource s(password, true,
		new StreamTransformationFilter( e,
			new StringSink(ciphered)
		)
	);

	memcpy( key.key, ciphered.c_str(), ciphered.size() );

	key.length = htons(ciphered.size());
	key.version = htons(OPI_KEY_VERSION);

	ofstream ofs(path, ios_base::binary | ios_base::trunc);

	if( ! ofs )
	{
		throw ErrnoException("Failed to open password file for writing");
	}

	ofs.write( (char*) &key, sizeof(opi_key));

	if( ! ofs )
	{
		throw ErrnoException("Failed to write password file");
	}

	ofs.close();
}
