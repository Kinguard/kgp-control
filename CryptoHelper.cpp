#include "CryptoHelper.h"

#include <crypto++/pwdbased.h>
#include <crypto++/secblock.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/pssr.h>
#include <crypto++/sha.h>

#include <sstream>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>

#include <libutils/Logger.h>
#include <libutils/String.h>

using namespace std;
using namespace CryptoPP;
using namespace  Utils;

namespace CryptoHelper {


/*
 *
 * Begin implementation RSA wrapper
 *
 */

RSAWrapper::RSAWrapper(): priv_i(false), pub_i(false)
{
}

void RSAWrapper::GenerateKeys(unsigned int size)
{

	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize( this->rng, size);

	this->privkey = PrivateKeyPtr( new RSA::PrivateKey( params) );
	this->pubkey = PublicKeyPtr( new RSA::PublicKey(params) );

	this->priv_i = true;
	this->pub_i = true;

}

void RSAWrapper::LoadPrivKey(const string &path)
{
	ByteQueue q;

	FileSource file(path.c_str(), true);
	file.TransferTo(q);
	q.MessageEnd();

	this->privkey = PrivateKeyPtr( new RSA::PrivateKey( ) );
	this->privkey->Load(q);

	this->ValidatePrivKey();

	this->priv_i = true;
}

void RSAWrapper::LoadPubKey(const string &path)
{
	ByteQueue q;

	FileSource file(path.c_str(), true);
	file.TransferTo(q);
	q.MessageEnd();

	this->pubkey = PublicKeyPtr( new RSA::PublicKey() );
	this->pubkey->Load(q);

	this->ValidatePubKey();

	this->pub_i = true;
}

vector<byte> RSAWrapper::GetPubKey()
{
	if( ! this->pub_i )
	{
		throw runtime_error("Public key not loaded");
	}

	ByteQueue q;

	this->pubkey->Save(q);

	vector<byte> ret(q.TotalBytesRetrievable() );

	ArraySink sink(&ret[0],ret.size() );

	q.CopyTo( sink );

	return ret;
}

vector<byte> RSAWrapper::GetPubKeyAsDER()
{
	ByteQueue q;
	this->pubkey->DEREncode(q);

	vector<byte> ret(q.TotalBytesRetrievable() );

	ArraySink sink(&ret[0],ret.size() );

	q.CopyTo( sink );

	return ret;
}

vector<byte> RSAWrapper::GetPrivKey()
{
	if( ! this->priv_i )
	{
		throw runtime_error("Private key not loaded");
	}

	ByteQueue q;

	this->privkey->Save(q);

	vector<byte> ret(q.TotalBytesRetrievable() );

	ArraySink sink(&ret[0],ret.size() );

	q.CopyTo( sink );

	return ret;
}

vector<byte> RSAWrapper::GetPrivKeyAsDER()
{
	ByteQueue q;
	this->privkey->DEREncodePrivateKey(q);

	vector<byte> ret(q.TotalBytesRetrievable() );

	ArraySink sink(&ret[0],ret.size() );

	q.CopyTo( sink );

	return ret;
}

void RSAWrapper::SavePrivKey(const string &path, mode_t setmask)
{
	if( ! this->priv_i )
	{
		throw runtime_error("Private key not loaded");
	}

	mode_t mask = umask(setmask);
	ByteQueue queue;
	this->privkey->Save(queue);

	FileSink file(path.c_str());

	queue.CopyTo(file);
	file.MessageEnd();

	umask( mask );
}

void RSAWrapper::SavePubKey(const string &path, mode_t setmask)
{
	if( ! this->pub_i )
	{
		throw runtime_error("Public key not loaded");
	}

	mode_t mask = umask(setmask);
	ByteQueue queue;
	this->pubkey->Save(queue);

	FileSink file(path.c_str());

	queue.CopyTo(file);
	file.MessageEnd();

	umask( mask );
}

string RSAWrapper::PubKeyAsPEM()
{
	if( ! this->pub_i )
	{
		throw runtime_error("Public key not loaded");
	}

	ByteQueue queue;
	this->pubkey->DEREncode(queue);

	string cert;
	Base64Encoder encoder;

	encoder.Attach( new StringSink(cert) );

	queue.CopyTo( encoder );
	encoder.MessageEnd();

	stringstream ss;
	ss << "-----BEGIN PUBLIC KEY-----\n";
	ss << cert;
	ss << "-----END PUBLIC KEY-----\n";

	return ss.str();
}

string RSAWrapper::PrivKeyAsPEM()
{
	if( ! this->priv_i )
	{
		throw runtime_error("Private key not loaded");
	}

	ByteQueue queue;
	this->privkey->DEREncodePrivateKey(queue);

	string cert;
	Base64Encoder encoder;

	encoder.Attach( new StringSink(cert) );

	queue.CopyTo( encoder );
	encoder.MessageEnd();

	stringstream ss;

	ss << "-----BEGIN RSA PRIVATE KEY-----\n";
	ss << cert;
	ss << "-----END RSA PRIVATE KEY-----\n";

	return ss.str();
}

void RSAWrapper::LoadPrivKey(const vector<byte> &key)
{
	ByteQueue q;

	q.Put(&key[0], key.size() );

	this->privkey = PrivateKeyPtr( new RSA::PrivateKey( ) );
	this->privkey->Load(q);

	this->ValidatePrivKey();

	this->priv_i = true;
}

void RSAWrapper::LoadPrivKeyFromPEM(const string &key)
{
	this->LoadPrivKeyFromDER( RSAWrapper::PEMToDER(key) );
}

/*
 * We actually use BER decode but never mind.
 */

void RSAWrapper::LoadPrivKeyFromDER(const vector<byte> &key)
{
	ByteQueue q;

	q.Put(&key[0], key.size() );

	this->privkey = PrivateKeyPtr( new RSA::PrivateKey() );

	this->privkey->BERDecodePrivateKey( q, false, q.MaxRetrievable() );

	this->ValidatePrivKey();

	this->priv_i = true;

}

void RSAWrapper::LoadPubKey(const vector<byte> &key)
{
	ByteQueue q;

	q.Put(&key[0], key.size() );

	this->pubkey = PublicKeyPtr( new RSA::PublicKey() );
	this->pubkey->Load(q);

	this->ValidatePubKey();

	this->pub_i = true;
}

void RSAWrapper::LoadPubKeyFromPEM(const string &key)
{
	this->LoadPubKeyFromDER( RSAWrapper::PEMToDER(key) );
}

void RSAWrapper::LoadPubKeyFromDER(const vector<byte> &key)
{
	ByteQueue q;

	q.Put(&key[0], key.size() );

	this->pubkey = PublicKeyPtr( new RSA::PublicKey() );

	this->pubkey->BERDecode( q );

	this->ValidatePubKey();

	this->pub_i = true;
}

vector<byte> RSAWrapper::SignMessage(const string &message)
{
	if( ! this->priv_i )
	{
		throw runtime_error("Private key not loaded");
	}

	RSASS<PKCS1v15, SHA1>::Signer signer( *this->privkey.get() );

	SecByteBlock signature( signer.MaxSignatureLength() );

	// Sign message
	signer.SignMessage( this->rng, (const byte*) message.c_str(),
		message.length(), signature );

	return vector<byte>(signature.begin(), signature.end());
}

bool RSAWrapper::VerifyMessage(const string &message, const string& signature)
{
	if( ! this->pub_i )
	{
		throw runtime_error("Public key not loaded");
	}

	RSASS<PKCS1v15, SHA1>::Verifier verifier( *this->pubkey.get() );

	bool result = verifier.VerifyMessage( (const byte*)message.c_str(),
		message.length(), (const byte*)signature.c_str(), signature.length() );

	return result;
}
/*
 * TODO: Merge these two to something more intelligent?
 */
bool RSAWrapper::VerifyMessage(const string &message, const vector<byte> &signature)
{
	if( ! this->pub_i )
	{
		throw runtime_error("Public key not loaded");
	}

	RSASS<PKCS1v15, SHA1>::Verifier verifier( *this->pubkey.get() );

	bool result = verifier.VerifyMessage( (const byte*)message.c_str(),
										  message.length(), &signature[0], signature.size() );

	return result;
}

vector<byte> RSAWrapper::PEMToDER(const string &key)
{
	list<string> rows = String::Split(key, "\n");
	if( rows.size() < 3 )
	{
		logg << Logger::Debug << "Key\n"<<key<<lend;
		logg << Logger::Debug << "Rows "<<rows.size()<<lend;
		throw runtime_error("Malformed PEM key");
	}

	// Lose first and last line
	rows.pop_back();
	rows.pop_front();

	// Merge rows again
	stringstream ss;
	for(auto row: rows)
	{
		ss << row;
	}

	return Base64Decode( ss.str() );
}

void RSAWrapper::ValidatePrivKey()
{
	if(! this->privkey->Validate( this->rng, 3) )
	{
		throw runtime_error("Rsa private key validation failed");
	}
}

void RSAWrapper::ValidatePubKey()
{
	if(! this->pubkey->Validate( this->rng, 3) )
	{
		throw runtime_error("Rsa public key validation failed");
	}
}

/*
 *
 * Begin implementation Stringtools
 *
 */

string Base64Encode ( const vector<byte>& in )
{
	string encoded;
	ArraySource(&in[0], in.size(), true,
			new Base64Encoder(
				new StringSink( encoded ), false
				)
			);
	return encoded;
}

string Base64Encode(const string& s)
{
	string encoded;

	StringSource ss( s, true,
			new Base64Encoder(
				new StringSink( encoded ), false
				)
		);

	return encoded;
}

vector<byte> Base64Decode(const string &data)
{
	//TODO: How avoid intermediate string?
	string decoded;
	StringSource ss( data, true,
			new Base64Decoder(
				new StringSink( decoded )
				)
		);

	vector<byte> ret( decoded.size() );

	std::copy(decoded.begin(), decoded.end(), ret.begin() );

	return ret;
}


string Base64DecodeToString(const string& s)
{
	string decoded;

	StringSource ss( s, true,
			new Base64Decoder(
				new StringSink( decoded )
				)
		);

	return decoded;
}


void
Base64Decode ( const string& s, vector<byte>& out )
{
	string decoded = Base64DecodeToString(s);
	out.resize( decoded.size() );
	std::copy(decoded.begin(), decoded.end(), out.begin() );
}

void
Base64Decode ( const string& s, SecVector<byte>& out )
{
	//TODO: the string here is not allocated with wiped allocator
	string decoded = Base64DecodeToString(s);
	out.resize( decoded.size() );
	std::copy(decoded.begin(), decoded.end(), out.begin() );
}


/*
 *
 *  Begin implementatsion AES wrapper
 *
 */

vector<byte> AESWrapper::defaultiv = {
	1,2,3,4,
	5,6,7,8,
	9,10,11,12,
	13,14,15,16
};

AESWrapper::AESWrapper(const SecVector<byte>& key, const vector<byte>& iv)
{
	this->Initialize(key, iv);
}

AESWrapper::AESWrapper ()
{
}

void
AESWrapper::Initialize ( const SecVector<byte>& key, const vector<byte>& iv )
{
	this->key = key;
	this->iv = iv;
#if 0
	this->e.SetKeyWithIV( &key[0], key.size(), &iv[0] );
	this->d.SetKeyWithIV( &key[0], key.size(), &iv[0] );
#endif
}

string AESWrapper::Encrypt(const string& plain)
{

	this->e.SetKeyWithIV( &this->key[0], this->key.size(), &this->iv[0] );

	string ciphered;

	StringSource s(plain, true,
		new StreamTransformationFilter( this->e,
			new StringSink(ciphered)
		)
	);

	return ciphered;
}
void

AESWrapper::Encrypt ( const vector<byte>& in, vector<byte>& out )
{

	this->e.SetKeyWithIV( &this->key[0], this->key.size(), &this->iv[0] );

	string enc;
	StringSource s( &in[0], in.size(), true,
			new StreamTransformationFilter( this->e,
					new StringSink(enc)
			)
		);

	out.resize(enc.size());
	copy(enc.begin(), enc.end(), out.begin() );
}

string AESWrapper::Decrypt(const string& encoded)
{
	this->d.SetKeyWithIV( &this->key[0], this->key.size(), &this->iv[0] );

	string plain;
	logg << Logger::Debug << "Decode string size "<<encoded.size()<<lend;
	StringSource s(encoded, true,
		new StreamTransformationFilter(this->d,
			new StringSink(plain)
		)
	);

	return plain;
}

void
AESWrapper::Decrypt ( const vector<byte>& in, vector<byte>& out )
{
	//Todo: investigate if the copy could be avoided.
	string plain = this->Decrypt(in);

	out.resize(plain.size());
	copy(plain.begin(), plain.end(), out.begin() );
}

string
AESWrapper::Decrypt ( const vector<byte>& in )
{
	this->d.SetKeyWithIV( &this->key[0], this->key.size(), &this->iv[0] );

	string plain;
	StringSource s( &in[0], in.size(), true,
			new StreamTransformationFilter( this->d,
					new StringSink(plain)
					)
			);
	return plain;
}

const vector<byte> defaultsalt( {
		33, 31, 2, 238, 199, 213, 62,
		70, 132, 179, 13, 251, 120,
		29, 251, 69, 216, 120, 141, 19,
		177, 102, 3, 49, 165, 5, 120,
		159, 191, 117, 240, 125, 235,
		75, 158, 112, 67, 172, 57, 123,
		175, 203, 37, 94, 57, 99, 237,
		225, 238, 122, 213, 86, 182, 181,
		251, 192, 142, 41, 105, 163, 1,
		132, 52, 97
	} );


SecVector<byte>
PBKDF2 (const SecString &passwd, size_t keylength, const vector<byte>& salt,
		unsigned int iter )
{

	SecVector<byte> ret(keylength);

	PKCS5_PBKDF2_HMAC<SHA512> df;

	int iters_done = df.DeriveKey(
		&ret[0], ret.size(),
		0,
		(const byte*)passwd.c_str(), passwd.length(),
		&salt[0],
		salt.size(),
		iter);

	return ret;
}

void
AESWrapper::SetDefaultIV ( const vector<byte>& iv )
{
	AESWrapper::defaultiv = iv;
}


AESWrapper::~AESWrapper()
{
}

static int do_call(const string& cmd){
	int ret=system(cmd.c_str());
	if(ret<0){
					return ret;
	}
	return WEXITSTATUS(ret);
}

bool MakeCSR(const string &privkeypath, const string &csrpath, const string &cn, const string &company)
{
	stringstream cmd;
	cmd << "/usr/bin/openssl ";
	cmd << "req -out \""<< csrpath << "\" -key \""<<  privkeypath << "\" -new -subj '/O="<<company<<"/CN="<<cn<<"'";

	return do_call( cmd.str().c_str() ) == 0;
}



}
