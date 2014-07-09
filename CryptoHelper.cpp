#include "CryptoHelper.h"

#include <crypto++/secblock.h>
#include <crypto++/base64.h>
#include <crypto++/files.h>
#include <crypto++/pssr.h>
#include <crypto++/sha.h>

#include <sstream>
#include <string>

#include <sys/types.h>
#include <sys/stat.h>

using namespace std;
using namespace CryptoPP;

CryptoHelper::CryptoHelper(): priv_i(false), pub_i(false)
{
}

void CryptoHelper::GenerateKeys(unsigned int size)
{

	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize( this->rng, size);

	this->privkey = PrivateKeyPtr( new RSA::PrivateKey( params) );
	this->pubkey = PublicKeyPtr( new RSA::PublicKey(params) );

	this->priv_i = true;
	this->pub_i = true;

}

void CryptoHelper::LoadPrivKey(const string &path)
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

void CryptoHelper::LoadPubKey(const string &path)
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

void CryptoHelper::SavePrivKey(const string &path, mode_t setmask)
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

void CryptoHelper::SavePubKey(const string &path, mode_t setmask)
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

string CryptoHelper::PubKeyAsPEM()
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

string CryptoHelper::PrivKeyAsPEM()
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

vector<byte> CryptoHelper::SignMessage(const string &message)
{
	if( ! this->priv_i )
	{
		throw runtime_error("Private key not loaded");
	}

	RSASS<PSS, SHA1>::Signer signer( *this->privkey.get() );

	SecByteBlock signature( signer.MaxSignatureLength() );

	// Sign message
	signer.SignMessage( this->rng, (const byte*) message.c_str(),
		message.length(), signature );

	return vector<byte>(signature.begin(), signature.end());
}

bool CryptoHelper::VerifyMessage(const string &message, const string& signature)
{
	if( ! this->pub_i )
	{
		throw runtime_error("Public key not loaded");
	}

	RSASS<PSS, SHA1>::Verifier verifier( *this->pubkey.get() );

	bool result = verifier.VerifyMessage( (const byte*)message.c_str(),
		message.length(), (const byte*)signature.c_str(), signature.length() );

	return result;
}
/*
 * TODO: Merge these two to something more intelligent?
 */
bool CryptoHelper::VerifyMessage(const string &message, const vector<byte> &signature)
{
	if( ! this->pub_i )
	{
		throw runtime_error("Public key not loaded");
	}

	RSASS<PSS, SHA1>::Verifier verifier( *this->pubkey.get() );

	bool result = verifier.VerifyMessage( (const byte*)message.c_str(),
										  message.length(), &signature[0], signature.size() );

	return result;
}


string CryptoHelper::Base64Encode(const string& s)
{
	string encoded;

	StringSource ss( s, true,
			new Base64Encoder(
				new StringSink( encoded ), false
				)
		);

	return encoded;
}

void CryptoHelper::ValidatePrivKey()
{
	if(! this->privkey->Validate( this->rng, 3) )
	{
		throw runtime_error("Rsa private key validation failed");
	}
}

void CryptoHelper::ValidatePubKey()
{
	if(! this->pubkey->Validate( this->rng, 3) )
	{
		throw runtime_error("Rsa public key validation failed");
	}
}

string CryptoHelper::Base64Encode ( const vector<byte>& in )
{
	string encoded;
	ArraySource(&in[0], in.size(), true,
			new Base64Encoder(
				new StringSink( encoded ), false
				)
			);
	return encoded;
}
