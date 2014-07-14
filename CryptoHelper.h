#ifndef CRYPTOHELPER_H
#define CRYPTOHELPER_H

#include <memory>
#include <string>

#include <crypto++/rsa.h>
#include <crypto++/osrng.h>
#include <crypto++/modes.h>

using namespace CryptoPP;
using namespace std;

namespace CryptoHelper {


template<typename T>
using SecVector = vector<T, AllocatorWithCleanup<T>>;

template<typename T>
using SecBasicString = basic_string<T, char_traits<T>, AllocatorWithCleanup<T>>;

typedef SecBasicString<char> SecString;


/*
 *
 * RSA Wrapper
 *
 */

typedef std::shared_ptr<RSA::PublicKey> PublicKeyPtr;
typedef std::shared_ptr<RSA::PrivateKey> PrivateKeyPtr;

class RSAWrapper
{
public:
	RSAWrapper();

	void GenerateKeys(unsigned int size=3072);

	void LoadPrivKey(const string& path);
	void LoadPubKey(const string& path);

	void SavePrivKey(const string& path, mode_t mask = 0077);
	void SavePubKey(const string& path, mode_t mask = 0002);

	string PubKeyAsPEM();
	string PrivKeyAsPEM();

	void LoadPubKey(const vector<byte>& key);
	void LoadPubKeyFromDER(const vector<byte>& key);
	void LoadPrivKey(const vector<byte>& key);
	void LoadPrivKeyFromDER(const vector<byte>& key);

	vector<byte> GetPubKey();
	vector<byte> GetPubKeyAsDER();
	vector<byte> GetPrivKey();
	vector<byte> GetPrivKeyAsDER();

	vector<byte> SignMessage(const string& message);
	bool VerifyMessage(const string& message, const string &signature);
	bool VerifyMessage(const string &message, const vector<byte>& signature);

private:
	void ValidatePrivKey();
	void ValidatePubKey();
	bool priv_i, pub_i; // Keys initialized?
	PrivateKeyPtr privkey;
	PublicKeyPtr pubkey;
	AutoSeededRandomPool rng;
};

/*
 *
 *	AES Wrapper
 *
 */

class AESWrapper {
public:
	AESWrapper();
	AESWrapper(const SecVector<byte>& key, const vector<byte>& iv=AESWrapper::defaultiv);

	void Initialize(const SecVector<byte>& key, const vector<byte>& iv=AESWrapper::defaultiv);

	string Encrypt(const string& s);
	void Encrypt(const vector<byte>& in, vector<byte>& out);
	string Decrypt(const string& s);
	void Decrypt(const vector<byte>& in, vector<byte>& out);
	string Decrypt(const vector<byte>& in);

	static void SetDefaultIV(const vector<byte>& iv);

	virtual ~AESWrapper();
private:

	SecVector<byte> key;
	vector<byte> iv;

	static vector<byte> defaultiv;
	static vector<byte> defaultsalt;

	CBC_Mode< AES >::Encryption e;
	CBC_Mode< AES >::Decryption d;
};


/*
 *
 * Crypt tools
 *
 */

string Base64Encode(const vector<byte> &in);
string Base64Encode(const string &s);

string Base64DecodeToString(const string& s);
vector<byte> Base64Decode( const string& data);
void Base64Decode(const string& s, vector<byte>& out);
void Base64Decode(const string& s, SecVector<byte>& out);


extern const vector<byte> defaultsalt;

SecVector<byte> PBKDF2(const SecString& passwd, size_t keylength,
		const vector<byte>& salt = defaultsalt, unsigned int iter=5000);

#if 0
vector<byte> PBKDF2(const string &passwd, size_t keylength,
		const vector<byte>& salt = defaultsalt, unsigned int iter=5000);
#endif

}

#endif // CRYPTOHELPER_H
