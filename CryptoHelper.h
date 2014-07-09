#ifndef CRYPTOHELPER_H
#define CRYPTOHELPER_H

#include <memory>
#include <string>

#include <crypto++/rsa.h>
#include <crypto++/osrng.h>

using namespace CryptoPP;
using namespace std;

typedef std::shared_ptr<RSA::PublicKey> PublicKeyPtr;
typedef std::shared_ptr<RSA::PrivateKey> PrivateKeyPtr;

class CryptoHelper
{
public:
	CryptoHelper();

	void GenerateKeys(unsigned int size=3072);

	void LoadPrivKey(const string& path);
	void LoadPubKey(const string& path);

	void SavePrivKey(const string& path, mode_t mask = 0077);
	void SavePubKey(const string& path, mode_t mask = 0002);

	string PubKeyAsPEM();
	string PrivKeyAsPEM();

	vector<byte> SignMessage(const string& message);
	bool VerifyMessage(const string& message, const string &signature);
	bool VerifyMessage(const string &message, const vector<byte>& signature);

	string Base64Encode(const vector<byte> &in);
	string Base64Encode(const string &s);
private:
	void ValidatePrivKey();
	void ValidatePubKey();
	bool priv_i, pub_i; // Keys initialized?
	PrivateKeyPtr privkey;
	PublicKeyPtr pubkey;
	AutoSeededRandomPool rng;
};

#endif // CRYPTOHELPER_H
