#ifndef LUKS_H
#define LUKS_H

#include <libcryptsetup.h>

#include <string>

using namespace std;

class Luks
{
public:
	Luks(const string& path);

	static bool isLuks(const string& device);

	void Format(const string& password);
	bool Open(const string& name, const string& password, bool discard = true );
	bool Active(const string& name);
	void Close(const string name="");

	virtual ~Luks();
private:
	string path;
	string name;
	bool open;
	struct crypt_device *cryptdevice;
};

#endif // LUKS_H
