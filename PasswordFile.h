#ifndef PASSWORDFILE_H
#define PASSWORDFILE_H

#include <string>

using namespace std;

namespace PasswordFile
{
	string Read(const string& path);
	void Write(const string& path, const string& password);
}

#endif // PASSWORDFILE_H
