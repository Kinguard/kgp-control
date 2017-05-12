#ifndef PWDCTRLAPP_H
#define PWDCTRLAPP_H

#include <libutils/Application.h>

class PwdCtrlApp: public Utils::Application
{
public:
	PwdCtrlApp();

	virtual void Startup();
	virtual void Main();

	virtual ~PwdCtrlApp();
private:

	void ReadPassword( const string& path );

	string password;
	string path;
};

#endif // PWDCTRLAPP_H
