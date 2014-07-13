#ifndef CONTROLAPP_H
#define CONTROLAPP_H

#include <libutils/Application.h>

#include "WebServer.h"

class ControlApp : public Utils::DaemonApplication
{
public:
	ControlApp();

	virtual void Startup();
	virtual void Main();
	virtual void ShutDown();

	void SigTerm(int signo);
	void SigHup(int signo);

	virtual ~ControlApp();
private:
	int state;
	int WebCallback(Json::Value v);
	bool Unlock(const string &pwd);
	bool AddUser(std::string user, std::string display, std::string password);
	bool SecopUnlocked();

	bool InitializeSD(const string& password);
	bool RegisterKeys();

	WebServerPtr ws;
};

#endif // CONTROLAPP_H
