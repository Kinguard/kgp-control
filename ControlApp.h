#ifndef CONTROLAPP_H
#define CONTROLAPP_H

#include <libutils/Application.h>

class ControlApp;

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
	bool Unlock(std::string pwd);
	bool SecopUnlocked();
	WebServerPtr ws;
};

#endif // CONTROLAPP_H
