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
	void Unlock(std::string pwd);
	bool SecopUnlocked();
	WebServerPtr ws;
};

#endif // CONTROLAPP_H
