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
	string unit_id;
	string masterpassword;
	string token;

	string global_error;

	// Web communication
	Json::Value WebCallback(Json::Value v);
	bool DoUnlock(const string& pwd);
	bool DoInit(const string &pwd, const string &unit_id);
	bool AddUser(const std::string user, const std::string display, const std::string password);
	bool SetDNSName( const std::string& opiname);
	bool SecopUnlocked();

	// Helper methods
	bool InitializeSD();
	bool RegisterKeys();
	bool GetCertificate(const string& opiname, const string& company="OPI");
	static void WriteConfig(const string &unit_id);
	static void WriteBackupConfig(const string& password);

	bool DoLogin();

	WebServerPtr ws;
};

#endif // CONTROLAPP_H
