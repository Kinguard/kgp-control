#ifndef CONTROLAPP_H
#define CONTROLAPP_H

#include <libutils/Application.h>

#include "LedControl.h"
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
	string opi_name;

	Json::Value connstatus;
	string global_error;

	// Web communication
	Json::Value WebCallback(Json::Value v);
	bool DoUnlock(const string& pwd, bool savepass);
	bool DoInit(const string &pwd, const string &unit_id, bool savepassword );
	bool AddUser(const std::string user, const std::string display, const std::string password);
	bool SetDNSName( const std::string& opiname);
	bool SecopUnlocked();

	// Helper methods
	bool InitializeSD();
	bool RegisterKeys();
	bool GetCertificate(const string& opiname, const string& company="OPI");
	bool GetPasswordUSB();
	bool SetPasswordUSB();
	void WriteConfig();
	static void WriteBackupConfig(const string& password);

	enum Ledstate {
		Error,
		Waiting,
		Completed
	};

	void SetLedstate(enum Ledstate state);

	bool DoLogin();

	WebServerPtr ws;

	LedControl leds;
};

#endif // CONTROLAPP_H
