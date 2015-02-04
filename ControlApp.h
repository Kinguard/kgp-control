#ifndef CONTROLAPP_H
#define CONTROLAPP_H

#include <libutils/Application.h>

#include <libopi/LedControl.h>
#include <libopi/BackupHelper.h>
#include "WebServer.h"
#include "EventHandler.h"

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
	string first_user;

	Json::Value connstatus;
	string global_error;

	// Web communication
	Json::Value WebCallback(Json::Value v);
	bool DoUnlock(const string& pwd, bool savepass);
	bool DoInit(const string &unit_id, bool savepassword );
	bool AddUser(const std::string user, const std::string display, const std::string password);
	bool SetDNSName( const std::string& opiname);
	bool SecopUnlocked();

	// Helper methods
	bool InitializeSD();
	bool RegisterKeys();
	string GetBackupPassword();
	bool GetCertificate(const string& opiname, const string& company="OPI");
	bool GetPasswordUSB();
	bool SetPasswordUSB();
	bool GuessOPIName();
	void WriteConfig();
	static void WriteBackupConfig(const string& password);

	// Helpers for restore backup
	Json::Value CheckRestore();
	bool DoRestore(const string& path);
	OPI::BackupHelperPtr backuphelper;
	bool skiprestore; // User opted to not do restore

	enum Ledstate {
		Error,
		Waiting,
		Completed
	};

	void SetLedstate(enum Ledstate state);

	bool DoLogin();

	WebServerPtr ws;

	OPI::LedControl leds;

	EventHandler evhandler;
};

#endif // CONTROLAPP_H
