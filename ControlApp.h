#ifndef CONTROLAPP_H
#define CONTROLAPP_H

#include <libutils/Application.h>
#include <libutils/Mutex.h>

#include <libopi/BackupHelper.h>
#include "WebServer.h"
#include "EventHandler.h"
#include "ControlState.h"

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

	friend class ControlState;
private:
	int state;
	string unit_id;
	string masterpassword;
	string token;
	string opi_name;
	string domain;
	string first_user;

	Json::Value connstatus;
	string global_error;

	// Web communication
	Json::Value WebCallback(Json::Value v);
	bool DoUnlock(const string& pwd, bool savepass);
	bool DoInit(bool savepassword );
	bool AddUser(const std::string user, const std::string display, const std::string password);
	bool SetDNSName( const std::string& opiname);
	bool SecopUnlocked();

	// Helper methods
	bool InitializeSD();
	bool RegisterKeys();
	string GetBackupPassword();
	bool GetCertificate(const string& opiname, const string& company="OPI");
	bool GetPasswordUSB();
	bool GetPasswordRoot();
	bool SetPasswordUSB();
	bool SetPasswordRoot();
	bool GuessOPIName();
	void WriteConfig();
	static void WriteBackupConfig(const string& password);

	// Helpers for restore backup
	bool SetupRestoreEnv();
	Json::Value CheckRestore();
	void CleanupRestoreEnv();
	bool DoRestore(const string& path);
	OPI::BackupHelperPtr backuphelper;
	bool skiprestore; // User opted to not do restore

	enum Ledstate {
		Error,
		Waiting,
		Completed
	};

	bool DoLogin();

	WebServerPtr ws;
	ControlStatePtr statemachine;

	EventHandler evhandler;
};

#endif // CONTROLAPP_H
