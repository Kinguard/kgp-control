#ifndef CONTROLAPP_H
#define CONTROLAPP_H

#include <libutils/Application.h>
#include <libutils/Thread.h>

#include <libopi/BackupHelper.h>
#include "WebServer.h"
#include "EventHandler.h"
#include "ControlState.h"

#include <memory>

typedef shared_ptr<Utils::Thread> ThreadPtr;

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

	// User value cache for state
	map<uint16_t, Json::Value> cache;

	// Web communication
	Json::Value WebCallback(Json::Value v);
	bool DoUnlock(const string& pwd, bool savepass);
	bool DoInit(bool savepassword );
	bool AddUser(const std::string user, const std::string display, const std::string password);
	bool SetDNSName();
	bool SetDNSName(const std::string& opiname, const string &domain);
	bool SecopUnlocked();

	// Helper methods
	bool InitializeSD();
	bool RegisterKeys();
	string GetBackupPassword();
	bool GetCertificate(const string& opiname, const string& company="OPI");
	bool GetSignedCert(const string& opiname);
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

	void StopWebserver();
	ThreadPtr signerthread; // Used by letsencrypt signer thread
};

#endif // CONTROLAPP_H
