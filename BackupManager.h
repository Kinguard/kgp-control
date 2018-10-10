#ifndef BACKUPMANAGER_H
#define BACKUPMANAGER_H

#include "BaseManager.h"

#include <libopi/BackupHelper.h>
#include <libutils/ClassTools.h>

#include <string>

#include <json/json.h>

using namespace std;

// Behöver troligen master password och ev unit-id
// bör baseras på sysconfig

// TODO: most likely should reside in libopi

class BackupManager: public BaseManager
{
private:
	BackupManager();
public:
	static BackupManager& Instance();

	/**
	 * @brief Configure, set current configuration for backup
	 * @param cfg json value with configuration.
	 *
	 * @example currently backup password is required
	 *
	 * { "password" : "secret backup password" }
	 *
	 */
	static void Configure(const Json::Value& cfg);

	/**
	 * @brief GetBackups
	 * @return Json:object with keys as sources and each key with list of backups
	 *
	 * @example { "local": ("2012-02-13","2012-04-05"), "remote" : ("date1", "date2")
	 */
	Json::Value GetBackups();


	/**
	 * @brief RestoreBackup restore a backup to target path
	 * @param backup Which backup to restore
	 * @param targetpath Where to restore backup (Currently unused, implied)
	 * @return status of operation
	 */
	bool RestoreBackup(const string& backup, const string& targetpath = "");


	virtual ~BackupManager();

private:
	void CleanupRestoreEnv();

	bool SetupRestoreEnv();

	/**
	 * @brief SetConfig
	 * @param cfg configuration to use from now on
	 */
	void SetConfig(const Json::Value& cfg);

	/**
	 * @brief WriteConfig writes config to disk
	 */
	void WriteConfig();

	bool opprovider;
	bool hasunitid;
	string unitid;
	Json::Value cfg;
	OPI::BackupHelperPtr backuphelper;
};

#endif // BACKUPMANAGER_H
