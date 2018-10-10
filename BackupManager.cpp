#include "BackupManager.h"

#include <libutils/Logger.h>
#include <libutils/FileUtils.h>

#include <libopi/SysConfig.h>
#include <libopi/AuthServer.h>
#include <libopi/CryptoHelper.h>

#include "StorageManager.h"

#define TMP_PRIV "/tmp/tmpkey.priv"
#define TMP_PUB "/tmp/tmpkey.pub"

#define TMP_MOUNT		"/mnt/opi/"

// Convenience defines
#define SCFG	(OPI::SysConfig())

using namespace Utils;
using namespace OPI;
using namespace OPI::CryptoHelper;

BackupManager::BackupManager(): opprovider(false),hasunitid(false),cfg(Json::nullValue)
{
	this->opprovider = ( SCFG.HasKey("dns", "provider") && SCFG.GetKeyAsString("dns", "provider") == "OpenProducts" );

	if( SCFG.HasKey("hostinfo", "unitid") )
	{
		this->hasunitid = true;
		this->unitid = SCFG.GetKeyAsString("hostinfo", "unitid");
	}
}

BackupManager &BackupManager::Instance()
{
	static BackupManager mgr;

	return mgr;
}

void BackupManager::Configure(const Json::Value &cfg)
{
	if( !cfg.isMember("password") || !cfg["password"].isString() )
	{
		throw std::runtime_error("Missing password in backup config");
	}

	BackupManager::Instance().SetConfig(cfg);
}

Json::Value BackupManager::GetBackups()
{
	if( ! this->backuphelper )
	{
		// Make sure we have no leftovers from earlier attempts
		this->CleanupRestoreEnv();

		if( ! this->SetupRestoreEnv() )
		{
			logg << Logger::Error << "Failed to set up restore environment"<<lend;
			return Json::nullValue;
		}
		this->backuphelper = BackupHelperPtr( new BackupHelper( this->cfg["password"].asString() ) );
	}
	else
	{
		// Entered password might have been changed
		this->backuphelper->SetPassword( this->cfg["password"].asString() );
	}

	Json::Value retval;
	bool hasdata = false;
	// Check local
	if( this->backuphelper->MountLocal() )
	{
		list<string> local = this->backuphelper->GetLocalBackups();
		for( const auto& val: local)
		{
			hasdata = true;
			retval["local"].append(val);
		}

		this->backuphelper->UmountLocal();
	}
	else
	{
		logg << Logger::Debug << "Mount local failed" << lend;
	}

	// Check remote if OP unit
	if( this->opprovider )
	{
		if( this->backuphelper->MountRemote() )
		{
			list<string> remote = this->backuphelper->GetRemoteBackups();
			for( const auto& val: remote)
			{
				hasdata = true;
				retval["remote"].append(val);
			}
			this->backuphelper->UmountRemote();
		}
		else
		{
			logg << Logger::Debug << "Mount remote failed" << lend;
		}
	}
	else
	{
		logg << Logger::Debug << "Not checking remote backup since none OP unit" << lend;
	}

	if( ! hasdata )
	{
		logg << Logger::Debug << "Clean up restore env since no data available"<<lend;
		this->CleanupRestoreEnv();
	}

	return hasdata ? retval : Json::nullValue ;
}

bool BackupManager::RestoreBackup(const string &backup, const string &targetpath)
{
	// Currently unused
	(void) targetpath;
	StorageManager& mgr=StorageManager::Instance();
	if( ! mgr.mountDevice( TMP_MOUNT ) )
	{
		logg << Logger::Error << "Failed to mount SD for backup: "<< mgr.Error()<<lend;
		this->global_error = "Restore backup - Failed to access SD card";
		return false;
	}

// Temp workaround to figure out if this is a local or remote backup
// Todo: Refactor in libopi
#define LOCALBACKUP	"/tmp/localbackup"
#define REMOTEBACKUP "/tmp/remotebackup"

	if( backup.substr(0,strlen(LOCALBACKUP) ) == LOCALBACKUP )
	{
		logg << Logger::Debug << "Do restore from local backup "<< backup << lend;
		if( ! this->backuphelper->MountLocal() )
		{
			logg << Logger::Error << "Failed to (re)mount local backup" << lend;
			this->global_error = "Restore backup - failed to retrieve local backup";
			return false;
		}
	}
	else if( backup.substr(0, strlen(REMOTEBACKUP)) == REMOTEBACKUP )
	{
		logg << Logger::Debug << "Do restore from remote backup "<< backup << lend;
		if( ! this->backuphelper->MountRemote() )
		{
			logg << Logger::Error << "Failed to (re)mount remote backup" << lend;
			this->global_error = "Restore backup - failed to retrieve remote backup";
			return false;
		}
	}
	else
	{
		logg << Logger::Error << "Malformed restore path: " << backup << lend;
		this->global_error = "Restore backup - Malformed source path" ;
		return false;
	}

	if( !this->backuphelper->RestoreBackup( backup ) )
	{
		StorageManager::umountDevice();
		this->global_error = "Restore Backup - restore failed";
		return false;
	}

	try
	{
		StorageManager::umountDevice();
	}
	catch( ErrnoException& err)
	{
		logg << Logger::Error << "Failed to umount SD after backup: "<< err.what()<<lend;
		this->global_error = "Restore backup - Failed to remove SD card";
		return false;
	}

	logg << Logger::Debug << "Restore completed sucessfully"<<lend;

	return true;
}

BackupManager::~BackupManager()
{
	this->CleanupRestoreEnv();
}

void BackupManager::CleanupRestoreEnv()
{
	logg << Logger::Debug << "Clean up restore environment"<<lend;

	if( ! this->opprovider )
	{
		logg << Logger::Notice << "None OP system, nothing to do" << lend;
		return;
	}

	string sysauthkey = SCFG.GetKeyAsString("hostinfo","sysauthkey");
	string syspubkey = SCFG.GetKeyAsString("hostinfo","syspubkey");

	if( this->backuphelper )
	{
		this->backuphelper->UmountLocal();
		this->backuphelper->UmountRemote();
	}

	if( File::LinkExists( sysauthkey ) )
	{
		unlink( sysauthkey.c_str() );
	}

	if( File::LinkExists( syspubkey ) )
	{
		unlink( syspubkey.c_str() );
	}

	unlink( TMP_PRIV );
	unlink( TMP_PUB );
}

bool BackupManager::SetupRestoreEnv()
{
	logg << Logger::Debug << "Setting up environment for restore"<<lend;

	if( ! this->opprovider )
	{
		logg << Logger::Notice << "None OP system, nothing to do" << lend;
		return true;
	}

	// Make sure we have environment to work from.
	// TODO: Lot of duplicated code here :(
	// Generate temporary keys to use
	RSAWrapper ob;
	ob.GenerateKeys();

#define TMP_PRIV "/tmp/tmpkey.priv"
#define TMP_PUB "/tmp/tmpkey.pub"

	string sysauthkey = SCFG.GetKeyAsString("hostinfo","sysauthkey");
	string syspubkey = SCFG.GetKeyAsString("hostinfo","syspubkey");


	// Write to disk
	string priv_path = File::GetPath( TMP_PRIV );
	if( ! File::DirExists( priv_path ) )
	{
		File::MkPath( priv_path, 0755);
	}

	string pub_path = File::GetPath( TMP_PUB );
	if( ! File::DirExists( pub_path ) )
	{
		File::MkPath( pub_path, 0755);
	}

	File::Write(TMP_PRIV, ob.PrivKeyAsPEM(), 0600 );
	File::Write(TMP_PUB, ob.PubKeyAsPEM(), 0644 );

	// Remove possible old keys
	unlink( sysauthkey.c_str() );
	unlink( syspubkey.c_str() );

	if( symlink( TMP_PRIV , sysauthkey.c_str() ) )
	{
		unlink( TMP_PRIV );
		unlink( TMP_PUB );
		logg << Logger::Notice << "Failed to symlink private key"<<lend;
		return false;
	}

	if( symlink( TMP_PUB , syspubkey.c_str() ) )
	{
		unlink( sysauthkey.c_str() );
		unlink( TMP_PRIV );
		unlink( TMP_PUB );
		logg << Logger::Notice << "Failed to symlink public key"<<lend;
		return false;
	}

	AuthServer s(this->unitid);

	string challenge;
	int resultcode;
	tie(resultcode,challenge) = s.GetChallenge();

	if( resultcode != 200 )
	{
		unlink( sysauthkey.c_str() );
		unlink( syspubkey.c_str() );
		unlink( TMP_PRIV );
		unlink( TMP_PUB );
		logg << Logger::Notice << "Failed to get challenge " << resultcode <<lend;
		return false;
	}

	string signedchal = CryptoHelper::Base64Encode( ob.SignMessage( challenge ) );
	Json::Value ret;
	tie(resultcode, ret) = s.SendSignedChallenge( signedchal );

	if( resultcode != 403 )
	{
		unlink( sysauthkey.c_str() );
		unlink( syspubkey.c_str() );
		unlink( TMP_PRIV );
		unlink( TMP_PUB );
		logg << Logger::Notice << "Failed to send challenge " << resultcode <<lend;
		return false;
	}

	challenge = ret["challange"].asString();

	vector<byte> tkey = Base64Decode( this->cfg["password"].asString() );
	SecVector<byte> key(tkey.begin(), tkey.end() );

	AESWrapper aes( key );

	string cryptchal = Base64Encode( aes.Encrypt( challenge ) );

	tie(resultcode, ret) = s.SendSecret(cryptchal, Base64Encode( ob.PubKeyAsPEM() ) );

	if( resultcode != 200 )
	{
		unlink( sysauthkey.c_str() );
		unlink( syspubkey.c_str() );
		unlink( TMP_PRIV );
		unlink( TMP_PUB );
		logg << Logger::Notice << "Failed to send secret ("
			 << resultcode
			 << ") '" << ret["Message"].asString()<<"'"
			 <<lend;
		logg << "Response : "<< ret.toStyledString()<<lend;
		return false;
	}

	return true;

}

void BackupManager::SetConfig(const Json::Value &cfg)
{
	this->cfg = cfg;
	this->WriteConfig();
}

void BackupManager::WriteConfig()
{
	string authfile = SCFG.GetKeyAsString("backup","authfile");
	string path = File::GetPath( authfile );

	if( ! File::DirExists( path ) )
	{
		File::MkPath( path ,0755);
	}

	stringstream ss;
	ss << "[s3op]\n"
		<< "storage-url: s3op://\n"
		<< "backend-login: NotUsed\n"
		<< "backend-password: NotUsed\n"
		<< "fs-passphrase: " << this->cfg["password"].asString() <<"\n\n"

		<< "[local]\n"
		<< "storage-url: local://\n"
		<< "fs-passphrase: " << this->cfg["password"].asString() <<endl

		<< "[s3]\n"
		<< "storage-url: s3://\n"
		<< "fs-passphrase: " << this->cfg["password"].asString() <<endl;


	File::Write(authfile, ss.str(), 0600 );
}
