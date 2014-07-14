#include "ControlApp.h"
#include "Config.h"

#include "Secop.h"
#include "WebServer.h"
#include "DiskHelper.h"
#include "ServiceHelper.h"
#include "CryptoHelper.h"
#include "AuthServer.h"
#include "Luks.h"

#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>

#include <functional>

#include <unistd.h>

using namespace Utils;
using namespace std::placeholders;

using namespace CryptoHelper;

#ifdef OPI_BUILD_LOCAL
#define OPI_MMC_DEV		"sdg"
#define OPI_MMC_PART	"sdg1"
#define STORAGE_DEV		"/dev/sdg"
#define STORAGE_PART	"/dev/sdg1"

#define MOUNTPOINT		"/var/opi/"
#define TMP_MOUNT		"/mnt/opi/"

#define LUKSDEVICE		"/dev/mapper/opi"
#endif

#ifdef OPI_BUILD_PACKAGE
#define OPI_MMC_DEV		"mmcblk0"
#define OPI_MMC_PART	"mmcblk0p1"
#define STORAGE_DEV		"/dev/mmcblk0"
#define STORAGE_PART	"/dev/mmcblk0p1"

#define TMP_MOUNT		"/mnt/opi"
#define MOUNTPOINT		"/var/opi"

#define LUKSDEVICE		"/dev/mapper/opi"
#endif

#define DEBUG (logg << Logger::Debug)

ControlApp::ControlApp() : DaemonApplication("opi-control","/var/run","root","root")
{
}

void ControlApp::Startup()
{
	logg << Logger::Debug << "Starting up!"<< lend;
	Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&ControlApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&ControlApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&ControlApp::SigHup, this, _1) );

	curl_global_init(CURL_GLOBAL_DEFAULT);
}

bool ControlApp::DoLogin(const string& pwd)
{
	AuthServer s( this->unit_id);

	string challenge;
	int resultcode;

	DEBUG << "Get Challenge"<<lend;
	tie(resultcode,challenge) = s.GetChallenge();

	if( resultcode != 200 )
	{
		logg << Logger::Error << "Unknown reply of server "<<resultcode<< lend;
		return false;
	}
#if 0
	cout << "Challenge:\n"<<challenge<<endl;
	DEBUG << "Send signed Challenge"<<lend;
#endif
	RSAWrapper c;

	Secop secop;
	secop.SockAuth();

	list<map<string,string>> ids =  secop.AppGetIdentifiers("op-backend");

	if( ids.size() == 0 )
	{
		logg << Logger::Error << "Failed to get keys from secop"<<lend;
		return false;
	}

	bool found = false;
	for(auto id : ids )
	{
		if( id.find("type") != id.end() )
		{
			if( id["type"] == "backendkeys" )
			{
				// Key found
				c.LoadPrivKeyFromDER( Base64Decode( id["privkey"]) );
				c.LoadPubKeyFromDER( Base64Decode( id["pubkey"]) );
				found = true;
				break;
			}
		}
	}

	if( ! found )
	{
		logg << Logger::Error << "failed to load keys from secop"<<lend;
		return false;
	}

	string signedchallenge = Base64Encode( c.SignMessage( challenge ) );

	Json::Value rep;
	tie(resultcode, rep) = s.SendSignedChallenge( signedchallenge );

	if( resultcode != 200 && resultcode != 403 )
	{
		logg << Logger::Error << "Unexpected reply from server "<< resultcode <<lend;
		return false;
	}

	if( resultcode == 403 )
	{
		DEBUG << "Send Secret"<<lend;

		// Got new challenge to encrypt with master
		string challenge = rep["challange"].asString();

		SecVector<byte> key = PBKDF2(SecString(pwd.c_str(), pwd.size() ), 32 );

		//SecVector<byte> key(pwd.begin(), pwd.end() );
		AESWrapper aes( key );

		string cryptchal = Base64Encode( aes.Encrypt( challenge ) );

		tie(resultcode, rep) = s.SendSecret(cryptchal, Base64Encode(c.PubKeyAsPEM()) );
		if( resultcode != 200 )
		{
			cout << "Result "<<resultcode<<endl;
			cout << "Reply "<< rep.toStyledString()<<endl;

		}

		DEBUG << "Send secret succeded"<<lend;
		if( rep.isMember("token") && rep["token"].isString() )
		{
			this->token = rep["token"].asString();
		}
		else
		{
			logg << Logger::Error << "Missing argument in reply"<<lend;
			return false;
		}

	}
	else
	{
#if 0
		DEBUG << "We should be authed"<<lend;
		cout << "Result "<<resultcode<<endl;
		cout << "Reply "<< rep.toStyledString()<<endl;
#endif
		if( rep.isMember("token") && rep["token"].isString() )
		{
			this->token = rep["token"].asString();
		}
		else
		{
			logg << Logger::Error << "Missing argument in reply"<<lend;
			return false;
		}
	}

	return true;
}

void ControlApp::Main()
{

	logg << Logger::Debug << "Checking device: "<< STORAGE_DEV <<lend;

	this->state = 3;

	// Preconditions
	// Secop should not be running
	if( ServiceHelper::IsRunning("secop") )
	{
		logg << Logger::Debug << "Stop running secop instance"<<lend;
		ServiceHelper::Stop("secop");
	}
	// Temp mountpoint must exist
	if( !File::DirExists(TMP_MOUNT) )
	{
		File::MkPath(TMP_MOUNT, 0755);
	}


	// Check environment
	if( ! DiskHelper::DeviceExists( STORAGE_DEV ) )
	{
		logg << Logger::Error << "Device not present"<<lend;
		this->state = 2;
	}
	else if( DiskHelper::DeviceSize( OPI_MMC_DEV ) == 0 )
	{
		logg << Logger::Error << "No space on device"<< lend;
		this->state = 2;
	}

	this->ws = WebServerPtr( new WebServer( this->state, std::bind(&ControlApp::WebCallback,this, _1)) );

	this->ws->Start();

	this->ws->Join();
}

void ControlApp::ShutDown()
{
	ServiceHelper::Stop("secop");
#if 0
	DiskHelper::Umount("/var/opi");
	Luks( STORAGE_PART).Close("opi");
#endif
	curl_global_cleanup();
	logg << Logger::Debug << "Shutting down"<< lend;
}

void ControlApp::SigTerm(int signo)
{
	// Possibly shutdown webserver
	if( this->ws != nullptr )
	{
		this->ws->Stop();
	}

}

void ControlApp::SigHup(int signo)
{

}

ControlApp::~ControlApp()
{

}

int ControlApp::WebCallback(Json::Value v)
{

	logg << Logger::Debug << "Got call from webserver\n"<<v.toStyledString()<<lend;

	if( v.isMember("cmd") )
	{
		string cmd = v["cmd"].asString();
		if( cmd == "init" )
		{
			if( this->Unlock(v["password"].asString(), v["unit_id"].asString() ) )
			{
				this->state = 4;
			}
			else
			{
				this->state = 3;
			}
		}
		else if( cmd == "adduser" )
		{

			if( this->AddUser(v["username"].asString(), v["displayname"].asString(), v["password"].asString() ) )
			{
				this->state = 5;
			}
			else
			{
				this->state = 4;
			}
		}
	}

	return this->state ;
}

bool ControlApp::Unlock(const string& pwd, const string& unit_id)
{
	bool ret = true;

	this->unit_id = unit_id;
	this->InitializeSD(pwd);

	if( ! ServiceHelper::IsRunning("secop") )
	{
		logg << Logger::Debug << "Starting Secop server"<<lend;
		if( ! ServiceHelper::Start("secop") )
		{
			logg << Logger::Notice << "Failed to start secop"<<lend;
		}
		else
		{
			// Give daemon time to start.
			sleep(1);
		}
	}

	try{
		if( this->SecopUnlocked())
		{
			return true;
		}

		logg << Logger::Debug << "Trying to unlock secop"<<lend;

		ret = Secop().Init(pwd);
	}
	catch(std::runtime_error err)
	{
		logg << Logger::Error << "Failed to unlock Secop:"<<err.what()<<lend;
		return false;
	}

	if( ret )
	{
		ret = this->RegisterKeys(pwd, unit_id);
	}

	if( ret)
	{
		for( int i=0; i<3; i++ )
		{
			try
			{
				ret = this->DoLogin(pwd);
				if( ret )
				{
					break;
				}
			}
			catch(runtime_error& err )
			{
				logg << Logger::Notice << "Failed to login to backend: "<< err.what()<<lend;
				ret = false;
			}
		}
	}

	return ret;
}

bool ControlApp::AddUser(const string user, const string display, const string password)
{
	logg << "Add user "<<user<<" "<< display<< " " << password << lend;

	if(! this->SecopUnlocked() )
	{
		return false;
	}

	Secop s;
	s.SockAuth();

	return s.CreateUser(user, password);
}

bool ControlApp::SecopUnlocked()
{
	Secop::State st = Secop::Unknown;
	try
	{
		Secop s;

		st  = s.Status();
	}
	catch( runtime_error& e)
	{
		logg << Logger::Notice << "Failed to check status "<<e.what()<<lend;
	}

	logg << Logger::Debug << "Secop status : "<< st << lend;

	return (st != Secop::Uninitialized) && (st != Secop::Unknown);
}

bool ControlApp::InitializeSD(const string &password)
{
	logg << Logger::Debug << "Initialize sd card"<<lend;
	bool sd_isnew = false;
	if( ! Luks::isLuks( OPI_MMC_PART ) )
	{
		logg << Logger::Notice << "No Luks volume on device, "<< STORAGE_PART<<", creating"<<lend;

		DiskHelper::PartitionDevice( STORAGE_DEV );
		Luks l( STORAGE_PART);
		l.Format(password);

		if( ! l.Open("opi",password) )
		{
			return false;
		}

		DiskHelper::FormatPartition( LUKSDEVICE,"OPI");
		sd_isnew = true;
	}
	else
	{
		logg << Logger::Notice << "LUKS volume found on "<<STORAGE_PART<< lend;

		Luks l( STORAGE_PART);

		if( ! l.Active("opi") )
		{
			logg << Logger::Debug << "Activating LUKS volume"<<lend;
			if ( !l.Open("opi",password) )
			{
				return false;
			}
		}
	}

	// Make sure device is not mounted (Should not happen)
	if( DiskHelper::IsMounted( LUKSDEVICE ) != "" )
	{
		DiskHelper::Umount( LUKSDEVICE );
	}

	if( sd_isnew )
	{
		logg << Logger::Debug << "Sync mmc to SD"<<lend;
		// Sync data from emmc to sd
		DiskHelper::Mount( LUKSDEVICE , TMP_MOUNT );

		DiskHelper::SyncPaths(MOUNTPOINT, TMP_MOUNT);

		DiskHelper::Umount(LUKSDEVICE);
	}

	// Mount in final place
	DiskHelper::Mount( LUKSDEVICE , MOUNTPOINT );

	return true;
}

bool ControlApp::RegisterKeys(const string& password, const string& unit_id)
{
	logg << Logger::Debug << "Register keys"<<lend;
	try{
		Secop s;

		s.SockAuth();
		list<map<string,string>> ids = s.AppGetIdentifiers("op-backend");

		if( ids.size() == 0 )
		{
			logg << Logger::Debug << "No keys in secop" << lend;
			s.AppAddID("op-backend");

			RSAWrapper ob;
			ob.GenerateKeys();

			// Write to disk
			string priv_path = File::GetPath( SYS_PRIV_PATH );
			if( ! File::DirExists( priv_path ) )
			{
				File::MkPath( priv_path, 0755);
			}

			string pub_path = File::GetPath( SYS_PUB_PATH );
			if( ! File::DirExists( pub_path ) )
			{
				File::MkPath( pub_path, 0755);
			}

			File::Write(SYS_PRIV_PATH, ob.PrivKeyAsPEM(), 0600 );
			File::Write(SYS_PUB_PATH, ob.PubKeyAsPEM(), 0644 );

			// Write to secop
			map<string,string> data;

			data["type"] = "backendkeys";
			data["pubkey"] = Base64Encode(ob.GetPubKeyAsDER());
			data["privkey"] = Base64Encode(ob.GetPrivKeyAsDER());
			s.AppAddIdentifier("op-backend", data);
		}

		string priv_path = File::GetPath( DNS_PRIV_PATH );
		if( ! File::DirExists( priv_path ) )
		{
			File::MkPath( priv_path, 0755);
		}

		string pub_path = File::GetPath( DNS_PUB_PATH );
		if( ! File::DirExists( pub_path ) )
		{
			File::MkPath( pub_path, 0755);
		}

		if( ! File::FileExists( DNS_PRIV_PATH) || ! File::FileExists( DNS_PUB_PATH ) )
		{
			RSAWrapper dns;
			dns.GenerateKeys();

			File::Write(DNS_PRIV_PATH, dns.PrivKeyAsPEM(), 0600 );
			File::Write(DNS_PUB_PATH, dns.PubKeyAsPEM(), 0644 );
		}

		SecString spass(password.c_str(), password.size() );
		SecVector<byte> key = PBKDF2( spass, 20);
		vector<byte> ukey(key.begin(), key.end());

		string  backuppass = Base64Encode( ukey );

		ControlApp::WriteBackupConfig(backuppass);

		ControlApp::WriteConfig(unit_id);
	}

	catch( runtime_error& err)
	{
		logg << Logger::Notice << "Failed to register keys " << err.what() << lend;
		return false;
	}
	return true;
}

void ControlApp::WriteConfig(const string& unit_id)
{
	string path = File::GetPath( SYSCONFIG_PATH );

	if( ! File::DirExists( path ) )
	{
		File::MkPath( path, 0755 );
	}

	ConfigFile c( SYSCONFIG_PATH );

	c["dns_pubkey"] = DNS_PUB_PATH;
	c["dns_privkey"] = DNS_PRIV_PATH;
	c["sys_pubkey"] = SYS_PUB_PATH;
	c["sys_privkey"] = SYS_PRIV_PATH;
	c["ca_path"] = "/etc/opi/op_ca.pem";
	c["unit_id"] = unit_id;

	c.Sync(true, 0644);

}


void ControlApp::WriteBackupConfig(const string &password)
{
	string path = File::GetPath( BACKUP_PATH );

	if( ! File::DirExists( path ) )
	{
		File::MkPath( path ,0755);
	}

	stringstream ss;
	ss << "[s3op]\n"
		<< "storage-url: s3op://storage.openproducts.com/\n"
		<< "backend-login: NotUsed\n"
		<< "backend-password: NotUsed\n"
		<< "fs-passphrase: " << password<<endl;

	File::Write(BACKUP_PATH, ss.str(), 0600 );
}
