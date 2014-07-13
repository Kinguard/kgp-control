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
}

void dologin()
{
	AuthServer s("486d72f5-a346-4cd8-afb9-257d39b95f07");

	string challenge;
	int resultcode;

	DEBUG << "Get Challenge"<<lend;
	tie(resultcode,challenge) = s.GetChallenge();

	if( resultcode != 200 )
	{
		cout << "Unknown reply of server "<<resultcode<<endl;
	}
	cout << "Challenge:\n"<<challenge<<endl;
	DEBUG << "Send signed Challenge"<<lend;

	RSAWrapper c;

	c.LoadPrivKey("privkey.bin");
	c.LoadPubKey("pubkey.bin");

	string signedchallenge = Base64Encode( c.SignMessage( challenge ) );

	Json::Value rep;
	tie(resultcode, rep) = s.SendSignedChallenge( signedchallenge );

	if( resultcode != 200 && resultcode != 403 )
	{
		cout << "Unexpected reply from server "<< resultcode;
	}
	cout << "Result "<<resultcode<<endl;
	cout << "Got "<< rep.toStyledString()<<endl;
	if( resultcode == 403 )
	{
		DEBUG << "Send Secret"<<lend;

		// Got new challenge to encrypt with master
		tie(resultcode, rep) = s.SendSecret(rep["challange"].asString(), Base64Encode(c.PubKeyAsPEM()) );
		cout << "Result "<<resultcode<<endl;
		cout << "Reply "<< rep.toStyledString()<<endl;
	}
	else
	{
		DEBUG << "We should be authed"<<lend;
		cout << "Result "<<resultcode<<endl;
		cout << "Reply "<< rep.toStyledString()<<endl;
	}

}

void ControlApp::Main()
{

	logg << Logger::Debug << "Checking device: "<< STORAGE_DEV <<lend;


	//RSAWrapper rsa;

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
			if( this->Unlock(v["password"].asString() ) )
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
		else if( cmd == "opiname" )
		{

		}
	}

	return this->state ;
}

bool ControlApp::Unlock(const string& pwd)
{
	bool ret = true;
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
		ret = this->RegisterKeys();
	}
	return ret;
}

bool ControlApp::AddUser(string user, string display, string password)
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

bool ControlApp::RegisterKeys()
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

			map<string,string> data;

			data["type"] = "backendkeys";
			data["pubkey"] = Base64Encode(ob.GetPubKeyAsDER());
			data["privkey"] = Base64Encode(ob.GetPrivKeyAsDER());
			s.AppAddIdentifier("op-backend", data);
		}

		//TODO: Fortsätt här....
	}

	catch( runtime_error& err)
	{
		logg << Logger::Notice << "Failed to register keys" << lend;
		return false;
	}
	return true;
}
