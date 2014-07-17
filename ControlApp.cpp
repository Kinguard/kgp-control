#include "ControlApp.h"
#include "Config.h"

#include "Secop.h"
#include "WebServer.h"
#include "DiskHelper.h"
#include "ServiceHelper.h"
#include "CryptoHelper.h"
#include "AuthServer.h"
#include "DnsServer.h"
#include "InboundTest.h"
#include "ConnTest.h"
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

bool ControlApp::DoLogin()
{
	AuthServer s( this->unit_id);

	RSAWrapper c;

	Secop secop;
	secop.SockAuth();

	list<map<string,string>> ids =  secop.AppGetIdentifiers("op-backend");

	if( ids.size() == 0 )
	{
		logg << Logger::Error << "Failed to get keys from secop"<<lend;
		this->global_error ="Failed to retrieve krypto keys";
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
		this->global_error ="Failed to load krypto keys";
		return false;
	}

	string challenge;
	int resultcode;

	tie(resultcode,challenge) = s.GetChallenge();

	if( resultcode != 200 )
	{
		logg << Logger::Error << "Unknown reply of server "<<resultcode<< lend;
		this->global_error ="Failed to connect with OP server";
		return false;
	}


	string signedchallenge = Base64Encode( c.SignMessage( challenge ) );

	Json::Value rep;
	tie(resultcode, rep) = s.SendSignedChallenge( signedchallenge );

	if( resultcode != 200 && resultcode != 403 )
	{
		logg << Logger::Error << "Unexpected reply from server "<< resultcode <<lend;
		this->global_error ="Unexpected reply from OP server";
		return false;
	}

	if( resultcode == 403 )
	{
		DEBUG << "Send Secret"<<lend;

		// Got new challenge to encrypt with master
		string challenge = rep["challange"].asString();

		SecVector<byte> key = PBKDF2(SecString(this->masterpassword.c_str(), this->masterpassword.size() ), 32 );

		AESWrapper aes( key );

		string cryptchal = Base64Encode( aes.Encrypt( challenge ) );

		tie(resultcode, rep) = s.SendSecret(cryptchal, Base64Encode(c.PubKeyAsPEM()) );
		if( resultcode != 200 )
		{
			this->global_error ="Failed to communicate with OP server";
			return false;
		}

		if( rep.isMember("token") && rep["token"].isString() )
		{
			this->token = rep["token"].asString();
		}
		else
		{
			logg << Logger::Error << "Missing argument in reply"<<lend;
			this->global_error ="Failed to communicate with OP server (Missing argument)";
			return false;
		}

	}
	else
	{
		if( rep.isMember("token") && rep["token"].isString() )
		{
			this->token = rep["token"].asString();
		}
		else
		{
			this->global_error ="Missing argument in reply from OP server";
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

	if( File::FileExists(SYSCONFIG_PATH))
	{
		ConfigFile c(SYSCONFIG_PATH);

		string unit_id = c.ValueOrDefault("unit_id");

		if( unit_id != "" )
		{
			this->state = 6;
			this->unit_id = unit_id;
		}

	}

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

	// We have a valid config and a device but device is not a luks container
	if( this->state == 6 && ! Luks::isLuks( OPI_MMC_PART ) )
	{
		logg << Logger::Debug << "Config correct but no luksdevice do initialization"<<lend;
		this->state = 9;
	}

	InboundTestPtr ibt;

	if( this->state == 3 )
	{
		logg << Logger::Debug << "Starting inbound connection tests"<<lend;
		ibt = InboundTestPtr(new InboundTest( {25,80,143, 993 }));
		ibt->Start();

		logg << Logger::Debug << "Doing connection tests"<<lend;
		ConnTest ct;
		this->connstatus = ct.DoTest();
	}

	this->ws = WebServerPtr( new WebServer( this->state, std::bind(&ControlApp::WebCallback,this, _1)) );

	this->ws->Start();

	this->ws->Join();

	if( ibt )
	{
		logg << Logger::Debug << "Stopping inbound connection tests"<<lend;
		ibt->Stop();
	}

	if( this->state == 7 )
	{
		// We should have reached a positive end of init, start services
		logg << Logger::Debug << "Init completed, start servers"<<lend;
		ServiceHelper::Start( "nginx" );
		ServiceHelper::Start( "opi-authproxy" );
	}

	logg << Logger::Debug << "OPI control finnished " <<lend;
}

void ControlApp::ShutDown()
{
#if 0
	ServiceHelper::Stop("secop");
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

Json::Value ControlApp::WebCallback(Json::Value v)
{

#if 0
	logg << Logger::Debug << "Got call from webserver\n"<<v.toStyledString()<<lend;
#endif

	Json::Value ret;
	bool status = true;
	if( v.isMember("cmd") )
	{
		string cmd = v["cmd"].asString();
		if( cmd == "init" )
		{
			if( this->DoInit(v["password"].asString(), v["unit_id"].asString() ) )
			{
				this->state = 4;
			}
			else
			{
				status = false;
				this->state = 3;
			}
		}
		else if( cmd == "reinit" )
		{
			if( this->DoInit(v["password"].asString(), this->unit_id ) )
			{
				this->state = 4;
			}
			else
			{
				status = false;
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
				status = false;
				this->state = 4;
			}
		}
		else if( cmd == "opiname" )
		{
			if( this->SetDNSName(v["opiname"].asString() ) )
			{
				this->state = 7;
			}
			else
			{
				status = false;
				this->state = 5;
			}
		}
		else if( cmd == "unlock" )
		{
			if( this->DoUnlock(v["password"].asString() ) )
			{
				this->state = 7;
			}
			else
			{
				status = false;
				this->state = 6;
			}
		}
		else if( cmd == "shutdown" )
		{
			if( v["shutdown"].asBool() && this->state == 7 )
			{
				this->ws->Stop();
			}
			else
			{
				status = false;
				this->global_error = "Wrong state for request";
			}
		}
		else if( cmd == "portstatus" )
		{
			return this->connstatus;
		}
		else
		{
			status = false;
			this->global_error = "Unknown command";
		}
	}
	ret["status"]=status;
	if(!status)
	{
		ret["errmsg"]=this->global_error;
	}
	ret["state"]=state;
	return ret;
}

bool ControlApp::DoUnlock(const string &pwd)
{
	logg << Logger::Debug << "Unlock sd card"<<lend;

	if( ! Luks::isLuks( OPI_MMC_PART ) )
	{
		this->global_error = "No crypto storage available";
		return false;
	}

	logg << Logger::Notice << "LUKS volume found on "<<STORAGE_PART<< lend;

	Luks l( STORAGE_PART);

	if( ! l.Active("opi") )
	{
		logg << Logger::Debug << "Activating LUKS volume"<<lend;
		if ( !l.Open("opi",pwd) )
		{
			logg << Logger::Debug << "Failed to openLUKS volume on "<<STORAGE_PART<< lend;
			this->global_error = "Unable to unlock crypto storage. (Wrong password?)";
			return false;
		}
	}

	logg << Logger::Debug << "LUKS volume on "<<STORAGE_PART<< " opened"<< lend;

	// Make sure device is not mounted (Should not happen)
	if( DiskHelper::IsMounted( LUKSDEVICE ) != "" )
	{
		DiskHelper::Umount( LUKSDEVICE );
	}

	DiskHelper::Mount( LUKSDEVICE , MOUNTPOINT );

	if( ! ServiceHelper::IsRunning("secop") )
	{
		logg << Logger::Debug << "Starting Secop server"<<lend;
		if( ! ServiceHelper::Start("secop") )
		{
			logg << Logger::Notice << "Failed to start secop"<<lend;
			this->global_error = "Failed to start password database";
			return false;
		}
		else
		{
			// Give daemon time to start.
			sleep(1);
		}
	}

	try{
		if( ! this->SecopUnlocked())
		{
			logg << Logger::Debug << "Trying to unlock secop"<<lend;
			if( ! Secop().Init(pwd) )
			{
				this->global_error = "Failed to unlock password database";
				return false;
			}
			return true;
		}
	}
	catch(std::runtime_error err)
	{
		logg << Logger::Error << "Failed to unlock Secop:"<<err.what()<<lend;
		this->global_error = "Failed to unlock password database ("+string(err.what() )+")";
		return false;
	}

	return true;
}

bool ControlApp::DoInit(const string& pwd, const string& unit_id)
{
	bool ret = true;

	this->unit_id = unit_id;
	this->masterpassword = pwd;

	if ( ! this->InitializeSD() )
	{
		logg << Logger::Error << "Failed to unlock SD card" <<lend;
		return false;
	}

	if( ! ServiceHelper::IsRunning("secop") )
	{
		logg << Logger::Debug << "Starting Secop server"<<lend;
		if( ! ServiceHelper::Start("secop") )
		{
			logg << Logger::Notice << "Failed to start secop"<<lend;
			this->global_error = "Failed to start krypto database";
			return false;
		}
		else
		{
			// Give daemon time to start.
			sleep(1);
		}
	}

	try{
		if( ! this->SecopUnlocked())
		{
			logg << Logger::Debug << "Trying to unlock secop"<<lend;
			ret = Secop().Init( this->masterpassword );
			if( ! ret )
			{
				this->global_error = "Wrong password for password store";
			}
		}
	}
	catch(std::runtime_error err)
	{
		logg << Logger::Error << "Failed to unlock Secop:"<<err.what()<<lend;
		this->global_error = "Wrong password for password store";
		return false;
	}

	if( ret )
	{
		ret = this->RegisterKeys();
	}

	if( ret)
	{
		// Assume that we fail and only set to true if we succeed
		ret = false;
		for( int i=0; i<3; i++ )
		{
			try
			{
				ret = this->DoLogin();
				if( ret )
				{
					break;
				}
			}
			catch(runtime_error& err )
			{
				this->global_error ="Failed to login with OP server ("+string(err.what())+")";
				logg << Logger::Notice << "Failed to login to backend: "<< err.what()<<lend;
				ret = false;
			}
		}
	}

	if( ret )
	{
		stringstream pk;
		for( auto row: File::GetContent(DNS_PUB_PATH) )
		{
			pk << row << "\n";
		}
		DnsServer dns;
		string pubkey = Base64Encode( pk.str() );
		ret = dns.RegisterPublicKey(this->unit_id, pubkey, this->token );
		if( ! ret )
		{
			this->global_error ="Failed to register dns key";
		}
	}

	return ret;
}

bool ControlApp::AddUser(const string user, const string display, const string password)
{
	logg << "Add user "<<user<<" "<< display<< " " << password << lend;

	if(! this->SecopUnlocked() )
	{
		this->global_error = "Failed to connect with password database";
		return false;
	}

	Secop s;
	s.SockAuth();

	if( ! s.CreateUser(user, password) )
	{
		this->global_error = "Failed to create user (User exists?)";
		return false;
	}

	return true;
}

bool ControlApp::SetDNSName(const string &opiname)
{
	DnsServer dns;
	if( ! dns.UpdateDynDNS(this->unit_id, opiname) )
	{
		this->global_error = "Failed to update DynDNS";
		return false;
	}

	if( !this->GetCertificate(opiname, "OPI") )
	{
		return false;
	}

	return true;
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

bool ControlApp::InitializeSD()
{
	logg << Logger::Debug << "Initialize sd card"<<lend;
	bool sd_isnew = false;
	if( ! Luks::isLuks( OPI_MMC_PART ) )
	{
		logg << Logger::Notice << "No Luks volume on device, "<< STORAGE_PART<<", creating"<<lend;

		DiskHelper::PartitionDevice( STORAGE_DEV );
		Luks l( STORAGE_PART);
		l.Format( this->masterpassword );

		if( ! l.Open("opi", this->masterpassword ) )
		{
			this->global_error = "Wrong password";
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
			if ( !l.Open("opi", this->masterpassword ) )
			{
				this->global_error = "Wrong password";
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

bool ControlApp::RegisterKeys( )
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

		SecString spass(this->masterpassword.c_str(), this->masterpassword.size() );
		SecVector<byte> key = PBKDF2( spass, 20);
		vector<byte> ukey(key.begin(), key.end());

		string  backuppass = Base64Encode( ukey );

		ControlApp::WriteBackupConfig(backuppass);

		ControlApp::WriteConfig( this->unit_id);
	}
	catch( runtime_error& err)
	{
		this->global_error = "Failed to register keys " + string(err.what());
		logg << Logger::Notice << "Failed to register keys " << err.what() << lend;
		return false;
	}
	return true;
}

bool ControlApp::GetCertificate(const string &opiname, const string &company)
{

	/*
	 *
	 * This is a workaround for a bug in the authserver that loses our
	 * credentials when we login with dns-key
	 *
	 */
	if( ! this->DoLogin() )
	{
		this->global_error = "Failed to login to OP servers";
		return false;
	}


	if( ! CryptoHelper::MakeCSR(DNS_PRIV_PATH, CSR_PATH, opiname+".op-i.me", company) )
	{
		this->global_error = "Failed to make certificate signing request";
		return false;
	}

	string csr = File::GetContentAsString(CSR_PATH, true);

	AuthServer s(this->unit_id);

	int resultcode;
	Json::Value ret;
	tie(resultcode, ret) = s.GetCertificate(csr,this->token );

	if( resultcode != 200 )
	{
		logg << Logger::Error << "Failed to get csr "<<resultcode <<lend;
		this->global_error = "Failed to get certificate from OP servers";
		return false;
	}

	if( ! ret.isMember("cert") || ! ret["cert"].isString() )
	{
		logg << Logger::Error << "Malformed reply from server " <<lend;
		this->global_error = "Unexpected reply from OP server when retrieving certificate";
		return false;
	}

	File::Write( CERT_PATH, ret["cert"].asString(), 0644);

#if 0
	cout << "Resultcode: "<<resultcode<<endl;
	cout << "Retobj\n"<<ret.toStyledString()<<endl;
#endif

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
