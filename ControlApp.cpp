#include "Config.h"

#include "WebServer.h"
#include "InboundTest.h"
#include "ConnTest.h"
#include "PasswordFile.h"
#include "StorageManager.h"


#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>
#include <libutils/UserGroups.h>
#include <libutils/Process.h>
#include <libutils/Thread.h>
#include <libutils/String.h>

#include <libopi/Secop.h>
#include <libopi/SysInfo.h>
#include <libopi/SysConfig.h>
#include <libopi/DnsServer.h>
#include <libopi/DiskHelper.h>
#include <libopi/AuthServer.h>
#include <libopi/Notification.h>
#include <libopi/ServiceHelper.h>

#include <kinguard/MailManager.h>
#include <kinguard/UserManager.h>
#include <kinguard/BackupManager.h>
#include <kinguard/IdentityManager.h>

#include <functional>

#include <syslog.h>
#include <unistd.h>

#include "ControlApp.h"

// Convenience defines
#define SCFG	(OPI::SysConfig())
#define SAREA (SCFG.GetKeyAsString("filesystem","storagemount"))

#define IS_OP	(IdentityManager::Instance().HasDnsProvider())

using namespace Utils;
using namespace std::placeholders;

using namespace OPI;
using namespace OPI::CryptoHelper;

using namespace KGP;

//#define DEBUG (logg << Logger::Debug)

ControlApp::ControlApp() : DaemonApplication("opi-control","/var/run","root","root")
{
}

void ControlApp::Startup()
{
	// Divert logger to syslog
	openlog( "opi-control", LOG_PERROR, LOG_DAEMON);
	logg.SetOutputter( [](const string& msg){ syslog(LOG_INFO, "%s",msg.c_str());});
	logg.SetLogName("");

	logg << Logger::Info << "Starting"<<lend;

	Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&ControlApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&ControlApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&ControlApp::SigHup, this, _1) );

	this->options.AddOption( Option('D', "debug", Option::ArgNone,"0","Debug logging") );

	curl_global_init(CURL_GLOBAL_DEFAULT);
}

bool ControlApp::DoLogin()
{
	AuthServer s( this->unit_id);
	int resultcode;
	Json::Value ret;

	tie(resultcode, ret) = s.Login();

	if( resultcode != 200 && resultcode != 403 )
	{
		logg << Logger::Error << "Unexpected reply from server "<< resultcode <<lend;
		this->global_error ="Unexpected reply from OP server ("+ ret["desc"].asString()+")";
		return false;
	}

	if( resultcode == 403 )
	{
		logg << Logger::Debug << "Send Secret"<<lend;

		if( ! ret.isMember("reply") || ! ret["reply"].isMember("challange")  )
		{
			logg << Logger::Error << "Missing argument from server "<< resultcode <<lend;
			this->global_error ="Missing argument in reply from server";
			return false;
		}

		// Got new challenge to encrypt with master
		string challenge = ret["reply"]["challange"].asString();

		RSAWrapperPtr c = AuthServer::GetKeysFromSecop();

		SecVector<byte> key = PBKDF2(SecString(this->masterpassword.c_str(), this->masterpassword.size() ), 32 );
		AESWrapper aes( key );

		string cryptchal = Base64Encode( aes.Encrypt( challenge ) );

		tie(resultcode, ret) = s.SendSecret(cryptchal, Base64Encode(c->PubKeyAsPEM()) );
		if( resultcode != 200 )
		{
			if( resultcode == 403)
			{
				this->global_error ="Failed to authenticate with OP server. Wrong activation code or password.";
			}
			else
			{
				this->global_error ="Failed to communicate with OP server";
			}
			return false;
		}

		if( ret.isMember("token") && ret["token"].isString() )
		{
			this->token = ret["token"].asString();
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
		if( ret.isMember("token") && ret["token"].isString() )
		{
			this->token = ret["token"].asString();
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

void ControlApp::StopWebserver()
{
	logg << Logger::Debug << "Stopping webserver" << lend;
	if( this->ws != nullptr )
	{
		// ID manager might have outstanding work, make sure its completed
		// before we shutdown webserver
		IdentityManager::Instance().CleanUp();

		this->ws->Stop();
	}
}

void ControlApp::Main()
{
    logg << Logger::Info << "------ !!!   TODO  !!!! ---------"<<lend;
    logg << Logger::Info << "Wrap/test reading of sysconfig keys to not get unwanted exceptions."<<lend;
	logg << Logger::Info << "------ !!!   End TODO  !!!! ---------"<<lend;

    if( this->options["debug"] == "1" )
	{
		logg << Logger::Info << "Increase logging to debug level "<<lend;
		logg.SetLevel(Logger::Debug);
	}

	logg << Logger::Info << "Running on: " << sysinfo.SysTypeText[sysinfo.Type()] << lend;

	logg << Logger::Debug << "Checking device: "<< sysinfo.StorageDevicePath() <<lend;

	this->state = ControlState::State::AskInitCheckRestore;
	this->skiprestore = false;

	if( SCFG.HasKey("hostinfo", "unitid") )
	{
		this->state = ControlState::State::AskUnlock;
        this->unit_id = SCFG.GetKeyAsString("hostinfo", "unitid");
	}

	// None OP device, currently that is the same as not having a dns-provider
	if( ! IdentityManager::Instance().HasDnsProvider() )
	{
		this->state = ControlState::State::AskUnlock;
	}

	// Preconditions
	// Secop should not be running
	if( ServiceHelper::IsRunning("secop") )
	{
		if( this->SecopUnlocked() )
		{
			// We are running on an already started system, exit gracefully
			logg << Logger::Notice << "Secop already unlocked, system likely up. Terminating opi-control"<<lend;
			return;
		}

		logg << Logger::Debug << "Stop running secop instance"<<lend;
		ServiceHelper::Stop("secop");
	}
	// Temp mountpoint must exist
	if( !File::DirExists(TMP_MOUNT) )
	{
		File::MkPath(TMP_MOUNT, 0755);
	}

	// Check environment
	if( ! StorageManager::DeviceExists() )
	{
		logg << Logger::Error << "Device not present"<<lend;
		this->state = ControlState::State::Error;
	}

	// We have a valid config and a device but device is not a luks container
	if( this->state == ControlState::State::AskUnlock )
	{
		if( StorageManager::UseLocking() && ! StorageManager::StorageAreaExists() )
		{
			logg << Logger::Debug << "Config correct but no luksdevice do initialization"<<lend;
			this->state = ControlState::State::AskReInitCheckRestore;
		}
	}

	// Try use password from USB or cfg in /root if possible
	if( this->state == ControlState::State::AskUnlock )
	{
		if( this->GetPasswordUSB() || this->GetPasswordRoot() )
		{
			if( this->DoUnlock( this->masterpassword, false ) )
			{
				this->state = ControlState::State::Completed;
			}
		}
	}

	InboundTestPtr ibt;
	TcpServerPtr redirector;

	if( this->state == ControlState::State::AskInitCheckRestore )
	{

		logg << Logger::Debug << "Starting inbound connection tests"<<lend;
		ibt = InboundTestPtr(new InboundTest( {25,80,143, 587, 993, 2525 }));
		ibt->Start();

		logg << Logger::Debug << "Doing connection tests"<<lend;
		ConnTest ct(SCFG.GetKeyAsString( "setup", "conntesthost"));
		this->connstatus = ct.DoTest();
	}
	else if ( this->state != ControlState::State::Completed )
	{
		logg << Logger::Debug << "Starting redirect service on port 80"<<lend;
		redirector = TcpServerPtr( new TcpServer(80) );

		redirector->Start();
	}

	if( this->state != ControlState::State::Completed )
	{

		this->statemachine = ControlStatePtr( new ControlState( this, static_cast<uint8_t>(this->state) ) );

		this->ws = WebServerPtr( new WebServer( std::bind(&ControlApp::WebCallback,this, _1)) );

		if( this->state == ControlState::State::Error )
		{
			OPI::notification.Notify( OPI::Notification::Error, "Possible error: " + this->global_error);
		}
		else
		{
			OPI::notification.Notify( OPI::Notification::Waiting, "Waiting for user");
		}

		this->ws->Start();

		this->ws->Join();
	}

	if( ibt )
	{
		logg << Logger::Debug << "Stopping inbound connection tests"<<lend;
		ibt->Stop();
		ibt.reset();
	}

	if( redirector )
	{
		logg << Logger::Debug << "Stopping redirect service"<<lend;
		redirector->Stop();
		redirector.reset();
	}

	if( this->state == ControlState::State::Completed )
	{
		// We should have reached a positive end of init, start services
		logg << Logger::Debug << "Init completed, start servers"<<lend;
		ServiceHelper::Start( "mysql" );
		ServiceHelper::Start( "postfix" );
		ServiceHelper::Start( "dovecot" );
		ServiceHelper::Start( "fetchmail" );
		ServiceHelper::Start( "nginx" );

		// Add eventhandler to process completed startup
		this->evhandler.AddEvent( 90, std::bind(
									  Process::Exec,
									  "/bin/run-parts --lsbsysinit  -- /etc/opi-control/completed" ));

		OPI::notification.Notify( OPI::Notification::Completed, "Opi Control completed ");
	}
	else if( this->state == ControlState::State::ShutDown )
	{
		logg << Logger::Debug << "Register power off opi"<<lend;

		this->evhandler.AddEvent( 99, bind(Process::Exec, "/sbin/poweroff") );
	}
	else if( this->state == ControlState::State::Reboot )
	{
		logg << Logger::Debug << "Register reboot opi"<<lend;
		this->evhandler.AddEvent( 99, bind(Process::Exec, "/sbin/reboot") );
	}

	logg << Logger::Debug << "Calling all eventhandlers"<< lend;
	this->evhandler.CallEvents();

	logg << Logger::Debug << "OPI control finnished " <<lend;
}

void ControlApp::ShutDown()
{
	curl_global_cleanup();
	logg << Logger::Debug << "Shutting down"<< lend;
}

void ControlApp::SigTerm(int signo)
{
	(void) signo;
	// Possibly shutdown webserver
	if( this->ws != nullptr )
	{
		this->StopWebserver();
	}

}

void ControlApp::SigHup(int signo)
{
	(void) signo;
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

	this->statemachine->ResetReturnData();

	if( v.isMember("cmd") )
	{
		string cmd = v["cmd"].asString();

		try
		{
			if( cmd == "init" )
			{
				this->masterpassword = v["password"].asString();
				this->unit_id = v["unit_id"].asString();
				this->WriteConfig();

				this->statemachine->Init( v["save"].asBool() );
			}
			else if( cmd == "reinit" )
			{
				this->masterpassword = v["password"].asString();

				this->statemachine->ReInit( v["save"].asBool() );
			}
			else if( cmd == "restore" )
			{
				this->statemachine->Restore(v["restore"].asBool(), v["path"].asString() );
			}
			else if( cmd == "adduser" )
			{
				this->statemachine->AddUser( v["username"].asString(), v["displayname"].asString(), v["password"].asString());
			}
			else if( cmd == "opiname" )
			{
				this->statemachine->OpiName( v["opiname"].asString() );
			}
			else if( cmd == "unlock" )
			{
				this->statemachine->Unlock( v["password"].asString(), v["save"].asBool()  );
			}
			else if( cmd == "terminate" )
			{
				this->statemachine->Terminate();
			}
			else if( cmd == "shutdown" )
			{
				this->statemachine->ShutDown( v["action"].asString() );
			}
			else if( cmd == "portstatus" )
			{
				return this->connstatus;
			}
            else if( cmd == "gettype" )
            {
                Json::Value ret;
                ret["type"] = sysinfo.SysTypeText[sysinfo.Type()];
				if ( SCFG.HasKey("hostinfo","provider") )
				{
					try
					{
						ret["provider"] = SCFG.GetKeyAsString("hostinfo","provider");
					}
					catch( std::runtime_error& err)
					{
						logg << Logger::Error << "Failed to read 'provider' from config."<< err.what() << lend;
					}
				}
                return ret;
            }
            else if( cmd == "getdomains" )
			{
                Json::Value ret(Json::objectValue);
				ret["domains"]=Json::arrayValue;
				list<string> domains;
				IdentityManager& idmgr = IdentityManager::Instance();

				if( idmgr.HasDnsProvider() )
				{
					list<string> domains = idmgr.DnsAvailableDomains();
					for(auto domain: domains)
					{
						ret["domains"].append(domain);
					}
					if( domains.size() > 0 )
					{
						ret["domain"]=domains.front();
					}
					else
					{
						// Really should not happen
						logg << Logger::Error << "Missing DNS providers!"<<lend;
					}
				}
				return ret;
			}
			else if( cmd == "status" )
			{
				Json::Value ret;
				Json::Value progress;
				Json::Reader reader;

				uint8_t state = this->statemachine->State();
				ret["state"] = state;
				if( this->cache.find( state) != this->cache.end() )
				{
					ret["cache"] = this->cache[state];
				}

				bool retval;
				string strprog;

				tie(retval,strprog) = Process::Exec( "/usr/share/opi-backup/progress.sh" );
				if ( retval )
				{
					retval = reader.parse(strprog,progress);
					if ( retval )
					{
						ret["progress"] = progress;
					}
					else
					{
						logg << Logger::Error << "Failed to parse restore progress." << lend;
					}
				}
				else
				{
					logg << Logger::Error << "Failed to run restore progress check." << lend;
				}
				return ret;
			}
			else
			{
				status = false;
				this->global_error = "Unknown command";
			}
		}
		catch( std::runtime_error& err)
		{
			status = false;
			logg << Logger::Error << "Statemachine failed "<< err.what() << lend;
			this->global_error = string("Internal error (") + err.what() +")";
		}

		if( status )
		{
			// Statemachine run, i.e no error, return result
			this->state = this->statemachine->State();
			tie(status, ret) = this->statemachine->RetValue();
		}

		ret["status"]=status;
		ret["state"]=this->state;
		if(!status)
		{
			ret["errmsg"]=this->global_error;
		}
	}
	else
	{
		ret["status"] = false;
		ret["state"] = this->state;
		ret["errmsg"] = "Internal error (Missing command)";
	}

	return ret;
}

bool ControlApp::DoUnlock(const string &pwd, bool savepass)
{
	logg << Logger::Debug << "Unlock storage"<<lend;

	if( ! StorageManager::Instance().Open(pwd) )
	{
		this->global_error = "Unable to unlock crypto storage. (Wrong password?)";
		return false;
	}

	logg << Logger::Debug << "Storage device opened"<< lend;

    if( ! StorageManager::mountDevice( SCFG.GetKeyAsString("filesystem","storagemount") ) )
	{
		this->global_error = "Unable to access storage";
		return false;
	}

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
		}
	}
	catch(std::runtime_error err)
	{
		logg << Logger::Error << "Failed to unlock Secop:"<<err.what()<<lend;
		this->global_error = "Failed to unlock password database ("+string(err.what() )+")";
		return false;
	}

	if( savepass )
	{
		logg << Logger::Debug << "Try saving password on successful unlock"<<lend;
		this->masterpassword = pwd;
		if( ! this->SetPasswordUSB() )
		{
			logg << Logger::Error << "Failed to write password to USB device"<<lend;
			return false;
		}
	}
	else
	{
		logg << Logger::Debug << "Not saving password on successful unlock"<<lend;
	}
	return true;
}

bool ControlApp::DoInit( bool savepassword )
{

	if ( ! this->InitializeStorage() )
	{
		logg << Logger::Error << "Failed to initialize storage area" <<lend;
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

			if( ! Secop().Init( this->masterpassword ) )
			{
				this->global_error = "Wrong password for password store";
				return false;
			}
		}
	}
	catch(std::runtime_error err)
	{
		logg << Logger::Error << "Failed to unlock Secop:"<<err.what()<<lend;
		this->global_error = "Wrong password for password store";
		return false;
	}

	if( !this->RegisterKeys() )
	{
		return false;
	}

	// Setup backup config
	Json::Value backupcfg;
	backupcfg["password"] = this->GetBackupPassword();

	BackupManager::Configure( backupcfg );

	this->WriteConfig( );

	// We only try to login if we run an OP enabled device
	bool loggedin = false;
	if( IS_OP )
	{
		for( int i=0; i<3; i++ )
		{
			try
			{
				if( this->DoLogin() )
				{
					loggedin = true;
					break;
				}
			}
			catch(runtime_error& err )
			{
				this->global_error ="Failed to login with OP server ("+string(err.what())+")";
				logg << Logger::Notice << "Failed to login to backend: "<< err.what()<<lend;
				return false;
			}
		}
	}

	// Possibly save password to usb device
	if( loggedin && savepassword )
	{
		logg << Logger::Debug << "Try saving password on successful init"<<lend;
		if( ! this->SetPasswordUSB() )
		{
			return false;
		}
	}
	else
	{
		logg << Logger::Debug << "Not saving password on successful init"<<lend;
	}

	//Only on OP-enabled devices
	if( IS_OP )
	{
		// TODO: THis have to go into IdManager somehow.
		// Function exists in Manager but is private.
		// Maybe integrate in AddDNSname or similar
		stringstream pk;
        for( auto row: File::GetContent(SCFG.GetKeyAsString("dns","dnspubkey")) )
		{
			pk << row << "\n";
		}
		DnsServer dns;
		string pubkey = Base64Encode( pk.str() );
		if( ! dns.RegisterPublicKey(this->unit_id, pubkey, this->token ) )
		{
			this->global_error ="Failed to register dns key";
			logg << Logger::Error << this->global_error << lend;
			return false;
		}
	}

	return true;
}

bool ControlApp::AddUser(const string user, const string display, const string password)
{
	logg << "Add user "<<user<<" "<< display << lend;

	if(! this->SecopUnlocked() )
	{
		this->global_error = "Failed to connect with password database";
		return false;
	}

	UserManagerPtr umgr = UserManager::Instance();

	if( ! umgr->AddUser(user, password, display, true) )
	{
		this->global_error = umgr->StrError();
		return false;
	}

	this->first_user = user;

	return true;
}
bool ControlApp::SetDNSName()
{
	return this->SetDNSName(this->opi_name,this->domain);
}
bool ControlApp::SetDNSName(const string &opiname,const string &domain)
{
	logg << Logger::Debug << "Set dns, hostname: " << opiname << " domain: " << domain << lend;

	IdentityManager& idmgr = IdentityManager::Instance();

	if( ! idmgr.SetFqdn(opi_name, domain) )
	{
		this->global_error = idmgr.StrError();
		logg << Logger::Error << this->global_error<< lend;
		return false;
	}

	if( ! idmgr.HasDnsProvider() )
	{
		logg << Logger::Error << "No DNS provider available" << lend;
		this->global_error = "No DNS provider available";
		return false;
	}

	if( ! idmgr.AddDnsName(opiname, domain ) )
	{
		this->global_error = idmgr.StrError();
		logg << Logger::Error << this->global_error << lend;
		return false;
	}

	this->opi_name = opiname;
	this->domain = domain;

	this->WriteConfig();

	/*
	 * If we have no first user this indicates old SD card with info and users
	 * skip adding in this case.
	 */
	if( this->first_user != "" )
	{
		try
		{
			// Add first user email on opidomain
			string fqdn = opiname +"."+domain;

			MailManager& mmgr = MailManager::Instance();
			mmgr.SetAddress(fqdn,this->first_user,this->first_user);
		}
		catch(runtime_error& err)
		{
			logg << Logger::Error << "Failed to add first user email"<<err.what()<<lend;
			this->global_error = "Failed to update mailsettings for user";
			return false;
		}
	}

	return true;
}

/**
 * @brief ControlApp::SetHostName, set static hostname and get self signed cert
 *        THis is the alternative/fallback if we have no DNS-provider
 * @return true upon success
 */
bool ControlApp::SetHostName()
{
	// CUrrently hardcode this, most likely change this later and ask user?
	try {
		IdentityManager& idmgr = IdentityManager::Instance();

		if( ! idmgr.SetFqdn("kgpunit", "localdomain") )
		{
			logg << Logger::Notice << "Failed to set hostname or domain" << lend;
			this->global_error = "Failed to set hostname or domain";
			return false;
		}

		if( ! idmgr.CreateCertificate() )
		{
			logg << Logger::Notice << "Failed to create certificate" << lend;
			this->global_error = "Failed to create certificate";
			return false;
		}

	}
	catch( runtime_error& err)
	{
		logg << Logger::Error << "Failed to set hostname: "<< err.what() << lend;
		this->global_error = string("Failed to set hostname (") + err.what() + string(")");
		return false;
	}

	return true;
}

bool ControlApp::SecopUnlocked()
{
	Secop::State st = Secop::Unknown;
	int retries = 3;

	while( st == Secop::Unknown && retries > 0)
	{
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

		if( st == Secop::Unknown && retries > 0 )
		{
			// Give secop some more time getting up and running
			sleep(1);
		}

		--retries;
	}

	return (st != Secop::Uninitialized) && (st != Secop::Unknown);
}

bool ControlApp::InitializeStorage()
{
	logg << Logger::Debug << "Initialize storage device" << lend;

	return StorageManager::Instance().Initialize(this->masterpassword);
}

bool ControlApp::RegisterKeys( )
{
	logg << Logger::Debug << "Register keys"<<lend;

	IdentityManager& idmgr = IdentityManager::Instance();

	if( ! idmgr.RegisterKeys() )
	{
		this->global_error = idmgr.StrError();
		logg << Logger::Error << this->global_error <<lend;
		return false;
	}

	return true;
}

string ControlApp::GetBackupPassword()
{
	//TODO: Move to BackupManager?
	SecString spass(this->masterpassword.c_str(), this->masterpassword.size() );
	SecVector<byte> key = PBKDF2( spass, 20);
	vector<byte> ukey(key.begin(), key.end());

	return Base64Encode( ukey );
}

bool ControlApp::GetPasswordUSB()
{
	logg << Logger::Debug << "Get password from "<< sysinfo.PasswordDevice() <<lend;

	bool ret = false;

	if( ! DiskHelper::DeviceExists( sysinfo.PasswordDevice() ) )
	{
		return false;
	}

	try
	{
		if( ! File::DirExists("/mnt/usb") )
		{
			File::MkDir("/mnt/usb", 0755);
		}

		DiskHelper::Mount( sysinfo.PasswordDevice(), "/mnt/usb", false, false, "");

		if( File::DirExists( "/mnt/usb/opi") && File::FileExists("/mnt/usb/opi/opicred.bin") )
		{
			this->masterpassword = PasswordFile::Read("/mnt/usb/opi/opicred.bin");
			ret = true;
		}
	}
	catch( CryptoPP::Exception& e)
	{
		logg << Logger::Info << "Failed to retrieve password "<< e.what()<<lend;
	}
	catch( ErrnoException& e)
	{
		logg << Logger::Info << "Failed to retrieve password "<< e.what()<<lend;
	}

	if( DiskHelper::IsMounted( sysinfo.PasswordDevice() ) != "" )
	{
		DiskHelper::Umount( sysinfo.PasswordDevice() );
	}

	return ret;
}

bool ControlApp::GetPasswordRoot()
{
	logg << Logger::Debug << "Get password from os storage"<<lend;

	bool ret = false;

	try
	{
		if( File::FileExists("/root/.keepcfg/opicred.bin"))
		{
			this->masterpassword = PasswordFile::Read("/root/.keepcfg/opicred.bin");
			ret = true;
		}
	}
	catch( CryptoPP::Exception& e)
	{
		logg << Logger::Info << "Failed to retrieve password "<< e.what()<<lend;
	}
	catch( ErrnoException& e)
	{
		logg << Logger::Info << "Failed to retrieve password "<< e.what()<<lend;
	}


	return ret;
}

bool ControlApp::SetPasswordUSB()
{
	logg << Logger::Debug << "Store password on device "<<sysinfo.PasswordDevice()<<lend;
	bool ret = false;
	bool wasmounted = false;

	if( ! DiskHelper::DeviceExists( sysinfo.PasswordDevice() ) )
	{
		this->global_error ="Failed to save password on device (Device not found)";
		return false;
	}

	try
	{
		if( ! File::DirExists("/mnt/usb") )
		{
			File::MkDir("/mnt/usb", 0755);
		}

		string mpath = DiskHelper::IsMounted( sysinfo.PasswordDevice());
		wasmounted = mpath != "";

		if( ! wasmounted  )
		{
			DiskHelper::Mount( sysinfo.PasswordDevice(), "/mnt/usb", false, false, "");
			mpath = "/mnt/usb";
		}

		if( ! File::DirExists( mpath + "/opi" ) )
		{
			File::MkDir(mpath + "/opi", 0755);
		}

		logg << Logger::Debug << "Storing password at " << mpath + "/opi/opicred.bin" << lend;
		PasswordFile::Write( mpath + "/opi/opicred.bin", this->masterpassword );

		ret = true;
	}
	catch( CryptoPP::Exception& e)
	{
		logg << Logger::Info << "Failed to save password "<< e.what()<<lend;
		this->global_error ="Failed to save password on device (Crypto error)";
	}
	catch( ErrnoException& e)
	{
		logg << Logger::Info << "Failed to save password "<< e.what()<<lend;
		this->global_error ="Failed to save password on device";
	}

	if( ! wasmounted && DiskHelper::IsMounted( sysinfo.PasswordDevice() ) != "" )
	{
		DiskHelper::Umount( sysinfo.PasswordDevice() );
	}

	return ret;
}

bool ControlApp::SetPasswordRoot()
{
	return false;
}

bool ControlApp::GuessOPIName()
{
	logg << Logger::Debug << "Guess opi-name"<<lend;
	IdentityManager& idmgr = IdentityManager::Instance();
	try
	{

		string name, domain;

		tie(name, domain) = idmgr.GetFqdn();

		if( name != "" && domain != "" )
		{
			this->opi_name = name;
			this->domain = domain;

			logg << Logger::Debug << "OPI-name, " << this->opi_name << "domain: " << this->domain << ", sucessfully read from sysconfig"<<lend;
			return true;
		}
		logg << Logger::Notice << "OPI-name not found in sysconfig ("<<name<<")"<<", ("<<domain<<")"<<lend;
	}
    catch (std::runtime_error& e)
    {
		logg << Logger::Notice << "Failed to retrieve hostname or domain (" << e.what() << ")" <<lend;
    }

	// If not found try figure out from mail-addresses
	try
	{
		logg << Logger::Notice << "Trying to guess fqdn from mailconfig" <<lend;

		MailManager& mmgr = MailManager::Instance();

		list<string> valid_domains = idmgr.DnsAvailableDomains();
		list<string> names;
		list<string> domains = mmgr.GetDomains();
		for( const string& domain: domains )
		{
			list<string> parts=String::Split(domain, ".",2);
			if( find( valid_domains.begin(), valid_domains.end(), parts.back() ) != valid_domains.end() )
			{
				names.push_back(domain);
			}
		}

		// If we have only one match we assume this is our opi-name and try with that.
		if( names.size() != 1 )
		{
			return false;
		}
		list<string> fqdn = String::Split(names.front(),".",2);
		this->opi_name = fqdn.front();
		this->domain = fqdn.back();

		return true;
	}
	catch(runtime_error& err)
	{
		logg << Logger::Notice << "Failed to guess OPIName: "<< err.what()<<lend;
		return false;
	}
}
void ControlApp::WriteConfig()
{
	logg << Logger::Notice << "Uppdating sysconfig" <<lend;
	SysConfig sysconfig(true);

	if( this->unit_id != "" )
	{
		sysconfig.PutKey("hostinfo","unitid",this->unit_id);
	}
}


Json::Value ControlApp::CheckRestore()
{
	logg << Logger::Debug << "Check if restore should be performed"<<lend;

	if( this->skiprestore )
	{
		logg << Logger::Debug << "Restore manually cancelled"<<lend;
		return Json::nullValue;
	}

	if( StorageManager::UseLocking() && StorageManager::StorageAreaExists()  )
	{
		// We never do a restore if we have a locked device
		logg << Logger::Notice << "Found locked device, aborting"<<lend;
		return Json::nullValue;
	}

	if( this->masterpassword == "" )
	{
		// Need password to be able to get backups
		logg << Logger::Notice << "Missing password, restore impossible" << lend;

		return Json::nullValue;
	}

	// Call backupmanager get backups
	Json::Value retval = BackupManager::Instance().GetBackups();

	if( retval != Json::nullValue )
	{
		//Update cache with backups
		if( retval.isMember("local") )
		{
			this->cache[ControlState::State::AskRestore]["local"] = retval["local"];
		}

		if( retval.isMember("remote") )
		{
			this->cache[ControlState::State::AskRestore]["remote"] = retval["remote"];
		}
	}

	return retval;
}

bool ControlApp::DoRestore(const string &path)
{
	logg << Logger::Debug << "Do restore backup"<<lend;
	// Setup SD-card
	if( ! this->InitializeStorage() )
	{
		this->global_error ="Restore backup - failed to initialize SD card";
		return false;
	}


	if( ! BackupManager::Instance().RestoreBackup(path) )
	{
		this->global_error = BackupManager::Instance().StrError();
		return false;
	}

	return true;
}
