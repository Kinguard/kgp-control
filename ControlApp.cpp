#include "Config.h"

#include "WebServer.h"
#include "InboundTest.h"
#include "ConnTest.h"
#include "PasswordFile.h"

#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>
#include <libutils/UserGroups.h>
#include <libutils/Process.h>

#include <libopi/Secop.h>
#include <libopi/DiskHelper.h>
#include <libopi/ServiceHelper.h>
#include <libopi/CryptoHelper.h>
#include <libopi/AuthServer.h>
#include <libopi/DnsServer.h>
#include <libopi/Luks.h>
#include <libopi/MailConfig.h>

#include <functional>

#include <syslog.h>
#include <unistd.h>

#include "ControlApp.h"

using namespace Utils;
using namespace std::placeholders;

using namespace OPI;
using namespace OPI::CryptoHelper;


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

void ControlApp::Main()
{
	if( this->options["debug"] == "1" )
	{
		logg << Logger::Info << "Increase logging to debug level "<<lend;
		logg.SetLevel(Logger::Debug);
	}

	logg << Logger::Debug << "Checking device: "<< STORAGE_DEV <<lend;

	this->state = ControlState::State::InitCheckRestore; // 3
	this->skiprestore = false;

	if( File::FileExists(SYSCONFIG_PATH))
	{
		ConfigFile c(SYSCONFIG_PATH);

		string unit_id = c.ValueOrDefault("unit_id");

		if( unit_id != "" )
		{
			this->state = ControlState::State::AskUnlock;  // 6
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
#ifdef DO_SANITY_CHECKS
	/*
	 * If on opi and no sd is in place, emmc will have gotten our
	 * devicenode that we want to install to. So we double check
	 * that we really have two mmc devices, mmc and SD card
	 */

	if( ! DiskHelper::DeviceExists( "/dev/mmcblk1" ) )
	{
		logg << Logger::Error << "No SD card present"<<lend;
		this->state = ControlState::State::Error; // 2
	}

#endif

	if( ! DiskHelper::DeviceExists( STORAGE_DEV ) )
	{
		logg << Logger::Error << "Device not present"<<lend;
		this->state = ControlState::State::Error; // 2
	}
	else if( DiskHelper::DeviceSize( OPI_MMC_DEV ) == 0 )
	{
		logg << Logger::Error << "No space on device"<< lend;
		this->state = ControlState::State::Error; // 2
	}

	// We have a valid config and a device but device is not a luks container
	if( this->state == ControlState::State::AskUnlock /* 6 */ && ! Luks::isLuks( OPI_MMC_PART ) )
	{
		logg << Logger::Debug << "Config correct but no luksdevice do initialization"<<lend;
		this->state = ControlState::State::ReInitCheckrestore; // 9
	}

	// Try use password from USB if possible
	if( this->state == ControlState::State::AskUnlock /* 6 */ )
	{
		if( this->GetPasswordUSB() )
		{
			if( this->DoUnlock( this->masterpassword, false ) )
			{
				this->state = ControlState::State::Completed; // 7
			}
		}
	}

	InboundTestPtr ibt;
	TcpServerPtr redirector;

	if( this->state == ControlState::State::InitCheckRestore /* 3 */ )
	{
		logg << Logger::Debug << "Starting inbound connection tests"<<lend;
		ibt = InboundTestPtr(new InboundTest( {25,80,143, 587, 993, 2525 }));
		ibt->Start();

		logg << Logger::Debug << "Doing connection tests"<<lend;
		ConnTest ct;
		this->connstatus = ct.DoTest();
	}
	else
	{
		logg << Logger::Debug << "Starting redirect service on port 80"<<lend;
		redirector = TcpServerPtr( new TcpServer(80) );

		redirector->Start();
	}

	if( this->state != ControlState::State::Completed /* 7 */ )
	{

		this->statemachine = ControlStatePtr( new ControlState( this ) );

		this->ws = WebServerPtr( new WebServer( this->state, std::bind(&ControlApp::WebCallback,this, _1)) );

		if( this->state == ControlState::State::Error /* 2 */ )
		{
			this->SetLedstate(Ledstate::Error);
		}
		else
		{
			this->SetLedstate( Ledstate::Waiting);
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

	if( this->state == ControlState::State::Completed /* 7 */ )
	{
		// We should have reached a positive end of init, start services
		logg << Logger::Debug << "Init completed, start servers"<<lend;
		ServiceHelper::Start( "mysql" );
		ServiceHelper::Start( "postfix" );
		ServiceHelper::Start( "dovecot" );
		ServiceHelper::Start( "opi-authproxy" );
		ServiceHelper::Start( "fetchmail" );
		ServiceHelper::Start( "nginx" );

		// Add event to be called when done
		this->evhandler.AddEvent( 90, std::bind(
									  Process::Exec,
									  "/bin/run-parts --lsbsysinit  -- /etc/opi-control/completed" ));

		this->SetLedstate( Ledstate::Completed);
	}
	else if( this->state == ControlState::State::ShutDown /* 10 */ )
	{
		logg << Logger::Debug << "Register power off opi"<<lend;

		this->evhandler.AddEvent( 99, bind(Process::Exec, "/sbin/poweroff") );
	}
	else if( this->state == ControlState::State::Reboot /* 11 */ )
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
			}
			else if( cmd == "opiname" )
			{
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
#if 0
		if( cmd == "init" )
		{
			this->masterpassword = v["password"].asString();
			this->unit_id = v["unit_id"].asString();

			// First check if we should try a restore
			Json::Value tmpret;
			if( ( tmpret = this->CheckRestore() ) != Json::nullValue  )
			{
				this->state = 12;
				ret = tmpret;
			}
			else
			{
				// No restore possible, continue
				if( this->DoInit( v["save"].asBool() ) )
				{
					Secop s;
					s.SockAuth();
					vector<string> users = s.GetUsers();

					if( users.size() > 0 )
					{
						// We have users on SD, skip register user
						if( this->GuessOPIName() && this->SetDNSName( this->opi_name ) )
						{
							// We have a opi-name in mailconfig and register succeded
							// Skip to end
							this->state = 7;
						}
						else
						{
							this->state = 5;
						}
						this->evhandler.AddEvent( 50, bind( Process::Exec, "/bin/run-parts --lsbsysinit  -- /etc/opi-control/reinstall"));
					}
					else
					{
						this->state = 4;
					}
					// TODO: try reuse opi-name and opi_unitid
				}
				else
				{
					status = false;
					this->state = 3;
				}
			}

		}
		else if( cmd == "reinit" )
		{
			this->masterpassword = v["password"].asString();

			// First check if we should try a restore
			Json::Value tmpret;
			if( ( tmpret = this->CheckRestore()) != Json::nullValue )
			{
				this->state = 12;
				ret = tmpret;
			}
			else
			{
				// No restore possible, continue
				if( this->DoInit( v["save"].asBool() ) )
				{
					this->evhandler.AddEvent( 50, bind( Process::Exec, "/bin/run-parts --lsbsysinit  -- /etc/opi-control/reinit"));
					this->state = 4;
				}
				else
				{
					status = false;
					this->state = 3;
				}
			}
		}
		else if( cmd == "restore" )
		{
			if( v["restore"].asBool() )
			{
				if( this->DoRestore( v["path"].asString() ) )
				{
					if( this->DoInit( false ) )
					{
						// We are done
						this->state = 7;
					}
				}

				// Clean up after restore, umount etc
				this->CleanupRestoreEnv();

				if( this->state != 7 )
				{
					// Restore failed return to previous state
					status = false;

					// Figure out what state to return to
					if( ! Luks::isLuks( OPI_MMC_PART ) )
					{
						this->state = 9;
					}
					else
					{
						this->state = 3;
					}
				}
			}
			else
			{
				// Mark that user don't want to restore
				this->skiprestore = true;

				// Figure out what state to return to
				if( ! Luks::isLuks( OPI_MMC_PART ) )
				{
					this->state = 9;
				}
				else
				{
					this->state = 3;
				}
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
			if( this->DoUnlock(v["password"].asString(), v["save"].asBool() ) )
			{
				this->state = 7;
			}
			else
			{
				status = false;
				this->state = 6;
			}
		}
		else if( cmd == "terminate" )
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
		else if( cmd == "shutdown" )
		{
			string action = v["action"].asString();

			if( action == "shutdown")
			{
				this->state = 10;
				this->ws->Stop();
			}
			else if( action == "reboot" )
			{
				this->state = 11;
				ret["url"]="/";
				ret["timeout"]=50;
				this->ws->Stop();
			}
			else
			{
				status = false;
				this->global_error = "Unknown action for shutdown";
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
#endif

}

bool ControlApp::DoUnlock(const string &pwd, bool savepass)
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

	try
	{
		// Make sure device is not mounted (Should not happen)
		if( DiskHelper::IsMounted( LUKSDEVICE ) != "" )
		{
			DiskHelper::Umount( LUKSDEVICE );
		}

		DiskHelper::Mount( LUKSDEVICE , MOUNTPOINT );
	}
	catch( ErrnoException& err)
	{
		this->global_error = "Unable to access SD card";
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
	bool ret = true;

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

	// Possibly save password to usb device
	if( ret && savepassword )
	{
		logg << Logger::Debug << "Try saving password on successful init"<<lend;
		ret = this->SetPasswordUSB();
	}
	else
	{
		logg << Logger::Debug << "Not saving password on successful init"<<lend;
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
	logg << "Add user "<<user<<" "<< display << lend;

	if(! this->SecopUnlocked() )
	{
		this->global_error = "Failed to connect with password database";
		return false;
	}

	Secop s;
	s.SockAuth();

	if( ! s.CreateUser(user, password, display) )
	{
		this->global_error = "Failed to create user (User exists?)";
		return false;
	}

	if( ! s.AddGroupMember("admin", user) )
	{
		this->global_error = "Failed to make user admin";
		return false;
	}

	this->first_user = user;

	try
	{
		// Add user to localdomain mailboxfile
		OPI::MailMapFile mmf( LOCAL_MAILFILE );
		mmf.ReadConfig();
		mmf.SetAddress("localdomain", user, user);
		mmf.WriteConfig();

		chown( LOCAL_MAILFILE, User::UserToUID("postfix"), Group::GroupToGID("postfix") );
	}
	catch( runtime_error& err)
	{
		this->global_error = string("Failed to add user mailbox (")+err.what()+")";
		return false;
	}

	// Add this user as receiver of administrative mail
	try
	{
		OPI::MailAliasFile mf( VIRTUAL_ALIASES );

		mf.AddUser("/^postmaster@/",user+"@localdomain");
		mf.AddUser("/^root@/",user+"@localdomain");

		mf.WriteConfig();
	}
	catch( runtime_error& err)
	{
		this->global_error = string("Failed to create user mail mapping (")+err.what()+")";
		return false;
	}

	chown( VIRTUAL_ALIASES, User::UserToUID("postfix"), Group::GroupToGID("postfix") );

	bool ret;
	tie(ret,ignore) = Process::Exec( "/usr/sbin/postmap " LOCAL_MAILFILE );

	if( !ret )
	{
		this->global_error = "Failed to create user mail mapping";
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

	this->opi_name = opiname;

	/*
	 * If we have no first user this indicates old SD card with info and users
	 * skip adding in this case.
	 */
	if( this->first_user != "" )
	{
		try
		{
			// Add first user email on opidomain
			OPI::MailConfig mc;
			mc.ReadConfig();
			mc.SetAddress(this->opi_name+".op-i.me",this->first_user,this->first_user);
			mc.WriteConfig();

			chown( ALIASES, User::UserToUID("postfix"), Group::GroupToGID("postfix") );

			bool ret;
			tie(ret, ignore) = Process::Exec("/usr/sbin/postmap " ALIASES);

			if( !ret )
			{
				this->global_error = "Failed to create user mail mapping";
				return false;
			}

			File::Write("/etc/mailname", opiname+".op-i.me", 0644);
		}
		catch(runtime_error& err)
		{
			logg << Logger::Error << "Failed to add first user email"<<err.what()<<lend;
			this->global_error = "Failed to update mailsettings for user";
			return false;
		}
	}

	this->WriteConfig();

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

	try
	{
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
	}
	catch( ErrnoException& err)
	{
		this->global_error = "Unable to access SD card";
		return false;
	}

	return true;
}

bool ControlApp::RegisterKeys( )
{
	logg << Logger::Debug << "Register keys"<<lend;
	try{
		Secop s;

		s.SockAuth();
		list<map<string,string>> ids;

		try
		{
			ids = s.AppGetIdentifiers("op-backend");
		}
		catch( runtime_error& err)
		{
			// Do nothing, appid is missing but thats ok.
		}

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
		// Todo: if keys in secop, does not mean they are on disk.
		// perhaps move that part out here to make sure keys exist
		// on disk.

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

			// Could be leftover symlinks, remove
			unlink( DNS_PRIV_PATH );
			unlink( DNS_PUB_PATH );

			File::Write(DNS_PRIV_PATH, dns.PrivKeyAsPEM(), 0600 );
			File::Write(DNS_PUB_PATH, dns.PubKeyAsPEM(), 0644 );
		}

		ControlApp::WriteBackupConfig( this->GetBackupPassword());

		this->WriteConfig( );
	}
	catch( runtime_error& err)
	{
		this->global_error = "Failed to register keys " + string(err.what());
		logg << Logger::Notice << "Failed to register keys " << err.what() << lend;
		return false;
	}
	return true;
}

string ControlApp::GetBackupPassword()
{
	SecString spass(this->masterpassword.c_str(), this->masterpassword.size() );
	SecVector<byte> key = PBKDF2( spass, 20);
	vector<byte> ukey(key.begin(), key.end());

	return Base64Encode( ukey );
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

	// Make sure we have no symlinked tempcert in place
	unlink( CERT_PATH );

	File::Write( CERT_PATH, ret["cert"].asString(), 0644);

#if 0
	cout << "Resultcode: "<<resultcode<<endl;
	cout << "Retobj\n"<<ret.toStyledString()<<endl;
#endif

	return true;
}

bool ControlApp::GetPasswordUSB()
{
	logg << Logger::Debug << "Get password from "<<OPI_PASSWD_DEVICE<<lend;

	bool ret = false;

	if( ! DiskHelper::DeviceExists( OPI_PASSWD_DEVICE ) )
	{
		return false;
	}

	try
	{
		if( ! File::DirExists("/mnt/usb") )
		{
			File::MkDir("/mnt/usb", 0755);
		}

		DiskHelper::Mount( OPI_PASSWD_DEVICE, "/mnt/usb", false, false, "");

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

	if( DiskHelper::IsMounted( OPI_PASSWD_DEVICE ) != "" )
	{
		DiskHelper::Umount( OPI_PASSWD_DEVICE );
	}

	return ret;
}

bool ControlApp::SetPasswordUSB()
{
	logg << Logger::Debug << "Store password on "<<OPI_PASSWD_DEVICE<<lend;
	bool ret = false;

	if( ! DiskHelper::DeviceExists( OPI_PASSWD_DEVICE ) )
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

		DiskHelper::Mount( OPI_PASSWD_DEVICE, "/mnt/usb", false, false, "");

		if( ! File::DirExists( "/mnt/usb/opi" ) )
		{
			File::MkDir("/mnt/usb/opi", 0755);
		}

		PasswordFile::Write("/mnt/usb/opi/opicred.bin", this->masterpassword );

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

	if( DiskHelper::IsMounted( OPI_PASSWD_DEVICE ) != "" )
	{
		DiskHelper::Umount( OPI_PASSWD_DEVICE );
	}

	return ret;
}

bool ControlApp::GuessOPIName()
{
	try
	{
		OPI::MailConfig mc;

		mc.ReadConfig();
		list<string> names;
		list<string> domains = mc.GetDomains();
		for( const string& domain: domains )
		{
			list<string> parts=String::Split(domain, ".",2);
			if( parts.back() == "op-i.me" )
			{
				names.push_back(parts.front());
			}
		}

		if( names.size() != 1 )
		{
			return false;
		}

		this->opi_name = names.front();

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
	string path = File::GetPath( SYSCONFIG_PATH );

	if( ! File::DirExists( path ) )
	{
		File::MkPath( path, 0755 );
	}

	ConfigFile c( SYSCONFIG_PATH );

	c["dns_key"] = DNS_PRIV_PATH;
	c["sys_key"] = SYS_PRIV_PATH;
	c["ca_path"] = "/etc/opi/op_ca.pem";

	if( this->unit_id != "" )
	{
		c["unit_id"] = this->unit_id;
	}

	if( this->opi_name != "" )
	{
		c["opi_name"] = this->opi_name;
	}

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
		<< "storage-url: s3op://\n"
		<< "backend-login: NotUsed\n"
		<< "backend-password: NotUsed\n"
		<< "fs-passphrase: " << password<<"\n\n"

		<< "[local]\n"
		<< "storage-url: local://\n"
		<< "fs-passphrase: " << password<<endl;

	File::Write(BACKUP_PATH, ss.str(), 0600 );
}

bool ControlApp::SetupRestoreEnv()
{
	logg << Logger::Debug << "Setting up environment for restore"<<lend;
	// Make sure we have environment to work from.
	// TODO: Lot of duplicated code here :(
	// Generate temporary keys to use
	RSAWrapper ob;
	ob.GenerateKeys();

#define TMP_PRIV "/tmp/tmpkey.priv"
#define TMP_PUB "/tmp/tmpkey.pub"

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
	unlink( SYS_PRIV_PATH );
	unlink( SYS_PUB_PATH );

	if( symlink( TMP_PRIV , SYS_PRIV_PATH ) )
	{
		unlink( TMP_PRIV );
		unlink( TMP_PUB );
		logg << Logger::Notice << "Failed to symlink private key"<<lend;
		return false;
	}

	if( symlink( TMP_PUB , SYS_PUB_PATH ) )
	{
		unlink( SYS_PRIV_PATH );
		unlink( TMP_PRIV );
		unlink( TMP_PUB );
		logg << Logger::Notice << "Failed to symlink public key"<<lend;
		return false;
	}

	AuthServer s(this->unit_id);

	string challenge;
	int resultcode;
	tie(resultcode,challenge) = s.GetChallenge();

	if( resultcode != 200 )
	{
		unlink( SYS_PRIV_PATH );
		unlink( SYS_PUB_PATH );
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
		unlink( SYS_PRIV_PATH );
		unlink( SYS_PUB_PATH );
		unlink( TMP_PRIV );
		unlink( TMP_PUB );
		logg << Logger::Notice << "Failed to send challenge " << resultcode <<lend;
		return false;
	}

	challenge = ret["challange"].asString();

	SecVector<byte> key = PBKDF2(SecString(this->masterpassword.c_str(), this->masterpassword.size() ), 32 );
	AESWrapper aes( key );

	string cryptchal = Base64Encode( aes.Encrypt( challenge ) );

	tie(resultcode, ret) = s.SendSecret(cryptchal, Base64Encode( ob.PubKeyAsPEM() ) );

	if( resultcode != 200 )
	{
		unlink( SYS_PRIV_PATH );
		unlink( SYS_PUB_PATH );
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

Json::Value ControlApp::CheckRestore()
{
	logg << Logger::Debug << "Check if restore should be performed"<<lend;

	if( this->skiprestore )
	{
		return Json::nullValue;
	}

	if( Luks::isLuks( OPI_MMC_PART ) )
	{
		// We never do a restore if we have a luks partition on sd
		return Json::nullValue;
	}

	if( this->masterpassword == "" )
	{
		// Need password to be able to get backups
		return Json::nullValue;
	}


	if( ! this->backuphelper )
	{
		// Make sure we have no leftovers from earlier attempts
		this->CleanupRestoreEnv();

		if( ! this->SetupRestoreEnv() )
		{
			return Json::nullValue;
		}
		this->backuphelper = BackupHelperPtr( new BackupHelper( this->GetBackupPassword() ) );
	}
	else
	{
		// Entered password might have been changed
		this->backuphelper->SetPassword( this->GetBackupPassword() );
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
	}

	// Check remote
	if( this->backuphelper->MountRemote() )
	{
		list<string> remote = this->backuphelper->GetRemoteBackups();
		for( const auto& val: remote)
		{
			hasdata = true;
			retval["remote"].append(val);
		}
	}

	return hasdata ? retval : Json::nullValue ;

}

void ControlApp::CleanupRestoreEnv()
{
	logg << Logger::Debug << "Clean up restore environment"<<lend;

	if( this->backuphelper )
	{
		this->backuphelper->UmountLocal();
		this->backuphelper->UmountRemote();
	}

	if( File::LinkExists( SYS_PRIV_PATH ) )
	{
		unlink( SYS_PRIV_PATH );
	}

	if( File::LinkExists( SYS_PUB_PATH ) )
	{
		unlink( SYS_PUB_PATH );
	}

	unlink( TMP_PRIV );
	unlink( TMP_PUB );
}

bool ControlApp::DoRestore(const string &path)
{
	logg << Logger::Debug << "Do restore backup"<<lend;
	// Setup SD-card
	if( ! this->InitializeSD() )
	{
		this->global_error ="Restore backup - failed to initialize SD card";
		return false;
	}

	try
	{
		// We need access to underlying info of SD card
		// move mount
		// Make sure device is not mounted (Should not happen)
		if( DiskHelper::IsMounted( LUKSDEVICE ) != "" )
		{
			DiskHelper::Umount( LUKSDEVICE );
		}

		DiskHelper::Mount( LUKSDEVICE , TMP_MOUNT );
	}
	catch( ErrnoException& err)
	{
		logg << Logger::Error << "Failed to mount SD for backup: "<< err.what()<<lend;
		this->global_error = "Restore backup - Failed to access SD card";
		return false;
	}

	if( !this->backuphelper->RestoreBackup( path ) )
	{
		DiskHelper::Umount( LUKSDEVICE );
		this->global_error = "Restore Backup - restore failed";
		return false;
	}

	try
	{
		DiskHelper::Umount( LUKSDEVICE );
	}
	catch( ErrnoException& err)
	{
		logg << Logger::Error << "Failed to umount SD after backup: "<< err.what()<<lend;
		this->global_error = "Restore backup - Failed to remove SD card";
		return false;
	}

	return true;
}

void ControlApp::SetLedstate(ControlApp::Ledstate state)
{
#ifdef OPI_BUILD_PACKAGE
	switch( state )
	{
	case Ledstate::Error:
		this->leds.SetTrigger("usr3", "heartbeat");
		break;
	case Ledstate::Waiting:
		this->leds.SetTrigger("usr2", "heartbeat");
		break;
	case Ledstate::Completed:
		this->leds.SetTrigger("usr2", "none");
		this->leds.Brightness("usr2", true);
		break;
	default:
		break;
	}
#endif
}
