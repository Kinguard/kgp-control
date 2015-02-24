#include "ControlState.h"

#include <libutils/Process.h>
#include <libopi/Secop.h>
#include <libopi/Luks.h>

#include "ControlApp.h"
#include "Config.h"

using namespace OPI;
using namespace Utils;

class ScopedLog
{
public:
	ScopedLog() = delete;
	ScopedLog(const ScopedLog&) = delete;
	ScopedLog& operator=(const ScopedLog&) = delete;

	ScopedLog(const string& message, Logger::LogLevel level = Logger::Debug): msg(message), level(level)
	{
		logg << this->level << "ControlState " << this->msg << " : started"<< lend;
	}


	virtual ~ScopedLog()
	{
		logg << this->level << "ControlState " << this->msg << " : completed"<< lend;
	}
private:
	string msg;
	Logger::LogLevel level;
};

ControlState::ControlState(ControlApp *app): app(app)
{
	this->statemap =
	{
		{ State::Idle,				std::bind( &ControlState::StIdle, this, std::placeholders::_1 )},
		{ State::InitCheckRestore,	std::bind( &ControlState::StInitCheckRestore, this, std::placeholders::_1 )},
		{ State::Init,				std::bind( &ControlState::StInit, this, std::placeholders::_1 )},
		{ State::ReInitCheckrestore,	std::bind( &ControlState::StReInitCheckrestore, this, std::placeholders::_1 )},
		{ State::ReInit,			std::bind( &ControlState::StReInit, this, std::placeholders::_1 )},
		{ State::AskRestore,		std::bind( &ControlState::StAskRestore, this, std::placeholders::_1 )},
		{ State::Restore,			std::bind( &ControlState::StRestore, this, std::placeholders::_1 )},
		{ State::AskUnlock,			std::bind( &ControlState::StAskUnlock, this, std::placeholders::_1 )},
		{ State::Unlock,			std::bind( &ControlState::StDoUnlock, this, std::placeholders::_1 )},
		{ State::Terminate,			std::bind( &ControlState::StTerminate, this, std::placeholders::_1 )},
		{ State::ShutDown,			std::bind( &ControlState::StShutDown, this, std::placeholders::_1 )},
		{ State::Reboot,			std::bind( &ControlState::StReboot, this, std::placeholders::_1 )},
		{ State::Completed,			std::bind( &ControlState::StCompleted, this, std::placeholders::_1 )},
	};

	this->state = State::Idle;
}

/*
 * External events
 */
void ControlState::Init(bool savepassword)
{
	ScopedLog l("Init");

	if( ! this->ValidState( {State::Idle, State::Init} ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}
	ControlData *data = new ControlData;
	data->data["savepassword"] = savepassword;

	this->TriggerEvent( ControlState::State::InitCheckRestore, data );
}

void ControlState::ReInit(bool savepassword)
{
	ScopedLog l("Reinit");

	if( ! this->ValidState( {State::Idle, State::ReInit} ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}
	ControlData *data = new ControlData;
	data->data["savepassword"] = savepassword;

	this->TriggerEvent( ControlState::State::ReInitCheckrestore, data );

}

void ControlState::Restore(bool dorestore, const string &path)
{
	ScopedLog l("Restore");

	if( ! this->ValidState( {State::AskRestore } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData *data = new ControlData;
	data->data["restore"] = dorestore;
	data->data["path"] = path;

	this->TriggerEvent( State::Restore, data );
}

void ControlState::Unlock(const string &password, bool save)
{
	ScopedLog l("Unlock");

	if( ! this->ValidState( {State::Idle, State::AskUnlock } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData *data = new ControlData;
	data->data["password"] = password;
	data->data["save"] = save;

	this->TriggerEvent( State::Unlock, data );
}

void ControlState::Terminate()
{
	ScopedLog l("Terminate");

	if( ! this->ValidState( {State::Idle, State::Completed } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	this->TriggerEvent( State::Terminate, nullptr);
}

void ControlState::ShutDown(const string &action)
{
	ScopedLog l("Shutdown");

/* TODO: check which states
	if( ! this->ValidState( {State::Idle, State::Completed } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}
*/

	if( action == "shutdown")
	{
		this->TriggerEvent( State::ShutDown, nullptr );
	}
	else if( action == "reboot" )
	{
		this->TriggerEvent( State::Reboot, nullptr );
	}
	else
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
	}
}

void ControlState::ResetReturnData()
{
	this->status = true;
	this->retvalue = Json::objectValue;
}

uint8_t ControlState::State()
{
	return this->state;
}

tuple<bool, Json::Value> ControlState::RetValue()
{
	return make_tuple(this->status, this->retvalue);
}

ControlState::~ControlState()
{

}

/*
 * State handlers
 */
void ControlState::StIdle(EventData *data)
{
	ScopedLog l("StIdle");

}

void ControlState::StInitCheckRestore(EventData *data)
{
	ScopedLog l("StInitCheckrestore");

	ControlData *arg = dynamic_cast<ControlData*>(data);

	Json::Value ret = this->app->CheckRestore();

	if( ret != Json::nullValue )
	{
		this->retvalue = ret;
		this->RegisterEvent( State::AskRestore, nullptr );
	}
	else
	{
		this->RegisterEvent( State::Init, new ControlData(arg->data));
	}

}

void ControlState::StInit(EventData *data)
{
	ScopedLog l("StInit");

	ControlData *arg = dynamic_cast<ControlData*>(data);

	if( this->app->DoInit( arg->data["savepassword"].asBool() ) )
	{
		Secop s;
		s.SockAuth();
		vector<string> users = s.GetUsers();

		if( users.size() > 0 )
		{
			// We have users on SD, skip register user
			if( this->app->GuessOPIName() && this->app->SetDNSName( this->app->opi_name ) )
			{
				this->RegisterEvent( State::Completed, nullptr );
			}
			else
			{
				this->RegisterEvent( State::OpiName, nullptr);
			}
			this->app->evhandler.AddEvent( 50, std::bind( Process::Exec, "/bin/run-parts --lsbsysinit  -- /etc/opi-control/reinstall"));
		}
		else
		{
			this->RegisterEvent( State::AddUser, nullptr );
		}
		// TODO: try reuse opi-name and opi_unitid
	}
	else
	{
		// Stay in this state
	}

}

void ControlState::StReInitCheckrestore(EventData *data)
{
	ScopedLog l("StInitCheckrestore");

	ControlData *arg = dynamic_cast<ControlData*>(data);

	Json::Value ret = this->app->CheckRestore();

	if( ret != Json::nullValue )
	{
		this->retvalue = ret;
		this->RegisterEvent( State::AskRestore, nullptr );
	}
	else
	{
		this->RegisterEvent( State::ReInit, new ControlData(arg->data));
	}

}

void ControlState::StReInit(EventData *data)
{
	ScopedLog l("StReInit");

	//TODO: Implement
}

void ControlState::StRestore(EventData *data)
{
	ScopedLog l("StRestore");

	ControlData *arg = dynamic_cast<ControlData*>(data);

	if( arg->data["restore"].asBool() )
	{
		if( this->app->DoRestore( arg->data["path"].asString() ) )
		{
			if( this->app->DoInit( false ) )
			{
				this->RegisterEvent( State::Completed, nullptr);
			}
		}

		// Clean up after restore, umount etc
		this->app->CleanupRestoreEnv();

		if( this->state != State::Completed )
		{
			// Restore failed return to previous state
			// TODO: howto handle failure?
			//status = false;

			// Figure out what state to return to
			if( ! Luks::isLuks( OPI_MMC_PART ) )
			{
				this->RegisterEvent( State::ReInit, nullptr);
			}
			else
			{
				this->RegisterEvent( State::Init, nullptr);
			}
		}
	}
	else
	{
		// Mark that user don't want to restore
		this->app->skiprestore = true;

		// Figure out what state to return to
		if( ! Luks::isLuks( OPI_MMC_PART ) )
		{
			this->RegisterEvent( State::ReInit, nullptr);
		}
		else
		{
			this->RegisterEvent( State::Init, nullptr);
		}
	}
}

void ControlState::StAskRestore(EventData *data)
{
	ScopedLog l("StAskRestore");

}

void ControlState::StAskUnlock(EventData *data)
{
	ScopedLog l("StAskUnlock");

}

void ControlState::StDoUnlock(EventData *data)
{
	ScopedLog l("StDoUnlock");

	ControlData *arg = dynamic_cast<ControlData*>(data);

	if( this->app->DoUnlock(arg->data["password"].asString(), arg->data["save"].asBool() ) )
	{
		this->RegisterEvent( State::Completed, nullptr);
	}
	else
	{
		this->status = false;
		this->RegisterEvent( State::AskUnlock, nullptr);
	}
}

void ControlState::StTerminate(EventData *data)
{
	ScopedLog l("StTerminate");

	this->app->ws->Stop();
}

void ControlState::StShutDown(EventData *data)
{
	ScopedLog l("StShutdown");

	this->app->ws->Stop();
}

void ControlState::StReboot(EventData *data)
{
	ScopedLog l("StReboot");

	this->app->ws->Stop();

	this->retvalue["url"] = "/";
	this->retvalue["timeout"] = 50;
}

void ControlState::StCompleted(EventData *data)
{
	ScopedLog l("StCompleted");

}

bool ControlState::ValidState(vector<uint8_t> vals)
{
	for( uint8_t val: vals)
	{
		if( val == this->state )
		{
			return true;
		}
	}
	return false;
}

