#ifndef CONTROLSTATE_H
#define CONTROLSTATE_H

#include <libutils/StateMachine.h>
#include <json/json.h>

#include <memory>

using namespace Utils;

class ControlApp;

class ControlData: public EventData
{
public:
	ControlData(Json::Value data): EventData(), data(data) {}
	ControlData(): ControlData(Json::nullValue) {}

	Json::Value data;

	virtual ~ControlData() {}
};

class ControlState : public StateMachine
{
public:
	ControlState(ControlApp* app);

	struct State
	{
		enum
		{
			InitCheckRestore=1,	//  1
			Init,				//  2
			ReInitCheckrestore,	//  3
			ReInit,				//  4
			AskRestore,			//  5
			Restore,			//  6
			AddUser,			//  7
			OpiName,			//  8
			AskUnlock,			//  9
			Unlock,				// 10
			Terminate,			// 11
			ShutDown,			// 12
			Reboot,				// 13
			Completed,			// 14
			Idle,				// 15
			Error,				// 16
		};
	};

	// External events
	void Init(bool savepassword);
	void ReInit(bool savepassword);
	void Restore(bool dorestore, const string& path);
	void AddUser();
	void OpiName();
	void Unlock(const string& password, bool save);
	void Terminate();
	void ShutDown(const string& action);

	void ResetReturnData();

	uint8_t State();
	tuple<bool, Json::Value> RetValue();

	~ControlState();
protected:
	void StIdle(EventData* data);
	void StInitCheckRestore(EventData* data);
	void StInit(EventData* data);
	void StReInitCheckrestore(EventData* data);
	void StReInit(EventData* data);
	void StRestore(EventData* data);
	void StAskRestore(EventData* data);
	void StAddUser(EventData* data);
	void StOpiName(EventData* data);
	void StAskUnlock(EventData* data);
	void StDoUnlock(EventData* data);
	void StTerminate(EventData* data);
	void StShutDown(EventData* data);
	void StReboot(EventData* data);
	void StCompleted(EventData* data);

private:
	bool ValidState(vector<uint8_t> vals);
	bool status;
	Json::Value retvalue;
	ControlApp* app;
};

typedef shared_ptr<ControlState> ControlStatePtr;


#endif // CONTROLSTATE_H
