
#include <stdlib.h>
#include <string>

#include <stdlib.h>

#include <libutils/FileUtils.h>
#include <libutils/String.h>

using namespace std;
using namespace Utils;

static int do_call(const string& cmd){
		int ret=system(cmd.c_str());
		if(ret<0){
				return ret;
		}
		return WEXITSTATUS(ret);
}


namespace ServiceHelper {

bool Start(const string& service)
{
	return do_call("/etc/init.d/"+service+" start >/dev/null")==0;
}

bool Stop(const string& service)
{
	return do_call("/etc/init.d/"+service+" stop >/dev/null")==0;
}

pid_t GetPid(const string& service)
{
	string pidfile;
	pid_t pid=0;

	pidfile="/var/run/"+service+".pid";

	if( File::FileExists( pidfile ) )
	{
		string s_pid=String::Chomp(File::GetContentAsString(pidfile));

		if(File::DirExists("/proc/"+s_pid))
		{
			pid=atoi(s_pid.c_str());
		}
	}

	return pid;
}


bool IsRunning(const string &service)
{
	return GetPid(service)!=0;
}

}

