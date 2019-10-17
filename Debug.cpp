#include "Debug.h"

#include <libutils/Logger.h>



// DEBUG
#include <csignal>
#include <string>
#include <map>

#include <csignal>

using namespace std;
using namespace Utils;

static map<int, string> sigmap =
{
	{ SIGHUP	," SIGHUP  "},
	{ SIGINT	," SIGINT  "},
	{ SIGQUIT	," SIGQUIT "},
	{ SIGILL	," SIGILL  "},
	{ SIGABRT	," SIGABRT "},
	{ SIGFPE	," SIGFPE  "},
	{ SIGKILL	," SIGKILL "},
	{ SIGSEGV	," SIGSEGV "},
	{ SIGPIPE	," SIGPIPE "},
	{ SIGALRM	," SIGALRM "},
	{ SIGTERM	," SIGTERM "},
	{ SIGUSR1	," SIGUSR1 "},
	{ SIGUSR2	," SIGUSR2 "},
	{ SIGCHLD	," SIGCHLD "},
	{ SIGCONT	," SIGCONT "},
	{ SIGSTOP	," SIGSTOP "},
	{ SIGTSTP	," SIGTSTP "},
	{ SIGTTIN	," SIGTTIN "},
	{ SIGTTOU 	," SIGTTOU "},
};

static map<int, string> flagmap =
{
	{SA_NOCLDSTOP	,"SA_NOCLDSTOP"},
	{SA_NOCLDWAIT	,"SA_NOCLDWAIT"},
	{SA_NODEFER		,"SA_NODEFER  "},
	{SA_ONSTACK		,"SA_ONSTACK  "},
	{SA_RESETHAND	,"SA_RESETHAND"},
	{SA_RESTART		,"SA_RESTART  "},
	{SA_SIGINFO		,"SA_SIGINFO  "}
};

#define OP logg << Logger::Info
#define ERR logg << Logger::Error
#define END lend
static void dump_sigaction(int signum, struct sigaction* act, bool blocked)
{
	OP << "Signal " << sigmap[signum];
	if(blocked)
	{
		OP << " is blocked " ;
	}
	else
	{
		OP << " is not blocked ";
	}
	OP << "Flags:   [";

	if ( act->sa_flags == 0 )
	{
		OP << "None] ";
	}
	else
	{
		for(auto flag: flagmap )
		{
			if( act->sa_flags & flag.first )
			{
				OP << flag.second;
			}
		}
		OP <<"] ";
	}

	if( ! (act->sa_flags & SA_SIGINFO) )
	{
		OP << "Handler: ";
		if( act->sa_handler == SIG_DFL)
		{
			OP << " Sig default ";
		}
		else if( act->sa_handler == SIG_IGN )
		{
			OP << " Sig ignore ";
		}
		else
		{
			OP << " User specified ";
			//OP << act->sa_handler << " ";
		}
	}
	else
	{
		//OP << "Actionhandler: " << act->sa_sigaction;
		OP << "Actionhandler: User specified ";
	}
	OP << END;
}

void dump_signals()
{
	sigset_t set;

	if( sigprocmask(SIG_BLOCK, nullptr, &set) < 0 )
	{
		ERR << "Failed to retrieve sigset" << END;
		return;
	}

	for(auto sig: sigmap)
	{
		struct sigaction act;

		if( sigaction(sig.first, nullptr, &act) < 0 )
		{
			ERR << "Failed to retrieve sigaction"<<END;
			continue;
		}

		dump_sigaction(sig.first, &act, sigismember(&set, sig.first) );
	}
}
// END DEBUG
