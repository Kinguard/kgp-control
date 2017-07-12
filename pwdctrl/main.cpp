
#include "PwdCtrlApp.h"

using namespace Utils;

int main(int argc, char *argv[])
{
	int ret = 0;

	try
	{
		PwdCtrlApp app;

		logg.SetLevel( Logger::Info);

		ret = app.Start( argc, argv);
	}
	catch( std::runtime_error& err)
	{
		logg << Logger::Error << "Caught exception " << err.what() << lend;
	}

	return ret;
}
