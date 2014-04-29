#include <unistd.h>
#include <libutils/Logger.h>

#include "ControlApp.h"

using namespace Utils;

int main(int argc, char** argv)
{
	int ret = 0;
	try{

		logg.SetLevel(Logger::Debug);

		ControlApp c;

		ret = c.Start(argc, argv);
	}
	catch( std::runtime_error& err)
	{
		logg << Logger::Error << "Caught exception " << err.what() << lend;
	}

	return ret;
}
