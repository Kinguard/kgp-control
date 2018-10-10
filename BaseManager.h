#ifndef BASEMANAGER_H
#define BASEMANAGER_H

#include <libutils/ClassTools.h>

#include <string>

using namespace std;

class BaseManager: public Utils::NoCopy
{
public:


	/**
	 * @brief StrError
	 * @return last reported error message
	 */
	string StrError();


	virtual ~BaseManager();
protected:
	BaseManager();

	string global_error;
};

#endif // BASEMANAGER_H
