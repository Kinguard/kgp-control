#ifndef INBOUNDTEST_H
#define INBOUNDTEST_H

#include <vector>
#include <memory>

#include <libutils/ClassTools.h>

using namespace std;
using namespace Utils;

class TcpServer;
typedef shared_ptr<TcpServer> TcpServerPtr;

class InboundTest : public NoCopy
{
public:
	InboundTest(const vector<int>& ports);

	void Start();

	void Stop();

	virtual ~InboundTest();
private:
	vector<TcpServerPtr> servers;

};

typedef shared_ptr<InboundTest> InboundTestPtr;


#endif // INBOUNDTEST_H
