#ifndef EVENTHANDLER_H
#define EVENTHANDLER_H

#include <functional>
#include <memory>
#include <string>
#include <queue>

using namespace std;

struct Event
{
	Event(int i, const function<void()> call): prio(i), call(call){	}
	int prio;
	function<void()> call;
};
typedef shared_ptr<Event> EventPtr;


struct Comparator
{
	bool operator()(const EventPtr& lhs, const EventPtr& rhs)
	{
		return lhs->prio > rhs->prio;
	}
};

typedef std::priority_queue<EventPtr,std::vector<EventPtr>, Comparator> EventQueue;

class EventHandler
{
public:
	void AddEvent(int prio, function<void()> callback)
	{
		this->queue.push(EventPtr( new Event(prio, callback)));
	}

	void CallEvents()
	{
		while( ! this->queue.empty() )
		{
			this->queue.top()->call();
			this->queue.pop();
		}
	}

private:
	EventQueue queue;
};

#endif // EVENTHANDLER_H
