#ifndef LEDCONTROL_H
#define LEDCONTROL_H

#include <memory>
#include <string>
#include <list>
#include <map>

using namespace std;

class Led
{
public:
	Led();
	Led(const string& path);

	list<string> Triggers();
	string CurrentTrigger();

	void SetTrigger( const string& trigger);

	bool Brightness();
	void Brightness(bool bright);

	string Color();
	string Name();
	string NS();

	void dump();

	virtual ~Led();
private:

	void parseTrigger();

	list<string> triggers;
	string set_trigger;
	bool brightness;

	string path;

	string name;
	string ns;
	string color;

};

typedef shared_ptr<Led> LedPtr;

class LedControl
{
public:
	LedControl(const string basepath = "/sys/class/leds");

	list<string> LedNames();


	list<string> Triggers(const string& name);
	string CurrentTrigger(const string& name);

	void SetTrigger( const string& name, const string& trigger);

	bool Brightness(const string& name);
	void Brightness(const string& name, bool bright);


	virtual ~LedControl();
private:
	string basepath;
	map<string, LedPtr> leds;
};

#endif // LEDCONTROL_H
