#include "LedControl.h"

#include <libutils/String.h>
#include <libutils/FileUtils.h>

#include <iostream>
#include <stdexcept>
#include <algorithm>

using namespace std;
using namespace Utils;

Led::Led(const string& path): path(path)
{
	list<string> parts = String::Split( File::GetFileName( path ), ":" );

	if( parts.size()  != 3 )
	{
		throw runtime_error("Unknown format on led dir");
	}

	this->ns = parts.front();
	parts.pop_front();

	this->color = parts.front();
	parts.pop_front();

	this->name = parts.front();
	parts.pop_front();

	this->parseTrigger();

}

list<string> Led::Triggers()
{
	return this->triggers;
}

string Led::CurrentTrigger()
{
	return this->set_trigger;
}

void Led::SetTrigger(const string &trigger)
{
	if( find(this->triggers.begin(), this->triggers.end(), trigger ) == this->triggers.end() )
	{
		throw runtime_error("No such trigger available");
	}

	File::Write(this->path+"/trigger", trigger, 0644);

	this->set_trigger = trigger;
}

string Led::Color()
{
	return this->color;
}

string Led::Name()
{
	return this->name;
}

string Led::NS()
{
	return this->ns;
}

bool Led::Brightness()
{
	return this->brightness;
}

void Led::Brightness(bool bright)
{
	File::Write(this->path+"/brightness", to_string(bright), 0644);
	this->brightness = bright;
}

void Led::dump()
{
	cout << "-----------------------------"<<endl;
	cout << "Name  : "<< this->name << endl;
	cout << "Color : "<< this->color << endl;
	cout << "Ns    : "<< this->ns << endl;
	for( auto trig: this->triggers )
	{
		cout << trig << " ";
	}
	cout << endl;
	cout << "Trigger "<< this->set_trigger<<endl;
}

Led::~Led()
{

}

void Led::parseTrigger()
{
	string trg = File::GetContentAsString( this->path+"/trigger");

	list<string> tmp_triggers = String::Split( trg, " ");

	for( const string& trigg: tmp_triggers )
	{
		if( trigg[0] == '[')
		{
			this->set_trigger = String::Trimmed(trigg, "[]");
		}
		this->triggers.push_back( String::Trimmed(trigg, "[]") );
	}

}

/*
 * Implementation of LedControl
 */

LedControl::LedControl(const string basepath): basepath(basepath)
{
	list<string> ledpaths = File::Glob( this->basepath+"/*");
	list<Led> llist;

	for( const string& led: ledpaths)
	{
		LedPtr l(new Led(led));
		this->leds[ l->Name() ] = l;
	}
}

list<string> LedControl::LedNames()
{
	list<string> l;
	for( auto led: this->leds )
	{
		l.push_back( led.first );
	}
	return l;
}

list<string> LedControl::Triggers(const string &name)
{
	return this->leds[name]->Triggers();
}

string LedControl::CurrentTrigger(const string &name)
{
	return this->leds[name]->CurrentTrigger();
}

void LedControl::SetTrigger(const string &name, const string &trigger)
{
	this->leds[name]->SetTrigger(trigger);
}

bool LedControl::Brightness(const string &name)
{
	return this->leds[name]->Brightness();
}

void LedControl::Brightness(const string &name, bool bright)
{
	this->leds[name]->Brightness( bright);
}

LedControl::~LedControl()
{

}
