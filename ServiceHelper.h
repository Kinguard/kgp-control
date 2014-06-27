#ifndef SERVICEHELPER_H
#define SERVICEHELPER_H

namespace ServiceHelper {

bool Start(const string& service);

bool Stop(const string& service);

bool IsRunning(const string& service);

pid_t GetPid(const string& service);


}

#endif // SERVICEHELPER_H
