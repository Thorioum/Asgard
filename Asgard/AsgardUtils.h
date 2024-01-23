#pragma once
#include <sstream>
#include <intsafe.h>
#define DLLEXPORT __declspec(dllexport)
class AsgardUtils {
public:
	static DLLEXPORT std::string longptrToString(ULONG64 address);
	static DLLEXPORT std::string uintptrToString(uintptr_t address);
private:


};
