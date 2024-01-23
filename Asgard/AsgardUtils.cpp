#include "AsgardUtils.h"

std::string AsgardUtils::longptrToString(ULONG64 address)
{
	std::stringstream ss;
	ss << std::hex << address;
	return "0x" + ss.str();
}
std::string AsgardUtils::uintptrToString(uintptr_t address)
{
	std::stringstream ss;
	ss << std::hex << address;
	return "0x" + ss.str();
}
