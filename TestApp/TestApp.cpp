#include "Memory.h"
#include "Scanner.h"
//setup --
// 
//Project Configuration -> General -> C++ Language Standard -> ISO C++20 Standard (/std:c++20)
//Project Configuration -> Advanced -> Character Set -> Not Set
//Project Configuration -> Linker -> Input -> Additional Dependencies -> Asgard.lib;
//Project Configuration -> Linker -> General -> Additional Library Directories -> (path to Asgard.lib)
//Project Configuration -> C++ -> General -> Additional Include Directories -> (path to the Asgard header Files)
//

int main()
{
	
	//test code for wesnoth 1.14.9
	DWORD procid = Memory::getProcId("wesnoth.exe");
	if (procid) {
		std::cout << procid;

		//check test dll source
		HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procid);
		bool a = Memory::simpleInject("C:\\source\\repos\\Asgard\\Release\\Asgard.dll", handle);
		bool b =  Memory::simpleInject("C:\\source\\repos\\Asgard\\Release\\TestDLL.dll", handle);
		std::cout << (a ? "t" : "f");
	}
	Sleep(5000);
}