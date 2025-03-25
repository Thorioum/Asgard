#include "Memory.h"
#include "Scanner.h"
#include "AsgardUtils.h"
//setup --
// 
//Project Configuration -> General -> C++ Language Standard -> ISO C++20 Standard (/std:c++20)
//Project Configuration -> Advanced -> Character Set -> Not Set
//Project Configuration -> Linker -> Input -> Additional Dependencies -> Asgard.lib;
//Project Configuration -> Linker -> General -> Additional Library Directories -> (path to Asgard.lib)
//Project Configuration -> C++ -> General -> Additional Include Directories -> (path to the Asgard header Files)
//
static void kernelTest() {
    
    KernelMemory::loadDriver();
    MessageBox(NULL, "kernel function hooked!", "yipee", NULL);

    DWORD procId = Memory::getProcId("wesnoth.exe");
    if (procId) {
        ScanData signature = ScanData("29 42 ? 80 BD");
        size_t size = Memory::getModuleSize(procId, "wesnoth.exe");
        ScanData data = ScanData(size);

        uintptr_t moduleBaseAddr = KernelMemory::getModuleBaseAddr(procId, "wesnoth.exe");

        KernelMemory::read(procId, moduleBaseAddr, data.data, data.size);

        uintptr_t patternAddr = Scanner::scan(signature, data);

        if (patternAddr) {
            MessageBox(NULL, "found pattern at: ", AsgardUtils::uintptrToString(patternAddr).c_str(), NULL);
            //add [edx+4] eax
            KernelMemory::patchFunction(procId, moduleBaseAddr + patternAddr, (BYTE*)"\x01\x42\x04", 3);

            while (!GetAsyncKeyState(VK_END)) {
                Sleep(10);
            }
            //original instruction                                               //sub [edx+4] eax 
            KernelMemory::patchFunction(procId, moduleBaseAddr + patternAddr, (BYTE*)"\x29\x42\x04", 3);

            MessageBox(NULL, "finished patching: ", AsgardUtils::uintptrToString(patternAddr).c_str(), NULL);
        }
        else {
            MessageBox(NULL, "failed to find pattern", "", NULL);
        }

    }
    else {

    }
}
static void dllTest() {
	DWORD procid = Memory::getProcId("wesnoth.exe");
	if (procid) {
		std::cout << procid;

		//check test dll source
		HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procid);
		bool a = Memory::simpleInject("C:\\source\\repos\\Asgard\\Release\\Asgard.dll", handle);
		bool b = Memory::simpleInject("C:\\source\\repos\\Asgard\\Release\\TestDLL.dll", handle);
		std::cout << (a ? "t" : "f");
        std::cout << (b ? "t" : "f");
	}
	Sleep(5000);
}
int main()
{
    //test code for wesnoth 1.14.9 will make soldiers you recruit add money instead of subtract

    kernelTest();

}