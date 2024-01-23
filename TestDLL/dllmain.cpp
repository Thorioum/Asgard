#include "Scanner.h"
#include "Memory.h"
#include "AsgardUtils.h"

//setup --
// 
//Project Configuration -> General -> C++ Language Standard -> ISO C++20 Standard (/std:c++20)
//Project Configuration -> Advanced -> Character Set -> Not Set
//Project Configuration -> Linker -> Input -> Additional Dependencies -> Asgard.lib;
//Project Configuration -> Linker -> General -> Additional Library Directories -> (path to Asgard.lib)
//Project Configuration -> C++ -> General -> Additional Include Directories -> (path to the Asgard header Files)
//

DWORD WINAPI MainThread(HMODULE hmodule) {
    MessageBox(NULL, "injected!", "yipee", NULL);

    DWORD procId = Memory::getProcId("wesnoth.exe");
    HANDLE wesnoth = GetCurrentProcess();
    if (wesnoth) {
        ScanData signature = ScanData("29 42 ? 80 BD");
        size_t size = Memory::getModuleSize(procId, "wesnoth.exe");
        ScanData data = ScanData(size);

        uintptr_t moduleBaseAddr = Memory::getModuleBaseAddr(procId, "wesnoth.exe");

        Memory::read(wesnoth, moduleBaseAddr, data.data, data.size);

        uintptr_t patternAddr = Scanner::scan(signature, data);

        if (patternAddr) {
            MessageBox(NULL, "found pattern at: ", AsgardUtils::uintptrToString(patternAddr).c_str(), NULL);
                                                                                 //add [edx+4] eax
            Memory::patchFunction((BYTE*)(moduleBaseAddr + patternAddr), (BYTE*)"\x01\x42\x04", 3);

            while (!GetAsyncKeyState(VK_END)) {
                Sleep(10);
            }
            //original instruction                                               //sub [edx+4] eax 
            Memory::patchFunction((BYTE*)(moduleBaseAddr + patternAddr), (BYTE*)"\x29\x42\x04", 3);
        }


    }

    FreeLibraryAndExitThread(hmodule, 0);
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr));
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

