#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOP 0x90
#define DLLEXPORT __declspec(dllexport)
#include <iostream>
#include <Windows.h>
#include <memory>
#include <regex>
#include <string_view>
#include <cstdint>
#include <vector>
#include <iomanip>
#include <sstream>
#include <psapi.h>
#include <tlhelp32.h>
#include <list>
#include <filesystem>

enum _INSTRUCTION {
    READ,
    WRITE,
    GETBASEADDRESS
};
typedef struct _INSTRUCTIONS {

    void* buffer_address;

    UINT_PTR address;
    UINT_PTR size;
    ULONG pid;
    const char* module_name;
    ULONG base_address;
    _INSTRUCTION instruction;

    void* output;
} _INSTRUCTIONS;

struct HandleDisposer {
    using pointer = HANDLE;
    void operator()(HANDLE handle) const {
        if (handle != NULL && handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
        }
    }
};

//ex at the end of functions means external, use those if you arent in the kernel, or havent done something like dll injection
namespace Memory {
    bool DLLEXPORT simpleInject(const char* dllPath, HANDLE proc);

    DWORD DLLEXPORT getProcId(std::string_view procName);

    size_t DLLEXPORT getModuleSize(DWORD procId, const char* modName);

    uintptr_t DLLEXPORT getDMAAddyEx(HANDLE proc, uintptr_t ptr, std::vector<unsigned int> offsets);

    uintptr_t DLLEXPORT getDMAAddy(uintptr_t ptr, std::vector<unsigned int> offsets);


    uintptr_t DLLEXPORT getModuleBaseAddr(DWORD procId, const char* modName);

    bool DLLEXPORT read(HANDLE proc, uintptr_t address, LPVOID buffer, size_t size);

    template<class R> DLLEXPORT
        R read(HANDLE proc, uintptr_t address) {
        R response{};
        read(proc, address, &response, sizeof(R));
        return response;
    }

    bool DLLEXPORT write(HANDLE proc, uintptr_t address, uintptr_t source_address, size_t write_size);

    bool DLLEXPORT write(HANDLE proc, void* address, void* source_address, size_t write_size);

    template<typename W> DLLEXPORT
        bool write(HANDLE proc, uintptr_t address, const W& value)
    {
        return write(proc, address, (uintptr_t)&value, sizeof(W));
    }


    bool DLLEXPORT NOPFunctionEx(HANDLE proc, BYTE* dest, unsigned int size);

    bool DLLEXPORT patchFunctionEx(HANDLE proc, BYTE* dest, BYTE* src, unsigned int size);

    bool DLLEXPORT NOPFunction(BYTE* dest, unsigned int size);

    bool DLLEXPORT patchFunction(BYTE* dest, BYTE* src, unsigned int size);
};
namespace KernelMemory {

    void DLLEXPORT loadDriver();

    template<typename ...Arg> DLLEXPORT
        uint64_t call_hook(const Arg ...args) {

        void* hooked_func = GetProcAddress(LoadLibrary("win32u.dll"), "NtDxgkGetTrackedWorkloadStatistics");
       
        auto func = static_cast<uint64_t(__stdcall*)(Arg...)>(hooked_func);
        return func(args...);
    }

    uintptr_t DLLEXPORT getDMAAddy(DWORD procId, uintptr_t ptr, std::vector<unsigned int> offsets);

    uintptr_t DLLEXPORT getModuleBaseAddr(DWORD procId, const char* modName);



    void DLLEXPORT read(DWORD procId, uintptr_t address, LPVOID buffer, size_t size);

    template<class R> DLLEXPORT
        R read(DWORD procId, uintptr_t address) {

        R response{};
        _INSTRUCTIONS instructions = { 0 };
        instructions.pid = procId;
        instructions.size = sizeof(R);
        instructions.address = address;
        instructions.instruction = READ;
        instructions.output = &response;
        call_hook(&instructions);

        return response;
    }
    bool DLLEXPORT write(DWORD procId, uintptr_t address, uintptr_t source_address, size_t write_size);

    template<typename W> DLLEXPORT
        bool write(DWORD procId, uintptr_t address, const W& value)
    {
        return write(procId, address, (uintptr_t)&value, sizeof(W));
    }

    bool DLLEXPORT NOPFunction(DWORD procId, uintptr_t address, int bytes);
    bool DLLEXPORT patchFunction(DWORD procId, uintptr_t address, BYTE* src, int bytes);

};