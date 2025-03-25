#pragma once
#include "definitions.h"

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


namespace mem {
    PVOID GetModuleBase(const char* module_name);
    PVOID GetModuleExport(const char* module_name, LPCSTR routine_name);
    bool WriteMemory(void* address, void* buffer, size_t size);
    bool WriteReadOnlyMemory(void* addres, void* buffer, size_t size);
    ULONG64 GetModuleBase64(PEPROCESS proc, UNICODE_STRING module_name);
    NTSTATUS ReadKernelMemory(ULONG pid, UINT_PTR address, void* buffer, UINT_PTR size);
    bool WriteKernelMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size);
};