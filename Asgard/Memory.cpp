#include "Memory.h"
using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;


bool DLLEXPORT Memory::simpleInject(const char* dllPath, HANDLE proc)
{
    if (!proc || proc == INVALID_HANDLE_VALUE) return false;

    void* alloc = VirtualAllocEx(proc, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    bool a = WriteProcessMemory(proc, alloc, dllPath, strlen(dllPath) + 1,0);
    if (!a) return false;
    HANDLE thread = CreateRemoteThread(proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, alloc, NULL, NULL);

    if (thread) {
        CloseHandle(thread);
        return true;
    }
    if (proc) {
        CloseHandle(proc);
    }
    return false;

}

DWORD Memory::getProcId(std::string_view procName)
{
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(MODULEENTRY32);

    const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

    if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
        return NULL;

    while (Process32Next(snapshot_handle.get(), &procEntry) == TRUE) {
        if (procName.compare(procEntry.szExeFile) == NULL) {
            return procEntry.th32ProcessID;
        }
    }
    return NULL;
}

size_t Memory::getModuleSize(DWORD procId, const char* modName)
{
    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, procId));

    if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
        return NULL;

    while (Module32Next(snapshot_handle.get(), &moduleEntry) == TRUE) {
        if (!strncmp((char*)moduleEntry.szModule, modName, 8)) {
            return moduleEntry.modBaseSize;
        }
    }
    return NULL;
}

uintptr_t Memory::getDMAAddyEx(HANDLE proc, uintptr_t ptr, std::vector<unsigned int> offsets)
{
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        ReadProcessMemory(proc, (BYTE*)addr, &addr, sizeof(addr), 0);
        addr += offsets[i];
    }
    return addr;
}
uintptr_t Memory::getDMAAddy(uintptr_t ptr, std::vector<unsigned int> offsets)
{
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        addr = *(uintptr_t*)addr;
        addr += offsets[i];
    }
    return addr;
}

uintptr_t Memory::getModuleBaseAddr(DWORD procId, const char* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!strcmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

bool Memory::read(HANDLE proc, uintptr_t address, LPVOID buffer, size_t size)
{
    return ReadProcessMemory(proc, (void*)address, buffer, size, 0);
}

bool Memory::write(HANDLE proc, uintptr_t address, uintptr_t source_address, size_t write_size)
{
    return WriteProcessMemory(proc, (void*)address, (void*)source_address, write_size, NULL);
}

bool DLLEXPORT Memory::write(HANDLE proc, void* address, void* source_address, size_t write_size)
{
    return WriteProcessMemory(proc, address, source_address, write_size, NULL);
}

bool DLLEXPORT Memory::NOPFunctionEx(HANDLE proc, BYTE* dest, unsigned int size)
{
    BYTE* nopArray = new BYTE[size];
    memset(nopArray, NOP, size);

    patchFunctionEx(proc, dest, nopArray, size);
    delete[] nopArray;
    return true;
}

bool DLLEXPORT Memory::patchFunctionEx(HANDLE proc, BYTE* dest, BYTE* src, unsigned int size)
{
    DWORD oldProtect;
    VirtualProtectEx(proc, dest, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    Memory::write(proc, dest, src, size);
    VirtualProtectEx(proc, dest, size, oldProtect, &oldProtect);
    return true;
}

bool Memory::NOPFunction(BYTE* dest, unsigned int size)
{
    DWORD oldProtect;
    VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    memset(dest, NOP, size);
    VirtualProtect(dest, size, oldProtect, &oldProtect);
    return true;
}

bool DLLEXPORT Memory::patchFunction(BYTE* dest, BYTE* src, unsigned int size)
{
    DWORD oldProtect;
    VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(dest, src, size);
    VirtualProtect(dest, size, oldProtect, &oldProtect);
    return true;
}

uintptr_t KernelMemory::getModuleBaseAddr(DWORD procId, const char* modName)
{
    _INSTRUCTIONS instructions = { 0 };
    instructions.pid = procId;
    instructions.instruction = GETBASEADDRESS;
    instructions.module_name = modName;
    call_hook(&instructions);
    uintptr_t base = NULL;
    base = instructions.base_address;
    return base;
}


void KernelMemory::loadDriver() {
    if (std::filesystem::exists("kdmapper.exe")) {
        system("kdmapper.exe AsgardDriver.sys");
    }
}

uintptr_t KernelMemory::getDMAAddy(DWORD procId, uintptr_t ptr, std::vector<unsigned int> offsets)
{
    uintptr_t addr = ptr;
    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        KernelMemory::read(procId, addr, &addr, sizeof(addr));
        addr += offsets[i];
    }
    return addr;
}

void KernelMemory::read(DWORD procId, uintptr_t address,LPVOID buffer, size_t size) {

    _INSTRUCTIONS instructions = { 0 };
    instructions.pid = procId;
    instructions.size = size;
    instructions.address = address;
    instructions.instruction = READ;
    instructions.output = buffer;
    call_hook(&instructions);
}


bool KernelMemory::NOPFunction(DWORD procId, uintptr_t address, int bytes)
{
    for (int i = 0; i < bytes; i++) {
        KernelMemory::write<char>(procId, address, NOP);
        address += 0x1;
    }
   
    return true;
}

bool KernelMemory::write(DWORD procId, uintptr_t address, uintptr_t source_address, size_t write_size)
{
    _INSTRUCTIONS instructions = { 0 };

    instructions.pid = procId;
    instructions.size = write_size;
    instructions.address = address;
    instructions.instruction = WRITE;
    instructions.buffer_address = (void*)source_address;

    call_hook(&instructions);

    return true;
}

