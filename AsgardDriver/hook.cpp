#include "hook.h"

bool hook::call_kernel_function(void* kernel_function_address)
{
    if (!kernel_function_address) {
        DbgPrint("Invalid kernel_function_address\n");
        return false;
    }

    PVOID* function = reinterpret_cast<PVOID*>(mem::GetModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtDxgkGetTrackedWorkloadStatistics"));

    if (!function) {
        DbgPrint("kernel function grab failed\n");
        return false;
    }
    BYTE orig[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

    BYTE shell_code[] = { 0x48, 0xB8 }; // mov rax, xxx
    BYTE shell_code_end[] = { 0xFF, 0xE0 }; //jmp rax          //detected by anti cheats. should change real

    RtlSecureZeroMemory(&orig, sizeof(orig));
    memcpy((PVOID)((ULONG_PTR)orig), &shell_code, sizeof(shell_code));
    uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
    memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));

    mem::WriteReadOnlyMemory(function, &orig, sizeof(orig));

    return true;
}
NTSTATUS hook::hook_handler(PVOID called_param) {
    
    _INSTRUCTIONS* instructions = (_INSTRUCTIONS*)called_param;


    switch (instructions->instruction)
    {
        case READ: {
            if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0) {
                mem::ReadKernelMemory(instructions->pid, instructions->address, instructions->output, instructions->size);                             
            }
            return STATUS_SUCCESS;
        }
        case WRITE: {
            if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0) {
                PVOID kernelBuff = ExAllocatePool(NonPagedPool, instructions->size);
                if (!kernelBuff) {
                    return STATUS_UNSUCCESSFUL;
                }
                if (!memcpy(kernelBuff, instructions->buffer_address, instructions->size)) {
                    return STATUS_UNSUCCESSFUL;
                }

                PEPROCESS process;
                PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
                mem::WriteKernelMemory((HANDLE)instructions->pid, instructions->address, kernelBuff, instructions->size);
                ExFreePool(kernelBuff);
            }
            return STATUS_SUCCESS;
        }
        case GETBASEADDRESS: {
            ANSI_STRING AS;
            UNICODE_STRING ModuleName;

            RtlInitAnsiString(&AS, instructions->module_name);
            RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

            PEPROCESS process;
            if (PsLookupProcessByProcessId((HANDLE)instructions->pid, &process) != STATUS_SUCCESS)
                return NULL;
            ULONG64 base_address64 = NULL;

            base_address64 = mem::GetModuleBase64(process, ModuleName);
            instructions->base_address = base_address64;
            RtlFreeUnicodeString(&ModuleName);
        }
    }
    return STATUS_SUCCESS;
}
