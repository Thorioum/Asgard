#include "hook.h"

bool hook::call_kernel_function(void* kernel_function_address)
{
    LOG("Mapping driver into memory. . .");

    if (!kernel_function_address) {
        LOG("Invalid kernel_function_address\n");
        return false;
    }

	void** function = reinterpret_cast<void**>(mem::GetModuleExport("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtDxgkGetTrackedWorkloadStatistics"));

    if (!function) {
        LOG("kernel function grab failed\n");
        return false;
    }
    unsigned char mov_rax[] = { 0x48, 0xB8 };
    unsigned char jmp_rax[] = { 0xFF, 0xE0 };

    unsigned char original_fn[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    RtlSecureZeroMemory(&original_fn, sizeof(original_fn));
    memcpy((void*)((ULONG_PTR)original_fn), &mov_rax, sizeof(mov_rax));

    uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
    memcpy((void*)((ULONG_PTR)original_fn + sizeof(mov_rax)), &hook_address, sizeof(void*));
    memcpy((void*)((ULONG_PTR)original_fn + sizeof(mov_rax) + sizeof(void*)), &jmp_rax, sizeof(jmp_rax));

    mem::WriteReadOnlyMemory(function, &original_fn, sizeof(original_fn));

    LOG("Mapped driver into memory!");
    return true;
}
NTSTATUS hook::hook_handler(PVOID called_param) {

    _INSTRUCTIONS* instructions = (_INSTRUCTIONS*)called_param;

    LOG("RECIEVED INSTRUCTION\n");

    switch (instructions->instruction)
    {
    case READ: {
        LOG("READ");
        if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0) {
            mem::ReadKernelMemory(instructions->pid, instructions->address, instructions->output, instructions->size);
        }
        return STATUS_SUCCESS;
    }
    case WRITE: {
        LOG("WRITE");
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
        LOG("GETBASEADDR");
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
    default: {
        LOG("UNKNOWN");
    }
    }
    return STATUS_SUCCESS;
}