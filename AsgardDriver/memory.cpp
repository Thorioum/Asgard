#include "memory.h"


PVOID mem::GetModuleBase(const char* module_name) {
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &bytes);

	if (!bytes) {
		DbgPrint("bytes failed\n");
		return NULL;
	}
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x4e554c4c);

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		DbgPrint("status failed\n");
		return NULL;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	PVOID module_base = 0, module_size = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++) {

		if (strcmp((char*)module[i].FullPathName, module_name) == 0) {
			module_base = module[i].ImageBase;
			module_size = (PVOID)module[i].ImageBase;
			break;
		}
	}
	if (modules)
		ExFreePoolWithTag(modules, NULL);

	if (module_base <= NULL) {
		DbgPrint("module_base less than 0\n");
		return NULL;
	}

	return module_base;
}
PVOID mem::GetModuleExport(const char* module_name, LPCSTR routine_name) {

	PVOID lpModule = GetModuleBase(module_name);

	if (!lpModule) {
		DbgPrint("get_system_module_base failed\n");
		return NULL;
	}

	return RtlFindExportedRoutineByName(lpModule, routine_name);
}

bool mem::WriteMemory(void* address, void* buffer, size_t size) {
	if (!RtlCopyMemory(address, buffer, size)) {
		DbgPrint("RtlCopyMemory failed\n");
		return false;
	}
	return true;
	
}
bool mem::WriteReadOnlyMemory(void* address, void* buffer, size_t size) {

	PMDL Mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);

	if (!Mdl) {
		DbgPrint("IoAllocateMdl failed\n");
		return false;
	}

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);

	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	WriteMemory(Mapping, buffer, size);
	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

ULONG64 mem::GetModuleBase64(PEPROCESS proc, UNICODE_STRING module_name)
{
	if (!proc)
		return NULL;
	KeAttachProcess((PKPROCESS)proc);

	PPEB PEB = PsGetProcessPeb(proc);
	if (!PEB) {
		KeDetachProcess();
		ObfDereferenceObject(proc);
		return STATUS_NOT_FOUND;
	}

	if (!PEB->Ldr || !PEB->Ldr->Initialized) {
		KeDetachProcess();
		ObfDereferenceObject(proc);
		return STATUS_NOT_FOUND;
	}
	ULONG64 Result = 0;
	for (PLIST_ENTRY PList = PEB->Ldr->ModuleListLoadOrder.Flink; PList != &PEB->Ldr->ModuleListLoadOrder; PList = PList->Flink) {
		PLDR_DATA_TABLE_ENTRY PLDREntry = CONTAINING_RECORD(PList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&PLDREntry->BaseDllName, &module_name, TRUE) == 0) {
			Result = (ULONG64)PLDREntry->DllBase;
			KeDetachProcess();
			ObfDereferenceObject(proc);
			return Result;
		}
	}
	return STATUS_NOT_FOUND;

}

NTSTATUS mem::ReadKernelMemory(ULONG pid, UINT_PTR address, void* buffer, UINT_PTR size)
{
	if (!address || !buffer || !size) {
		return STATUS_UNSUCCESSFUL;
	}
	NTSTATUS status = STATUS_SUCCESS;
	__try
	{
		SIZE_T bytes = 0;
		PEPROCESS process;
		status = PsLookupProcessByProcessId((HANDLE)pid, &process);
		if (!NT_SUCCESS(status))
		{
			LOG("PsLookupProcessByProcessId Failed: 0x%llx\n", status);
			return status;
		}
		status = MmCopyVirtualMemory(process, (void*)address, PsGetCurrentProcess(), (void*)buffer, size, UserMode, &bytes);

		if (!NT_SUCCESS(status)) {
			if (status == STATUS_PARTIAL_COPY) {
				LOG("MmCopyVirtualMemory Failed: STATUS_PARTIAL_COPY");
			}
			else {
				LOG("MmCopyVirtualMemory Failed: 0x%llx\n", status);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("ERROR OCCURED: ReadMemory (RtlCopyMemory) Code: 0x%x\n", GetExceptionCode());
		status = STATUS_UNSUCCESSFUL;
	}
	return status;
}

bool mem::WriteKernelMemory(HANDLE pid, uintptr_t address, void* buffer, SIZE_T size)
{
	if (!address || !buffer || !size) {
		LOG("WriteKernelMemory params are null");
		return false;
	}

	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS process;
	PsLookupProcessByProcessId((HANDLE)pid, &process);

	KAPC_STATE state;
	KeStackAttachProcess(process, &state);

	MEMORY_BASIC_INFORMATION info;

	status = ZwQueryVirtualMemory(ZwCurrentProcess(), (PVOID)address, MemoryBasicInformation, &info, sizeof(info), NULL);
	if (!NT_SUCCESS(status)) {
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (((uintptr_t)info.BaseAddress + info.RegionSize) < (address + size)) {
		KeUnstackDetachProcess(&state);
		return false;
	}

	if (!(info.State & MEM_COMMIT) || (info.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
		KeUnstackDetachProcess(&state);
		return false;
	}

	if ((info.Protect & PAGE_EXECUTE_WRITECOPY) || (info.Protect & PAGE_EXECUTE_READWRITE) || (info.Protect & PAGE_READWRITE) || (info.Protect & PAGE_WRITECOPY)) {
		RtlCopyMemory((void*)address, buffer, size);
	} else {
		KeUnstackDetachProcess(&state);

		PMDL mdl = IoAllocateMdl((void*)address, size, FALSE, FALSE, NULL);
		if (!mdl) { return false; }

		MmProbeAndLockProcessPages(mdl,process, KernelMode, IoReadAccess);
		void* map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
		MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

		RtlCopyMemory(map, buffer, size);

		MmUnmapLockedPages(map, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		
		return true;
	}
	KeUnstackDetachProcess(&state);
	return true;
}

