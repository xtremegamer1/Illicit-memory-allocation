#define _FILE_IOCTL_C
#include "ioctl.h"
#include "utils.h"

PDRIVER_DISPATCH originalIoControl;

NTSTATUS HandleIO(DEVICE_OBJECT* DeviceObject, IRP* Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	DbgPrint("We are in process %X\n", (ULONG)PsGetCurrentProcessId());

	Irp->IoStatus.Information = 0;
	IOCTL_PARAMETERS* CtlParameters = (IOCTL_PARAMETERS*)&(IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl);

	if (DEVICE_TYPE_FROM_CTL_CODE(CtlParameters->IoControlCode) != FILE_DEVICE_UNAUTHORIZED_COMMUNICATION)
	{
		return originalIoControl(DeviceObject, Irp);
	}
	Irp->IoStatus.Information = 0;
	switch (CtlParameters->IoControlCode)
	{
		case IO_MODIFY_PAGE_MAP_ENTRY:
			Irp->IoStatus.Status = IoctlModifyPageMapEntry(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength);
			break;
		case IO_PROTECT_PROCESS:
			Irp->IoStatus.Status = IoctlProtectProcess(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength);
			break;
		case IO_GET_PTE:
			Irp->IoStatus.Status = IoctlGetPte(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength, CtlParameters->OutputBufferLength, &Irp->IoStatus.Information);
			break;
		case IO_FREE_MDL_CHAIN:
			Irp->IoStatus.Status = IoctlFreeMdlChain();
			break;
		case IO_CREATE_THREAD:
			Irp->IoStatus.Status = IoctlCreateThread(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength);
			break;
		case IO_QUERY_BASIC_VIRTUAL:
			Irp->IoStatus.Status = IoctlQueryVirtual(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength);
			break;
		case IO_ALLOCATE_VIRTUAL:
			Irp->IoStatus.Status = IoctlAllocateVirtual(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength, CtlParameters->OutputBufferLength, &Irp->IoStatus.Information);
			break;
		case IO_FREE_VIRTUAL:
			Irp->IoStatus.Status = IoctlFreeVirtual(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength);
			break;
		case IO_PROTECT_VIRTUAL:
			Irp->IoStatus.Status = IoctlProtectVirtual(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength);
			break;
		case IO_COPY_VIRTUAL:
			Irp->IoStatus.Status = IoctlCopyVirtual(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength);
			break;
		case IO_GET_MODULE:
			Irp->IoStatus.Status = IoctlGetModule(Irp->AssociatedIrp.SystemBuffer, CtlParameters->InputBufferLength);
			break;
		default:
			Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
			break;
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

//Returns the address of the location which should store the address of the next MDL in the chain. if you dont understand what this means, sorry but you have a brain tumor and only 3 months to live :( 
HELPER PMDL* GetLastMdlNextInChain(PMDL *base)
{
	if (!*base)
		return base;
	PMDL iterator = *base;
	while (iterator->Next)
	{
		iterator = iterator->Next;
	}
	return &iterator->Next;
}

HELPER __inline PHYSICAL_ADDRESS CastQwordToPhysicalAddress(UINT64 to_cast)
{
	PHYSICAL_ADDRESS returnVal = { .QuadPart = to_cast };
	return returnVal;
}

//As of yet this function is oblivious to the existence of large and huge pages
NTSTATUS IoctlModifyPageMapEntry(PIO_MODIFY_PAGE_MAP_ENTRY_PARAMETERS param, ULONG input_size)
{
	if (input_size != sizeof(*param))
		return STATUS_INVALID_PARAMETER;
	PEPROCESS targetProcess = 0;
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)param->ProcessID, &targetProcess)))
		return STATUS_INVALID_CID;
	KAPC_STATE state = { 0 };
	KeStackAttachProcess(targetProcess, &state);
	DbgPrint("preparing to write pte corresponding to vpn %p in process %X\n", param->VirtualPageNumber, param->ProcessID);

	//Ok now we must go through every level of the PML4, adding entries if it proves necessary, until we can edit the lowest level page table
	//Scoped to reduce stack waste and scope name pollution and cause it looks pwetty 
	// Create a new PDPT if necessary
	{
		LinearAddress PML4E_pointer = {
			.sign_extend = 0xFFFF, //Self reference PML4 is always > 0xFF
			.PML4_offset = g_SelfReferencePML4Index,
			.PDPT_offset = g_SelfReferencePML4Index,
			.PD_offset = g_SelfReferencePML4Index,
			.PT_offset = g_SelfReferencePML4Index,
			.page_offset = (((uintptr_t)param->VirtualPageNumber >> 27) & 0x1FF) * sizeof(WINPTE)
		};
		DbgPrint("\tReading PML4E at %p\n", PML4E_pointer.Address);
#pragma warning(suppress : 6011)
		WINPTE PML4E = *(WINPTE*)PML4E_pointer.Address;
		DbgPrint("\t\tPML4E is %p\n", *(PVOID*)&PML4E);
		if (!PML4E.Valid)
		{
			DbgPrint("\t\t\tAllocating new page for PDPT at %p\n", PML4E_pointer.Address);
			//We must ensure a future for... wait I mean we must get a new unpageable page frame to use as a PDPT should the current PML4E prove invalid
			//MDLs and their associated buffers will be freed on process destruction. As of now there is no support for simultaneous process connection
			//nor is there support for a process closing a handle and another one opening one without the first process terminating. Doing so may cause a bugcheck.
			PMDL New_PDPT_Mdl = MmAllocatePagesForMdl(CastQwordToPhysicalAddress(0), CastQwordToPhysicalAddress(0xFFFF'FFFF'FFFF'FFFF), CastQwordToPhysicalAddress(0), PAGE_SIZE);
			*GetLastMdlNextInChain(&MdlChain) = New_PDPT_Mdl;
			PFN_NUMBER New_PML4E_Pfn = *MmGetMdlPfnArray(New_PDPT_Mdl); //Only 1 PFN so we goood G
			//Ok now we build a new PTE to insert. I will reuse the variable that read the PML4E
			PML4E = (WINPTE){ 0 };
			PML4E = (WINPTE){ .WriteProtect = 1, .hardwareWrite = 1, .Dirty = 1, .Accessed = 1, 
				.Valid = 1, .Owner = 1, .PFN = New_PML4E_Pfn }; //1 for owner is usermode
			*(WINPTE*)PML4E_pointer.Address = PML4E;
		}
	}

	// Create a new PD if necessary
	{
		//PDPTE = page directory pointer table entry
		LinearAddress PDPTE_pointer =
		{
			.sign_extend = 0XFFFF,
			.PML4_offset = g_SelfReferencePML4Index,
			.PDPT_offset = g_SelfReferencePML4Index,
			.PD_offset = g_SelfReferencePML4Index,
			.PT_offset = (((uintptr_t)param->VirtualPageNumber >> 27) & 0x1FF),
			.page_offset = (((uintptr_t)param->VirtualPageNumber >> 18) & 0x1FF) * sizeof(WINPTE)
		};
		DbgPrint("\tReading PDPTE at %p\n", PDPTE_pointer.Address);
#pragma warning(suppress : 6011)
		WINPTE PDPTE = *(WINPTE*)PDPTE_pointer.Address;
		DbgPrint("\t\tPDPTE is %p\n", *(PVOID*)&PDPTE);
		if (!PDPTE.Valid)
		{
			DbgPrint("\t\t\tAllocating new page for PD at %p\n", PDPTE_pointer.Address);
			PMDL New_PD_Mdl = MmAllocatePagesForMdl(CastQwordToPhysicalAddress(0), CastQwordToPhysicalAddress(0xFFFF'FFFF'FFFF'FFFF), CastQwordToPhysicalAddress(0), PAGE_SIZE);
			*GetLastMdlNextInChain(&MdlChain) = New_PD_Mdl;
			PFN_NUMBER New_PDPTE_Pfn = *MmGetMdlPfnArray(New_PD_Mdl);
			PDPTE = (WINPTE){ 0 };
			PDPTE = (WINPTE){ .WriteProtect = 1, .hardwareWrite = 1, .Dirty = 1, .Accessed = 1,
				.WriteProtect = 1, .Valid = 1, .Owner = 1, .PFN = New_PDPTE_Pfn };
			*(WINPTE*)PDPTE_pointer.Address = PDPTE;
		}
	}

	// Create a new PT if necessary
	{
		//PDE = page directory entry (obviously)
		LinearAddress PDE_pointer =
		{
			.sign_extend = 0XFFFF,
			.PML4_offset = g_SelfReferencePML4Index,
			.PDPT_offset = g_SelfReferencePML4Index,
			.PD_offset = (((uintptr_t)param->VirtualPageNumber >> 27) & 0x1FF),
			.PT_offset = (((uintptr_t)param->VirtualPageNumber >> 18) & 0x1FF),
			.page_offset = (((uintptr_t)param->VirtualPageNumber >> 9) & 0x1FF) * sizeof(WINPTE)
		};
		DbgPrint("\tReading PDE at %p\n", PDE_pointer.Address);
#pragma warning(suppress : 6011)
		WINPTE PDE = *(WINPTE*)PDE_pointer.Address;
		DbgPrint("\t\tPDEis %p\n", *(PVOID*)&PDE);
		if (!PDE.Valid)
		{
			DbgPrint("\t\t\tAllocating new page for PT at %p\n", PDE_pointer.Address);
			PMDL New_PT_Mdl = MmAllocatePagesForMdl(CastQwordToPhysicalAddress(0), CastQwordToPhysicalAddress(0xFFFF'FFFF'FFFF'FFFF), CastQwordToPhysicalAddress(0), PAGE_SIZE);
			*GetLastMdlNextInChain(&MdlChain) = New_PT_Mdl;
			PFN_NUMBER New_PDE_Pfn = *MmGetMdlPfnArray(New_PT_Mdl);
			PDE = (WINPTE){ 0 };
			PDE = (WINPTE){ .WriteProtect = 1, .hardwareWrite = 1, .Dirty = 1, .Accessed = 1,
				.Valid = 1, .Owner = 1, .PFN = New_PDE_Pfn };
			*(WINPTE*)PDE_pointer.Address = PDE;
		}
	}

	// Finally, alter the actual page table entry now that we are sure it exists
	{
		//I hope you know what PTE means
		LinearAddress PTE_pointer =
		{
			.sign_extend = 0XFFFF,
			.PML4_offset = g_SelfReferencePML4Index,
			.PDPT_offset = (((uintptr_t)param->VirtualPageNumber >> 27) & 0x1FF),
			.PD_offset = (((uintptr_t)param->VirtualPageNumber >> 18) & 0x1FF),
			.PT_offset = (((uintptr_t)param->VirtualPageNumber >> 9) & 0x1FF),
			.page_offset = (((uintptr_t)param->VirtualPageNumber) & 0x1FF) * sizeof(WINPTE)
		};
		//No validation necessary just write the source PTE into the target
		DbgPrint("Writing pte %p at address %p in process %X\n", *(PVOID*)&param->NewEntry, PTE_pointer.Address, param->ProcessID);
#pragma warning(suppress : 6011)
		*(WINPTE*)PTE_pointer.Address = param->NewEntry;
	}
	KeUnstackDetachProcess(&state);
	return STATUS_SUCCESS;
}

NTSTATUS IoctlGetPte(_Inout_ PIO_GET_PTE_PARAMETERS param, ULONG input_size, ULONG output_size, _Out_ SIZE_T* numBytesReturned)
{
	if (input_size != sizeof(param->in) || output_size != sizeof(param->out) || !numBytesReturned)
		return STATUS_INVALID_PARAMETER;
	*numBytesReturned = sizeof(param->out);
	PEPROCESS process = 0;
	if (PsLookupProcessByProcessId((HANDLE)param->in.ProcessID, &process))
	{
		param->out.PTE = (WINPTE){ 0 };
		return STATUS_INVALID_CID;
	}
	KAPC_STATE state = { 0 };
	KeStackAttachProcess(process, &state);
	LinearAddress PTE_pointer =
	{
		.sign_extend = 0xFFFF,
		.PML4_offset = g_SelfReferencePML4Index,
		.PDPT_offset = (((uintptr_t)param->in.VirtualPageNumber >> 27) & 0x1FF),
		.PD_offset = (((uintptr_t)param->in.VirtualPageNumber >> 18) & 0x1FF),
		.PT_offset = (((uintptr_t)param->in.VirtualPageNumber >> 9) & 0x1FF),
		.page_offset = (((uintptr_t)param->in.VirtualPageNumber) & 0x1FF) * sizeof(WINPTE)
	};
	DbgPrint("fetching pte at address 0x%p\n", PTE_pointer.Address);
#pragma warning(suppress : 6011)
	WINPTE returnPte = *(WINPTE*)PTE_pointer.Address;
	KeUnstackDetachProcess(&state);
	param->out.PTE = returnPte;
	return STATUS_SUCCESS;
}

HELPER void FreeProtectionCallback(_In_ PVOID StartContext) //Probably not thread safe.
{
	UNREFERENCED_PARAMETER(StartContext);
	DbgPrint("Stopping process protection\n");
	g_ProtectedProcess = NULL;
}

NTSTATUS IoctlProtectProcess(PIO_PROTECT_PROCESS_PARAMETERS param, ULONG input_size)
{
	DbgPrint("Attempting to protect or free process. input size: 0x%X\n", input_size);
	if (input_size != sizeof(*param))
		return STATUS_INVALID_PARAMETER;
	if (param->free)
	{
		if (!g_ProtectedProcess)
			return STATUS_REQUEST_OUT_OF_SEQUENCE;
		DbgPrint("Freeing process from protection\n");
		ObDereferenceObject(g_ProtectedProcess);
		KeSetEvent(&killWaitingThread, 0, FALSE);
		return STATUS_SUCCESS;
	}
	else
	{
		if (g_ProtectedProcess)
			return STATUS_REQUEST_OUT_OF_SEQUENCE;
		DbgPrint("Protecting process: 0x%X\n", param->ProcessID);
		PEPROCESS toProtect = 0;
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)param->ProcessID, &toProtect)))
			return STATUS_INVALID_CID;
		ObReferenceObject(toProtect);
		DbgPrint("Protected process at 0x%p\n", toProtect);
		KeClearEvent(&killWaitingThread);
		SetEventCallback((PKEVENT)toProtect, FreeProtectionCallback, NULL);
		g_ProtectedProcess = toProtect;
		return STATUS_SUCCESS;
	}
}

NTSTATUS IoctlFreeMdlChain()
{
	PMDL iterator = MdlChain;
	DbgPrint("Freeing Mdl Chain.\n");
	while (iterator)
	{
		DbgPrint("Freeing mdl %p\n", iterator);
		MmFreePagesFromMdl(iterator);
		PMDL last = iterator;
		iterator = iterator->Next;
		ExFreePool(last);
	}
	MdlChain = NULL;
	return STATUS_SUCCESS;
}

NTSTATUS IoctlCreateThread(PIO_CREATE_THREAD_PARAMETERS param, ULONG input_size)
{
	if (input_size != sizeof(*param))
		return STATUS_INVALID_PARAMETER;
	DbgPrint("Attempting to create thread in process 0x%X at address %p with parameter %p\n", param->processID, param->EntryPoint, param->Parameter);
	PEPROCESS targetProc = 0;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)param->processID, &targetProc);
	if (!NT_SUCCESS(status))
		return status;
	HANDLE procHandle = 0;
	status = ObOpenObjectByPointer(targetProc, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &procHandle);
	if (!NT_SUCCESS(status))
		return status;
	status = RtlCreateUserThread(procHandle, NULL, FALSE, 0, 0, 0, param->EntryPoint, param->Parameter, NULL, NULL);
	ZwClose(procHandle);
	return status;
}

NTSTATUS IoctlQueryVirtual(PIO_QUERY_BASIC_VIRTUAL_PARAMETERS param, ULONG input_size)
{
	if (input_size != sizeof(*param))
		return STATUS_INVALID_PARAMETER;
	PEPROCESS targetProc = 0;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)param->ProcessID, &targetProc);
	if (!NT_SUCCESS(status))
		return status;
	HANDLE procHandle = 0;
	status = ObOpenObjectByPointer(targetProc, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &procHandle);
	if (!NT_SUCCESS(status))
		return status;
	status = ZwQueryVirtualMemory(procHandle, param->Address, MemoryBasicInformation, param->outbuffer, sizeof(MEMORY_BASIC_INFORMATION), NULL);
	ZwClose(procHandle);
	return status;
}

NTSTATUS IoctlAllocateVirtual(_Inout_ PIO_ALLOCATE_VIRTUAL_PARAMETERS param, ULONG input_size, ULONG output_size, _Out_ SIZE_T* numBytesReturned)
{
	*numBytesReturned = sizeof(param->out); //I've set it up such that the out buffer is always initialized.
	if (input_size != sizeof(param->in) || output_size != sizeof(param->out))
	{
		param->out.AllocatedBase = 0;
		return STATUS_INVALID_PARAMETER;
	}
	PEPROCESS targetProc = 0;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)param->in.ProcessID, &targetProc);
	if (!NT_SUCCESS(status))
		goto failure;
	HANDLE procHandle = 0;
	status = ObOpenObjectByPointer(targetProc, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &procHandle);
	if (!NT_SUCCESS(status))
		goto failure;
	ULONG_PTR ZeroBits = NULL;
	PVOID BaseAddress = param->in.AllocationBase;
	status = ZwAllocateVirtualMemory(procHandle, &BaseAddress, ZeroBits, &param->in.SizeOfAllocation, param->in.AllocationType, param->in.Protect);
	DbgPrint("ZwAllocateVirtualMemory returned %X\n", status);
	if (!NT_SUCCESS(status))
		BaseAddress = 0;
	param->out.AllocatedBase = BaseAddress;
	ZwClose(procHandle);
	return status;
failure:
	param->out.AllocatedBase = 0;
	return status;
}

NTSTATUS IoctlFreeVirtual(PIO_FREE_VIRTUAL_PARAMETERS param, ULONG input_size)
{
	if (input_size != sizeof(*param))
		return STATUS_INVALID_PARAMETER;
	PEPROCESS targetProc = 0;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)param->ProcessID, &targetProc);
	if (!NT_SUCCESS(status))
		return status;
	HANDLE procHandle = 0;
	status = ObOpenObjectByPointer(targetProc, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &procHandle);
	if (!NT_SUCCESS(status))
		return status;
	PVOID BaseAddress = param->FreeBase;
	status = ZwFreeVirtualMemory(procHandle, &BaseAddress, &param->FreeSize, param->FreeType);
	ZwClose(procHandle);
	return status;
}

NTSTATUS IoctlProtectVirtual(PIO_PROTECT_VIRTUAL_PARAMETERS param, ULONG input_size)
{
	if (input_size != sizeof(*param))
		return STATUS_INVALID_PARAMETER;
	PEPROCESS targetProc = 0;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)param->ProcessID, &targetProc);
	if (!NT_SUCCESS(status))
		return status;
	HANDLE procHandle = 0;
	status = ObOpenObjectByPointer(targetProc, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, &procHandle);
	if (!NT_SUCCESS(status))
		return status;
	PVOID BaseAddress = param->base;
	DWORD oldProtect = 0;
	ULONG size = param->size;
	status = ZwProtectVirtualMemory(procHandle, &BaseAddress, &size, param->NewProtect, &oldProtect);
	ZwClose(procHandle);
	return status;
}

__forceinline HELPER DisableWriteProtect()
{
	__writecr4(__readcr4() & 0xfffffffff7ffffff);
	__writecr0(__readcr0() & 0xfffffffffffeffff);
}
//Both calls must be within the same call frame or CET will freak out
__forceinline HELPER EnableWriteProtect()
{
	__writecr0(__readcr0() | 0x10000);
	__writecr4(__readcr4() | 8000000);
}

NTSTATUS IoctlCopyVirtual(PIO_COPY_VIRTUAL_PARAMETERS param, ULONG input_size)
{
	if (input_size != sizeof(*param))
		return STATUS_INVALID_PARAMETER;
	SIZE_T length = min(param->srcProcessBufferLength, param->trgtProcessBufferLength);
	BYTE* buffer = ExAllocatePool(PagedPool, length);
	if (!buffer)
		return STATUS_NO_MEMORY;
	KAPC_STATE state = { 0 };
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(param->srcProcessID, &process);
	if (!NT_SUCCESS(status))
		return status;

	KeStackAttachProcess(process, &state);
	DisableWriteProtect();
	RtlCopyMemory(buffer, param->srcProcessBuffer, length);
	EnableWriteProtect();
	KeUnstackDetachProcess(&state);

	status = PsLookupProcessByProcessId(param->trgtProcessID, &process);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(buffer);
		return status;
	}

	KeStackAttachProcess(process, &state);
	DisableWriteProtect();
	RtlCopyMemory(param->trgtProcessBuffer, buffer, length);
	EnableWriteProtect();
	KeUnstackDetachProcess(&state);

	ExFreePool(buffer);
	return STATUS_SUCCESS;
}

HELPER NTSTATUS GetModule64(_Out_ PVOID * pMod, _In_ PEPROCESS process, _In_ LPCWSTR modName)
{
	*pMod = NULL;
	PPEB peb = PsGetProcessPeb(process);
	if (!peb)
		return STATUS_NOT_FOUND;
	ULONG length = (ULONG)wcsnlen(modName, 0x800);
	KAPC_STATE state;
	KeStackAttachProcess(process, &state);
	PPEB_LDR_DATA ldrdata = peb->Ldr;
	for (LIST_ENTRY* entry = ldrdata->ModuleListLoadOrder.Flink; entry != &ldrdata->ModuleListLoadOrder; entry = entry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList); //unneccesary but more elegant
		if (!_wcsnicmp(ldrEntry->BaseDllName.Buffer, modName, min(length, ldrEntry->BaseDllName.Length)))
		{
			*pMod = ldrEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return STATUS_SUCCESS;
		}
	}
	KeUnstackDetachProcess(&state);
	return STATUS_NOT_FOUND;
}

HELPER NTSTATUS GetModule32(_Out_ PVOID* pMod, _In_ PEPROCESS process, _In_ LPCWSTR modName)
{
	*pMod = NULL;
	PPEB32 peb = PsGetProcessWow64Process(process);
	if (!peb)
		return STATUS_NOT_FOUND;
	ULONG length = wcsnlen(modName, 0x800);
	KAPC_STATE state;
	KeStackAttachProcess(process, &state);
	PPEB_LDR_DATA32 ldrdata = peb->LdrData;
	for (LIST_ENTRY32* entry = ldrdata->InLoadOrderModuleList.Flink; entry != &ldrdata->InLoadOrderModuleList; entry = entry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY32 ldrEntry= CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
		if (!_wcsnicmp(ldrEntry->BaseDllName.Buffer, modName, min(length, ldrEntry->BaseDllName.Length)))
		{
			*pMod = ldrEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return STATUS_SUCCESS;
		}
	}
	KeUnstackDetachProcess(&state);
	return STATUS_NOT_FOUND;
}

NTSTATUS IoctlGetModule(PIO_GET_MODULE_PARAMETERS param, ULONG input_size)
{
	if (input_size != sizeof(*param))
		return STATUS_INVALID_PARAMETER;
	ULONG length = (ULONG)strnlen(param->in.modName, 0x800);
	if (length == 0x800) // Will be 0x7FF if there is a null terminator at index 0x800
	{
		return STATUS_BUFFER_TOO_SMALL;
	}
	LPWSTR nameBuf = ExAllocatePool(PagedPool, length * 2);
	if (!nameBuf)
		return STATUS_NO_MEMORY;
	for (ULONG i = 0; i < length; ++i)
	{
		nameBuf[i] = param->in.modName[i];
	}
	if (!wcswcs(nameBuf, L"."))
	{
		if (length > 0x7fb) //Need 5 chars for the .dll and null terminator
			return STATUS_BUFFER_TOO_SMALL;
		memcpy(nameBuf + length - 4, L".dll", 10);
	}
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(param->in.pid, &process);
	if (!NT_SUCCESS(status))
		return status;
	PVOID modAddr = NULL;
	if (param->in.getWow64Modules)
		status = GetModule32(&modAddr, process, nameBuf);
	else
		status = GetModule64(&modAddr, process, nameBuf);
	param->out.modBase = modAddr;
	ExFreePool(nameBuf);
	return status;
}