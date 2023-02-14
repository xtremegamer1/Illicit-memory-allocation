#pragma once
#include "include.h"

extern PDRIVER_DISPATCH originalIoControl;

//ioctl structs
typedef struct _IOCTL_PARAMETERS {
	ULONG                   OutputBufferLength;
	ULONG POINTER_ALIGNMENT InputBufferLength;
	ULONG POINTER_ALIGNMENT IoControlCode;
	PVOID                   Type3InputBuffer;
} IOCTL_PARAMETERS;

DRIVER_DISPATCH HandleIO;

#ifdef _FILE_IOCTL_C
NTSTATUS IoctlModifyPageMapEntry(PIO_MODIFY_PAGE_MAP_ENTRY_PARAMETERS param, ULONG input_size);
NTSTATUS IoctlGetPte(_Inout_ PIO_GET_PTE_PARAMETERS param, ULONG input_size, ULONG output_size, _Out_ SIZE_T* numBytesReturned);
NTSTATUS IoctlProtectProcess(PIO_PROTECT_PROCESS_PARAMETERS param, ULONG input_size);
NTSTATUS IoctlFreeMdlChain();
NTSTATUS IoctlCreateThread(PIO_CREATE_THREAD_PARAMETERS param, ULONG input_size);
NTSTATUS IoctlQueryVirtual(PIO_QUERY_BASIC_VIRTUAL_PARAMETERS param, ULONG input_size);
NTSTATUS IoctlFreeVirtual(PIO_FREE_VIRTUAL_PARAMETERS param, ULONG input_size);
NTSTATUS IoctlAllocateVirtual(_Inout_ PIO_ALLOCATE_VIRTUAL_PARAMETERS param, ULONG input_size, ULONG output_size, _Out_ SIZE_T* numBytesReturned);
NTSTATUS IoctlCopyVirtual(PIO_COPY_VIRTUAL_PARAMETERS param, ULONG input_size);
NTSTATUS IoctlProtectVirtual(PIO_PROTECT_VIRTUAL_PARAMETERS param, ULONG input_size);
NTSTATUS IoctlGetModule(PIO_GET_MODULE_PARAMETERS param, ULONG input_size);
#endif