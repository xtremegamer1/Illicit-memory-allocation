#pragma once 
#include <windef.h>
#ifndef _KERNEL_MODE
#include <winioctl.h>
#endif
#ifndef _AMD64_
#error "THIS HEADER IS FOR 64 BIT ONLY!!!!!!!!!!!!!!!!!!!!!"
#endif

/*
* THIS HEADER SHOULD BE USED IN ANY PROJECT MEANT TO ACCESS THE DRIVER FROM USERMODE
*/
#pragma warning(disable : 4201)

#define FILE_DEVICE_UNAUTHORIZED_COMMUNICATION 0x9D5A

//Usermode compiler cries about trying to use a signed as an unsigned
#define UCTL_CODE(DeviceType, Access, Function, Method) (DWORD)CTL_CODE(DeviceType, Access, Function, Method)

//IOCTL codes
#define IO_MODIFY_PAGE_MAP_ENTRY	UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#define IO_GET_PTE					UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_PROTECT_PROCESS			UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_FREE_MDL_CHAIN			UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_CREATE_THREAD			UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_QUERY_BASIC_VIRTUAL		UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_ALLOCATE_VIRTUAL			UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_FREE_VIRTUAL				UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_PROTECT_VIRTUAL			UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_COPY_VIRTUAL				UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_GET_MODULE				UCTL_CODE(FILE_DEVICE_UNAUTHORIZED_COMMUNICATION, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

//Used to build addresses from page map offsets
typedef union _LinearAddress
{
	struct {
		uintptr_t page_offset : 12;
		uintptr_t PT_offset : 9;
		uintptr_t PD_offset : 9;
		uintptr_t PDPT_offset : 9;
		uintptr_t PML4_offset : 9;
		uintptr_t sign_extend : 16;
#pragma warning(suppress : 4201)
	};
	PVOID Address;
} LinearAddress;

typedef struct _WINPTE
{
	uintptr_t Valid : 1;
	uintptr_t hardwareWrite : 1;
	uintptr_t Owner : 1;
	uintptr_t WriteThrough : 1;
	uintptr_t CacheDisabled : 1;
	uintptr_t Accessed : 1;
	uintptr_t Dirty : 1;
	uintptr_t LargePage : 1;
	uintptr_t Global : 1;
	uintptr_t CopyOnWrite : 1;
	uintptr_t Prototype : 1;
	uintptr_t WriteProtect : 1;
	uintptr_t PFN : 36;
	uintptr_t Reserved : 15;
	uintptr_t NX : 1;
} WINPTE;

typedef struct _IO_MODIFY_PAGE_MAP_ENTRY_PARAMETERS {
	ULONG ProcessID;
	PVOID VirtualPageNumber;
	WINPTE NewEntry;
	BOOLEAN is32BitProcess;
} IO_MODIFY_PAGE_MAP_ENTRY_PARAMETERS, * PIO_MODIFY_PAGE_MAP_ENTRY_PARAMETERS;

//IMPORTANT: User mode code must validate the address. If the VPN supplied corresponds to a nonexistent PTE, a bugcheck will occur. Ensure that the memory is resident using VirtualLock before calling this routine.
typedef union _IO_GET_PTE_PARAMETERS { 
	struct {
		ULONG ProcessID;
		PVOID VirtualPageNumber;
	} in;
	struct {
		WINPTE PTE;
	} out;
} IO_GET_PTE_PARAMETERS, * PIO_GET_PTE_PARAMETERS;


//Only one process may be protected at a time. Issue a free request before a protected process terminates to avoid unneccesarily prolonging the life of the process object.
typedef struct _IO_PROTECT_PROCESS_PARAMETERS {
	ULONG ProcessID;
	BOOLEAN free;
} IO_PROTECT_PROCESS_PARAMETERS, * PIO_PROTECT_PROCESS_PARAMETERS;

typedef struct _IO_CREATE_THREAD_PARAMETERS
{
	ULONG processID;
#ifdef _NTDDK_
	DWORD(__stdcall* EntryPoint)(PVOID);
#else
	LPTHREAD_START_ROUTINE EntryPoint;
#endif
	PVOID Parameter;
} IO_CREATE_THREAD_PARAMETERS, * PIO_CREATE_THREAD_PARAMETERS;

typedef struct _IO_QUERY_BASIC_VIRTUAL_PARAMETERS
{
	ULONG ProcessID;
	PVOID Address;
	PMEMORY_BASIC_INFORMATION outbuffer; //This can be a pointer to a 64 bit or 32 bit version of the structure but it must be congruent to is32bitprocess
	BOOLEAN is32bitprocess;
} IO_QUERY_BASIC_VIRTUAL_PARAMETERS, * PIO_QUERY_BASIC_VIRTUAL_PARAMETERS;

typedef union _IO_ALLOCATE_VIRTUAL_PARAMETERS
{
	struct {
		ULONG ProcessID;
		PVOID AllocationBase;
		SIZE_T SizeOfAllocation;
		BOOLEAN is32bitAllocation;
		ULONG AllocationType;
		ULONG Protect;
	} in;
	struct {
		PVOID AllocatedBase;
	} out;
} IO_ALLOCATE_VIRTUAL_PARAMETERS, * PIO_ALLOCATE_VIRTUAL_PARAMETERS;

typedef struct _IO_FREE_VIRTUAL_PARAMETERS
{
	ULONG ProcessID;
	PVOID FreeBase;
	SIZE_T FreeSize;
	ULONG FreeType;
} IO_FREE_VIRTUAL_PARAMETERS, * PIO_FREE_VIRTUAL_PARAMETERS;

typedef struct _IO_PROTECT_VIRTUAL_PARAMETERS
{
	ULONG ProcessID;
	PVOID base;
	ULONG size;
	DWORD NewProtect;
} IO_PROTECT_VIRTUAL_PARAMETERS, * PIO_PROTECT_VIRTUAL_PARAMETERS;

typedef struct _IO_COPY_VIRTUAL_PARAMETERS
{
	ULONG srcProcessID;
	ULONG trgtProcessID;
	PVOID srcProcessBuffer;
	SIZE_T srcProcessBufferLength;
	PVOID trgtProcessBuffer;
	SIZE_T trgtProcessBufferLength;
} IO_COPY_VIRTUAL_PARAMETERS, * PIO_COPY_VIRTUAL_PARAMETERS;

typedef union _IO_GET_MODULE_PARAMETERS
{
	struct
	{
		ULONG pid;
		LPCSTR modName;
		BOOLEAN getWow64Modules;
	} in;
	struct
	{
		PVOID modBase;
	} out;
} IO_GET_MODULE_PARAMETERS, * PIO_GET_MODULE_PARAMETERS;