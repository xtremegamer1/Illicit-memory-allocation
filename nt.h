#pragma once
#include <ntddk.h>

//Undocumented, exported by kernel image
NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	PUNICODE_STRING ObjectName,

	ULONG Attributes,

	PACCESS_STATE AccessState,

	ACCESS_MASK DesiredAccess,

	POBJECT_TYPE ObjectType,

	KPROCESSOR_MODE AccessMode,

	PVOID ParseContext OPTIONAL,

	PVOID* Object);
NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN DWORD(__stdcall* StartAddress)(PVOID),
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL
);

NTSYSAPI
NTSTATUS
ZwProtectVirtualMemory(
	IN  HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG RegionSize,
	IN  ULONG NewProtect,
	OUT PULONG OldProtect
);

typedef struct _MEMORY_BASIC_INFORMATION32 {
	DWORD BaseAddress;
	DWORD AllocationBase;
	DWORD AllocationProtect;
	DWORD RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
} MEMORY_BASIC_INFORMATION32, * PMEMORY_BASIC_INFORMATION32;

//im pretty sure this is linked to ntoskrnl.lib but it's not in any header
extern POBJECT_TYPE* IoDriverObjectType;
extern POBJECT_TYPE* IoDeviceObjectType;

#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage; // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags; // LDR_*
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN SpareBool;
	DWORD   Mutant;
	DWORD   ImageBaseAddress;
	DWORD   LdrData;
	DWORD   ProcessParameters;
	DWORD   SubSystemData;
	DWORD   ProcessHeap;
	DWORD   FastPebLock;
	DWORD   FastPebLockRoutine;
	DWORD   FastPebUnlockRoutine;
	ULONG   EnvironmentUpdateCount;
	DWORD   KernelCallbackTable;
	ULONG   Reserved[2];
} PEB32, * PPEB32;

typedef struct _PEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PVOID						  ProcessParameters;
	PVOID                         Reserved4[3];
	PVOID                         AtlThunkSListPtr;
	PVOID                         Reserved5;
	ULONG                         Reserved6;
	PVOID                         Reserved7;
	ULONG                         Reserved8;
	ULONG                         AtlThunkSListPtr32;
	PVOID                         Reserved9[45];
	BYTE                          Reserved10[96];
	PVOID						  PostProcessInitRoutine;
	BYTE                          Reserved11[128];
	PVOID                         Reserved12[1];
	ULONG                         SessionId;
} PEB, * PPEB;

NTKERNELAPI
PPEB
PsGetProcessPeb(
	IN PEPROCESS Process
);

NTKERNELAPI 
PPEB32 
PsGetProcessWow64Process(__in PEPROCESS Process);