#pragma once
#include <ntddk.h>
#include <ntstrsafe.h>
#include <windef.h>

extern KEVENT killWaitingThread;

BOOLEAN SetEventCallback(PKEVENT event, PKSTART_ROUTINE callback, PVOID parameter);
PVOID MmGetSystemRoutineAddressW(_NullNull_terminated_ LPWSTR export_name);
UINT GetSelfReferencePML4Index();