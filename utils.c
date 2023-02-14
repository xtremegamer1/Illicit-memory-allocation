#include "utils.h"

typedef struct _EventWaitParams {
	PKEVENT _event;
	PKSTART_ROUTINE _callback;
	PVOID _parameter;
} EventWaitParams, *pEventWaitParams;

KEVENT killWaitingThread;

static void EventWait(pEventWaitParams parameter)
{

	DISPATCHER_HEADER* waitObjs[2] = {&killWaitingThread.Header, &parameter->_event->Header};
	DbgPrint("Waiting on objects %p and %p\n", waitObjs[0], waitObjs[1]);
	KeWaitForMultipleObjects(2, waitObjs, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
	parameter->_callback(parameter->_parameter);
	ExFreePool(parameter);
}

BOOLEAN SetEventCallback(PKEVENT event, PKSTART_ROUTINE callback , PVOID parameter)
{
	HANDLE ThreadHandle;
	EventWaitParams* event_wait_params = ExAllocatePool2(PagedPool, sizeof(EventWaitParams), '\0sus');
	if (!event_wait_params)
		return FALSE;
	*event_wait_params = (EventWaitParams){._event = event, ._callback = callback, ._parameter = parameter};
	if (!NT_SUCCESS(PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, EventWait, event_wait_params)))
		return FALSE;
	ZwClose(ThreadHandle);
	return TRUE;
}

UINT GetSelfReferencePML4Index()
{
	uintptr_t KeBugCheck2 = (uintptr_t)KeBugCheckEx + 0x107 + *(signed*)((uintptr_t)KeBugCheckEx + 0x103);
	uintptr_t KiMarkBugCheckReigons = KeBugCheck2 + 0xB6C + *(signed*)(KeBugCheck2 + 0xB68);
	uintptr_t pMmPteBase = KiMarkBugCheckReigons + 0xC7 + *(signed*)(KiMarkBugCheckReigons + 0xC3);
	uintptr_t MmPteBase = *(uintptr_t*)pMmPteBase;
	DbgPrint("MmPteBase: %llX\n", MmPteBase);
	UINT returnVal = (MmPteBase >> 39) & 0x1ff;
	return returnVal;
}

PVOID MmGetSystemRoutineAddressW(_NullNull_terminated_ LPWSTR export_name)
{
	UNICODE_STRING routine_name;
	RtlUnicodeStringInit(&routine_name, export_name);
	return MmGetSystemRoutineAddress(&routine_name);
}