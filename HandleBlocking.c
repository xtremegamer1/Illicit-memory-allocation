#include "HandleBlocking.h"

/*Unfortunately this section is defunct until I can figure out how i can make it work in a manually mapped driver :(*/

LPSTR NTAPI PsGetProcessImageFileName(PEPROCESS Process);

OB_PREOP_CALLBACK_STATUS Process_Handle_Blocking_Preop(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (OperationInformation->ObjectType != *PsProcessType || OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE)
	{
		KeBugCheck(0xDEADBEEF);
	}
	if (OperationInformation->Object != g_ProtectedProcess)
	{
		return OB_PREOP_SUCCESS;
	}
	
	PSTR RequestorName = PsGetProcessImageFileName(IoGetCurrentProcess());
	DbgPrint("Process %s wants a handle\n", RequestorName);
	if (!strcmp(RequestorName, "lsass.exe") || !strcmp(RequestorName, "csrss.exe") || IoGetCurrentProcess() == g_ProtectedProcess || OperationInformation->KernelHandle)
	{
		return OB_PREOP_SUCCESS;
	}
	DbgPrint("Blocked handle. Nice try kid.\n");
	OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;
	return OB_PREOP_SUCCESS;
}

NTSTATUS RegisterCallbacks()
{
	OB_OPERATION_REGISTRATION opReg = { .ObjectType = PsProcessType,
									.Operations = OB_OPERATION_HANDLE_CREATE,
									.PreOperation = Process_Handle_Blocking_Preop,
									.PostOperation = 0 };

	OB_CALLBACK_REGISTRATION callbackReg = { .Version = OB_FLT_REGISTRATION_VERSION,
											.Altitude = {.MaximumLength = 14, .Length = 12, .Buffer = L"133769"},
											.OperationRegistrationCount = 1,
											.RegistrationContext = 0,
											.OperationRegistration = &opReg };

	return ObRegisterCallbacks(&callbackReg, &g_CallbackRegistrationHandle);
}