#include "include.h"
#include <intrin.h>
#include "utils.h"

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("LoaderDriver executing main\n");

	UNICODE_STRING drv_name;
	RtlUnicodeStringInit(&drv_name, L"\\Driver\\tdx"); 
	PDRIVER_OBJECT tdx_driver;
	NTSTATUS status = 
		ObReferenceObjectByName(&drv_name, OBJ_CASE_INSENSITIVE, NULL, FILE_ALL_ACCESS, *IoDriverObjectType, KernelMode, NULL, &tdx_driver);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Invalid driver name.");
		return status;
	}
	ObDereferenceObject(tdx_driver);

	//register object callbacks for process protection
	KeInitializeEvent(&killWaitingThread, NotificationEvent, FALSE);
	DbgPrint("Register callbacks returned: 0x%X\n", RegisterCallbacks());

	//Get the self reference PML4 index
	g_SelfReferencePML4Index = GetSelfReferencePML4Index();
	DbgPrint("self ref pml4 index = 0x%X\n", g_SelfReferencePML4Index);

	originalIoControl = tdx_driver->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	tdx_driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleIO;

	return 0x1337;
}


