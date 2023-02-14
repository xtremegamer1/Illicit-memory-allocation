#pragma once
#include "globals.h"
#include "macro.h"

OB_PREOP_CALLBACK_STATUS Process_Handle_Blocking_Preop(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation);
NTSTATUS RegisterCallbacks();