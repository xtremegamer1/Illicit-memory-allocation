#include "globals.h"
UINT g_SelfReferencePML4Index;
PMDL MdlChain;
PEPROCESS g_ProtectedProcess = 0;
PVOID g_CallbackRegistrationHandle;