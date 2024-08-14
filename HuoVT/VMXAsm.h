#pragma once
#include <ntifs.h>

EXTERN_C VOID AsmGetGdtTable(PVOID tableBaseAddr);
EXTERN_C USHORT AsmReadES();
EXTERN_C USHORT AsmReadCS();
EXTERN_C USHORT AsmReadSS();
EXTERN_C USHORT AsmReadDS();
EXTERN_C USHORT AsmReadFS();
EXTERN_C USHORT AsmReadGS();
EXTERN_C USHORT AsmReadTR();
EXTERN_C USHORT AsmReadLDTR();
EXTERN_C VOID AsmInvd();

EXTERN_C VOID AsmVmCall(ULONG exitCode, ULONG64 kernelCR3, ULONG64 newAddrPageNumber, ULONG64 oldAddrPageNumber, PULONG64 retValue);
EXTERN_C VOID AsmJmpRet(ULONG64 rip, ULONG64 rsp);

EXTERN_C VOID AsmVmxExitHandler();

EXTERN_C VOID Asminvept(ULONG type, ULONG64 eptp);