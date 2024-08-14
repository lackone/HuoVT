#include <ntifs.h>
#include "VMXTools.h"
#include "VMX.h"
#include "VMXAsm.h"
#include "Export.h"
#include "VMXEptHook.h"
#include "TestHook.h"

extern ULONG64 NtOpenProcessRet = 0;

EXTERN_C NTSTATUS NTAPI MyNtOpenProcess(
	_Out_ PHANDLE ProcessHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_ PCLIENT_ID ClientId
)
{
	Log("MyNtOpenProcess");
}

VOID VmxStartVT(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	do
	{
		if (!VmxChcekCPUID())
		{
			Log("VmxChcekCPUID number = %d", KeGetCurrentProcessorNumber());
			break;
		}
		if (!VmxChcekBIOS())
		{
			Log("VmxChcekBIOS number = %d", KeGetCurrentProcessorNumber());
			break;
		}
		if (!VmxCheckCR4())
		{
			Log("VmxCheckCR4 number = %d", KeGetCurrentProcessorNumber());
			break;
		}

		VmxInit(DeferredContext);
	} while (0);

	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}

VOID VmxStopVT(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	AsmVmCall('byte', NULL, NULL, NULL, NULL);
	VmxDestory();

	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	Log("DriverUnload");

	KeGenericCallDpc(VmxStopVT, NULL);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	//返回地址就是NtOpenProcess加20个字节
	NtOpenProcessRet = (ULONG64)NtOpenProcess + 20;

	KeGenericCallDpc(VmxStartVT, AsmVmxExitHandler);

	SetEptHook(NtOpenProcess, AsmNtOpenProcess);

	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}