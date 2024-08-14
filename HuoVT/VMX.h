#pragma once
#include <ntifs.h>
#include "VMXEpt.h"

typedef struct _VMXCPUPCB
{
	ULONG cpuNumber; //�˺�
	PVOID vmxonAddr; //�����ַ
	PHYSICAL_ADDRESS vmxonAddrPhy; //�����ַ

	PVOID vmcsAddr;
	PHYSICAL_ADDRESS vmcsAddrPhy; //�����ַ

	PVOID vmxHostStackTop;	//ջ�� С
	PVOID vmxHostStackBase; //ջ�� ��

	PVOID msrBitMap;  //
	PHYSICAL_ADDRESS msrBitMapAddrPhy;

	PVMX_MAMAGER_PAGE_ENTRY vmxManagerPage; //����ҳ
	VMX_EPTP vmxEptp; //�൱��CR3

} VMXCPUPCB, * PVMXCPUPCB;

#pragma pack(push, 1)
typedef struct _GdtTable
{
	USHORT limit;
	ULONG64 base;
} GdtTable, * PGdtTable;
#pragma pack(pop)

PVMXCPUPCB GetVMXCPUPCB(ULONG cpuNumber);

PVMXCPUPCB GetCurrentVMXCPUPCB();

INT VmxInit(ULONG64 hostEip);

INT VmxInitVmON();

VOID VmxDestory();

VOID FullGdtDataItem(INT index, USHORT select);