#pragma once
#include <ntifs.h>
#include "VMXEpt.h"

typedef struct _VMXCPUPCB
{
	ULONG cpuNumber; //核号
	PVOID vmxonAddr; //虚拟地址
	PHYSICAL_ADDRESS vmxonAddrPhy; //物理地址

	PVOID vmcsAddr;
	PHYSICAL_ADDRESS vmcsAddrPhy; //物理地址

	PVOID vmxHostStackTop;	//栈顶 小
	PVOID vmxHostStackBase; //栈底 大

	PVOID msrBitMap;  //
	PHYSICAL_ADDRESS msrBitMapAddrPhy;

	PVMX_MAMAGER_PAGE_ENTRY vmxManagerPage; //管理页
	VMX_EPTP vmxEptp; //相当于CR3

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