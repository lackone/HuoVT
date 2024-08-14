#pragma once
#include <ntifs.h>

#define _EPT_PAGE_HOOK_MAX 20

typedef struct _EptHookContext
{
	LIST_ENTRY list; //链表

	PVOID newAddr[_EPT_PAGE_HOOK_MAX];
	PVOID oldAddr[_EPT_PAGE_HOOK_MAX];

	PVOID newAddrPageStart; //新页的起始地址
	PVOID oldAddrPageStart; //老页的起始地址

	ULONG64 newAddrPageNumber; //新页的页帧
	ULONG64 oldAddrPageNumber; //老页的页帧

	ULONG64 kernelCR3; //内核CR3
	ULONG64 userCR3; //用户CR3

	ULONG64 hookLen; //HOOK的数据长度

	ULONG64 hookCount; //HOOK的数量
	BOOLEAN isHook;

	BOOLEAN isKernelHook;
} EptHookContext, * PEptHookContext;

VOID EptHookHandler(ULONG64 kernelCr3, ULONG64 CodePfNumber, ULONG64 DataPfNumber, PULONG64 isHook);

PEptHookContext GetEptHookContext(ULONG64 oldAddrPageStart, ULONG64 kernelCR3, ULONG64 userCR3);

BOOLEAN SetEptHook(PVOID oldAddr, PVOID newAddr);