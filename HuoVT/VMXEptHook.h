#pragma once
#include <ntifs.h>

#define _EPT_PAGE_HOOK_MAX 20

typedef struct _EptHookContext
{
	LIST_ENTRY list; //����

	PVOID newAddr[_EPT_PAGE_HOOK_MAX];
	PVOID oldAddr[_EPT_PAGE_HOOK_MAX];

	PVOID newAddrPageStart; //��ҳ����ʼ��ַ
	PVOID oldAddrPageStart; //��ҳ����ʼ��ַ

	ULONG64 newAddrPageNumber; //��ҳ��ҳ֡
	ULONG64 oldAddrPageNumber; //��ҳ��ҳ֡

	ULONG64 kernelCR3; //�ں�CR3
	ULONG64 userCR3; //�û�CR3

	ULONG64 hookLen; //HOOK�����ݳ���

	ULONG64 hookCount; //HOOK������
	BOOLEAN isHook;

	BOOLEAN isKernelHook;
} EptHookContext, * PEptHookContext;

VOID EptHookHandler(ULONG64 kernelCr3, ULONG64 CodePfNumber, ULONG64 DataPfNumber, PULONG64 isHook);

PEptHookContext GetEptHookContext(ULONG64 oldAddrPageStart, ULONG64 kernelCR3, ULONG64 userCR3);

BOOLEAN SetEptHook(PVOID oldAddr, PVOID newAddr);