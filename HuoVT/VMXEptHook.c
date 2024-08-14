#include "VMXEptHook.h"
#include <intrin.h>
#include "SearchCode.h"
#include "AsmCode.h"
#include "Export.h"
#include "VMXDefine.h"
#include "VMXAsm.h"
#include "VMXEpt.h"
#include "VMX.h"
#include "VMXTools.h"

EptHookContext g_EptHookContext = { 0 };

VOID EptHookStart(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
)
{
	PEptHookContext context = (PEptHookContext)DeferredContext;

	ULONG64 retValue = 0;

	AsmVmCall(__EPT_PAGE_HOOK, context->kernelCR3, context->newAddrPageNumber, context->oldAddrPageNumber, &retValue);

	context->isHook = TRUE;

	Log("cpu number = %d hook = %llx retValue = %lld", KeGetCurrentProcessorNumberEx(NULL), context->oldAddrPageStart, retValue);

	KeSignalCallDpcDone(SystemArgument1);
	KeSignalCallDpcSynchronize(SystemArgument2);
}

/**
 * 把2M页拆成4K页
 */
VOID EptSplit(PEPDE_2MB pde)
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	//1个PDE下有512个PTE
	//我们得给切割
	PEPTE ptes = (PEPTE)ExAllocatePool(NonPagedPool, sizeof(EPTE) * 512);

	if (!ptes)
	{
		return;
	}

	for (INT i = 0; i < PTE_ENTRY_COUNT; i++)
	{
		ptes[i].Flags = 0;
		ptes[i].ExecuteAccess = 1;
		ptes[i].WriteAccess = 1;
		ptes[i].ReadAccess = 1;
		//ptes[i].MemoryType = cpuPcb->vmxEptp.MemoryType;
		//左移9位，相当于乘以512
		ptes[i].PageFrameNumber = (pde->PageFrameNumber << 9) + i;
	}

	EPDE pde4k;
	pde4k.Flags = 0;
	pde4k.ReadAccess = 1;
	pde4k.WriteAccess = 1;
	pde4k.ExecuteAccess = 1;
	pde4k.PageFrameNumber = MmGetPhysicalAddress(ptes).QuadPart / PAGE_SIZE;

	//用4K的PDE覆盖2M的PDE
	memcpy(pde, &pde4k, sizeof(pde4k));
}

VOID EptHookHandler(ULONG64 kernelCr3, ULONG64 newAddrPageNumber, ULONG64 oldAddrPageNumber, PULONG64 retValue)
{
	ULONG64 cr3 = __readcr3();
	//切CR3
	__writecr3(kernelCr3);

	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	//获取HPA
	do
	{
		ULONG64 oldGpa = oldAddrPageNumber * PAGE_SIZE;

		ULONG64 newGpa = newAddrPageNumber * PAGE_SIZE;

		//获取PDE
		PEPDE_2MB oldPde = GetPDE2MHpaByGpa(oldGpa);

		PEPDE_2MB newPde = GetPDE2MHpaByGpa(newGpa);

		if (!oldPde || !newPde)
		{
			break;
		}

		//把2M页切成4K页
		if (oldPde->LargePage)
		{
			EptSplit(oldPde);
		}

		//把2M页切成4K页
		if (newPde->LargePage)
		{
			EptSplit(newPde);
		}

		PEPTE oldPte = EptGetPte(oldGpa);

		//把老的页置为不可执行，从而触发异常
		oldPte->ExecuteAccess = 0;

		*retValue = TRUE;

	} while (0);

	__writecr3(cr3);

	//刷新CR3
	Asminvept(2, &cpuPcb->vmxEptp.Flags);
}

/**
 * 获取HOOK的长度
 */
INT GetHookLen(ULONG64 Addr, ULONG64 size, BOOLEAN isX64)
{
	PUCHAR tempAddr = Addr;
	INT totalSize = 0;
	INT len = 0;

	if (isX64)
	{
		do
		{
			len = insn_len_x86_64((ULONG64)tempAddr);

			tempAddr = tempAddr + len;

			totalSize += len;

		} while (totalSize < size);
	}
	else
	{
		do
		{
			len = insn_len_x86_32((ULONG64)tempAddr);

			tempAddr = tempAddr + len;

			totalSize += len;

		} while (totalSize < size);
	}

	return totalSize;
}

/**
 * 判断当前进程是否是X64
 */
BOOLEAN IsCurrentProcessX64()
{
	PEPROCESS Process = PsGetCurrentProcess();

	return PsGetProcessWow64Process(Process) == NULL;
}

/**
 * 获取当前进程的用户CR3
 */
ULONG64 GetCurrentProcessUserCR3()
{
	PEPROCESS process = PsGetCurrentProcess();

	ULONG number = GetWindowsVersionNumber();
	ULONG64 offset = 0;

	//获取 KPROCESS 中 UserDirectoryTableBase
	switch (number)
	{
	case 7:
		offset = 0x110;
		break;
	case 8:
	case 1507:
	case 1511:
	case 1607:
	case 1703:
	case 1709:
		offset = 0x278;
		break;
	case 1803:
	case 1809:
		offset = 0x280;
		break;
	case 1903:
	case 1909:
		offset = 0x280;
		break;
	case 2004:
	case 2009:
	case 2011:
	case 2012:
	case 2013:
		offset = 0x388;
		break;
	default:
		offset = 0x388;
		break;
	}

	ULONG64 userCr3 = *(PULONG64)((ULONG_PTR)process + offset);

	if (userCr3 & 1 == 0)
	{
		userCr3 = 1; //没有用户CR3
	}

	return userCr3;
}

/**
 * 获取EPT HOOK的上下文
 */
PEptHookContext GetEptHookContext(ULONG64 oldAddrPageStart, ULONG64 kernelCR3, ULONG64 userCR3)
{
	if (!oldAddrPageStart)
	{
		return NULL;
	}

	PEptHookContext head = (PEptHookContext)&g_EptHookContext.list;
	PEptHookContext next = head;

	PEptHookContext findContext = NULL;

	if (IsListEmpty(head))
	{
		return NULL;
	}

	//遍历链表
	do
	{
		if (next->oldAddrPageStart == oldAddrPageStart)
		{
			//内核HOOK
			if (next->isKernelHook)
			{
				findContext = next;
				break;
			}

			//3环HOOK
			if (next->kernelCR3 == kernelCR3 || (userCR3 != 1 && next->userCR3 == userCR3))
			{
				findContext = next;
				break;
			}
		}

		next = next->list.Flink;

	} while (next != head);

	return findContext;
}

/**
 * 初始化EPT HOOK上下文
 */
VOID InitEptHookContext(PEptHookContext context)
{
	memset(context, 0, sizeof(EptHookContext));

	ULONG64 kernelCR3 = __readcr3(); //获取内核CR3

	ULONG64 userCR3 = GetCurrentProcessUserCR3(); //获取用户CR3

	context->isHook = FALSE;
	context->kernelCR3 = kernelCR3;
	context->userCR3 = userCR3;

	InitializeListHead(&context->list);
}

/**
 * 设置EPT HOOK
 */
BOOLEAN SetEptHook(PVOID oldAddr, PVOID newAddr)
{
	if (!MmIsAddressValid(oldAddr) || !MmIsAddressValid(newAddr))
	{
		return FALSE;
	}

	ULONG64 kernelCR3 = __readcr3(); //获取内核CR3

	ULONG64 userCR3 = GetCurrentProcessUserCR3(); //获取用户CR3

	ULONG64 oldAddrPageStart = ((ULONG64)oldAddr >> 12) << 12; //获取页的起始地址

	if (g_EptHookContext.list.Flink == 0)
	{
		InitializeListHead(&g_EptHookContext.list);
	}

	PEptHookContext context = GetEptHookContext(oldAddrPageStart, kernelCR3, userCR3);

	//如果没有找到，说明
	if (!context)
	{
		context = ExAllocatePool(NonPagedPool, sizeof(EptHookContext));
		if (!context)
		{
			return FALSE;
		}

		InitEptHookContext(context);

		context->oldAddrPageStart = oldAddrPageStart;
	}

	context->oldAddr[context->hookCount] = oldAddr;
	context->newAddr[context->hookCount] = newAddr;

	//增加hook数量
	context->hookCount++;

	//创建一个新的假页
	if (!context->newAddrPageStart)
	{
		PHYSICAL_ADDRESS higPhy = { 0 };
		higPhy.QuadPart = -1;

		//创建新页
		PUCHAR newPage = MmAllocateContiguousMemory(PAGE_SIZE, higPhy);

		//复制内容
		memcpy(newPage, oldAddrPageStart, PAGE_SIZE);

		context->newAddrPageStart = newPage;

		context->newAddrPageNumber = MmGetPhysicalAddress(context->newAddrPageStart).QuadPart / PAGE_SIZE;

		context->oldAddrPageNumber = MmGetPhysicalAddress(oldAddrPageStart).QuadPart / PAGE_SIZE;
	}

	ULONG64 codeOffset = (ULONG64)oldAddr - oldAddrPageStart;
	//构建HOOK
	BOOLEAN isX64 = IsCurrentProcessX64();

	//如果大于最高用户地址，说明在内核层，是内核HOOK
	if (oldAddrPageStart > MmHighestUserAddress)
	{
		context->isKernelHook = TRUE;
	}

	if (isX64)
	{
		char code[] = {
			//push 0x12345678
			0x68, 0x78, 0x56, 0x34, 0x12,
			//mov dword ptr ss:[rsp + 0x4], 0x12345678
			0xC7, 0x44, 0x24, 0x04, 0x78, 0x56, 0x34, 0x12,
			//ret
			0xC3,
		};

		*(PULONG)&code[1] = (ULONG)((ULONG64)newAddr & 0xFFFFFFFF);
		*(PULONG)&code[9] = (ULONG)(((ULONG64)newAddr >> 32) & 0xFFFFFFFF);

		INT hookLen = GetHookLen(oldAddr, sizeof(code), isX64);

		context->hookLen = hookLen;

		INT fillLen = hookLen - sizeof(code);

		//复制HOOK数据
		memcpy((PUCHAR)context->newAddrPageStart + codeOffset, code, sizeof(code));
		//补全nop
		memset((PUCHAR)context->newAddrPageStart + codeOffset + sizeof(code), 0x90, fillLen);
	}
	else
	{
		char code[] = {
			//push 0x12345678
			0x68, 0x78, 0x56, 0x34, 0x12,
			//ret
			0xC3,
		};

		*(PULONG)&code[1] = (ULONG)((ULONG64)newAddr & 0xFFFFFFFF);

		INT hookLen = GetHookLen(oldAddr, sizeof(code), isX64);

		context->hookLen = hookLen;

		INT fillLen = hookLen - sizeof(code);

		memcpy((PUCHAR)context->newAddrPageStart + codeOffset, code, sizeof(code));
		memset((PUCHAR)context->newAddrPageStart + codeOffset + sizeof(code), 0x90, fillLen);
	}

	if (IsListEmpty(&context->list))
	{
		//插入到链表尾部
		InsertTailList(&g_EptHookContext.list, &context->list);
	}

	//调用vmcall进入VT 去HOOK
	KeGenericCallDpc(EptHookStart, context);

	return TRUE;
}