#include "VMXEpt.h"
#include "VMX.h"
#include "VMXDefine.h"
#include <intrin.h>
#include "VMXEptHook.h"
#include "VMXAsm.h"

#define ACCESS_EPT_READ		1
#define ACCESS_EPT_WRITE	2
#define ACCESS_EPT_EXECUTE	4

BOOLEAN VmxCheckEPT()
{
	//IA32_VMX_PROCBASED_CTLS2[33]=1,��ʾ֧��EPT
	ULONG64 ctls2 = __readmsr(IA32_MSR_VMX_PROCBASED_CTLS2);

	if (((ctls2 >> 33) & 1) == 0)
	{
		return FALSE;
	}

	//�ж�
	//��1λ ����ִֻ��
	//��7λ ֧��4��ҳ��
	//��17λ ֧��2Mҳ��
	ULONG64 cap = __readmsr(IA32_MSR_VMX_EPT_VPID_CAP);

	BOOLEAN isExec = cap & 1;
	BOOLEAN is4Level = (cap >> 6) & 1;
	BOOLEAN is2M = (cap >> 16) & 1;

	if (!isExec || !is4Level || !is2M)
	{
		return FALSE;
	}

	return TRUE;
}

BOOLEAN VmxInitEPT()
{
	if (!VmxCheckEPT())
	{
		return FALSE;
	}

	ULONG64 cap = __readmsr(IA32_MSR_VMX_EPT_VPID_CAP);

	//�Ƿ�֧�ֻ�д
	BOOLEAN isWB = (cap >> 14) & 1;

	//֧�ֻ�д������EPTP��0-2λ������ WB���ͣ�ֵΪ6
	//6 �ǻ����д���ԣ�0 ��û�л���
	ULONG memoryType = isWB ? 6 : 0;

	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	cpuPcb->vmxManagerPage = ExAllocatePool(NonPagedPool, sizeof(VMX_MAMAGER_PAGE_ENTRY));

	if (!cpuPcb->vmxManagerPage)
	{
		return FALSE;
	}

	memset(cpuPcb->vmxManagerPage, 0, sizeof(VMX_MAMAGER_PAGE_ENTRY));

	//���������
	cpuPcb->vmxManagerPage->pmlt[0].Flags = 0;
	cpuPcb->vmxManagerPage->pmlt[0].ExecuteAccess = 1;
	cpuPcb->vmxManagerPage->pmlt[0].ReadAccess = 1;
	cpuPcb->vmxManagerPage->pmlt[0].WriteAccess = 1;
	cpuPcb->vmxManagerPage->pmlt[0].PageFrameNumber = MmGetPhysicalAddress(&cpuPcb->vmxManagerPage->pdptt[0]).QuadPart / PAGE_SIZE;

	for (int i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
		cpuPcb->vmxManagerPage->pdptt[i].Flags = 0;
		cpuPcb->vmxManagerPage->pdptt[i].ExecuteAccess = 1;
		cpuPcb->vmxManagerPage->pdptt[i].ReadAccess = 1;
		cpuPcb->vmxManagerPage->pdptt[i].WriteAccess = 1;
		cpuPcb->vmxManagerPage->pdptt[i].PageFrameNumber = MmGetPhysicalAddress(&cpuPcb->vmxManagerPage->pdt[i][0]).QuadPart / PAGE_SIZE;

		for (int j = 0; j < PDE_ENTRY_COUNT; j++)
		{
			cpuPcb->vmxManagerPage->pdt[i][j].Flags = 0;
			cpuPcb->vmxManagerPage->pdt[i][j].ExecuteAccess = 1;
			cpuPcb->vmxManagerPage->pdt[i][j].ReadAccess = 1;
			cpuPcb->vmxManagerPage->pdt[i][j].WriteAccess = 1;
			cpuPcb->vmxManagerPage->pdt[i][j].MemoryType = memoryType;
			cpuPcb->vmxManagerPage->pdt[i][j].LargePage = 1; //��ҳ��2M
			cpuPcb->vmxManagerPage->pdt[i][j].PageFrameNumber = (i * 512 + j);

			//�����4Kҳ�����ٶ�һ��ѭ��
			//cpuPcb->vmxManagerPage->pte[i][j].PageFrameNumber = MmGetPhysicalAddress(&cpuPcb->vmxManagerPage->pte[i][j][0]).QuadPart / PAGE_SIZE;
			//for (int k = 0; k < PTE_ENTRY_COUNT; k++)
			//{
			//	cpuPcb->vmxManagerPage->pte[i][j][k].PageFrameNumber = (i * (512 * 512)) + (j * 512) + k;
			//}
		}
	}

	cpuPcb->vmxEptp.Flags = 0;
	cpuPcb->vmxEptp.MemoryType = memoryType;
	cpuPcb->vmxEptp.PageWalkLength = 3;
	cpuPcb->vmxEptp.EnableAccessAndDirtyFlags = (cap >> 21) & 1;
	cpuPcb->vmxEptp.PageFrameNumber = MmGetPhysicalAddress(&cpuPcb->vmxManagerPage->pmlt[0]).QuadPart / PAGE_SIZE;

	return TRUE;
}

PEPDE_2MB GetPDE2MHpaByGpa(ULONG64 gpa)
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	//PML4E index
	ULONG64 pml4eIndex = EPML4_INDEX(gpa);

	if (pml4eIndex > 0)
	{
		return NULL;
	}

	//PDPTE index
	ULONG64 pdpteIndex = EPDPTE_INDEX(gpa);

	//PDE index
	ULONG64 pdeIndex = EPDE_INDEX(gpa);

	return &cpuPcb->vmxManagerPage->pdt[pdpteIndex][pdeIndex];
}

/**
 * ��ȡPTE
 */
PEPTE EptGetPte(ULONG64 PfNumber)
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	PEPDE_2MB pde = GetPDE2MHpaByGpa(PfNumber);

	//����Ǵ�ҳ��ֱ�ӷ���NULL
	if (pde->LargePage)
	{
		return NULL;
	}

	//ע�⣬����Ҫת��4Kҳ
	PEPDE pde4K = (PEPDE)pde;

	//PDE��PageFrameNumber����PAGE_SIZE��������ַָ�����PTE���׵�ַ
	ULONG64 ptePhy = pde4K->PageFrameNumber * PAGE_SIZE;

	PHYSICAL_ADDRESS ptePhyAddr = { 0 };

	ptePhyAddr.QuadPart = ptePhy;

	//ͨ�������ַ��ȡ�������Ե�ַ
	PEPTE ptes = (PEPTE)MmGetVirtualForPhysical(ptePhyAddr);
	//��ȡpte������
	ULONG64 pteindex = EPTE_INDEX(PfNumber);

	return &ptes[pteindex];
}

VOID VmxUpdateEptPage(ULONG Access, ULONG64 cr3, ULONG64 lineAddr, ULONG64 guestPhyAddress)
{
	ULONG64 startPage = (lineAddr >> 12) << 12;

	PEptHookContext context = GetEptHookContext(startPage, cr3, cr3);

	if (!context)
	{
		return;
	}

	//ͨ��GPA����ȡPTE
	PEPTE pte = EptGetPte(guestPhyAddress);

	if (!pte)
	{
		return;
	}

	if (Access == ACCESS_EPT_READ)
	{
		//PEPTE readPte = EptGetPte(context->OldFunAddrNumber * PAGE_SIZE);
		//
		//if (!readPte) return;
		pte->PageFrameNumber = context->oldAddrPageNumber;

		pte->ReadAccess = 1;

		pte->ExecuteAccess = 0;

		pte->WriteAccess = 1;

		__invlpg(lineAddr);
	}
	else if (Access == ACCESS_EPT_EXECUTE)
	{
		//PEPTE codePte = EptGetPte(context->NewAddrPageNumber * PAGE_SIZE);
		//
		//if (!codePte) return;
		pte->PageFrameNumber = context->newAddrPageNumber;

		pte->ReadAccess = 0;

		pte->ExecuteAccess = 1;

		pte->WriteAccess = 0;

		__invlpg(lineAddr);

	}
	else if (Access == ACCESS_EPT_WRITE)
	{
		pte->PageFrameNumber = context->oldAddrPageNumber;

		pte->ReadAccess = 1;

		pte->ExecuteAccess = 0;

		pte->WriteAccess = 1;

		__invlpg(lineAddr);
	}
}

VOID VmxEptHandler(PGuestContext context)
{
	struct
	{
		ULONG64 read : 1;
		ULONG64 wrire : 1;
		ULONG64 execute : 1;
		ULONG64 readable : 1;
		ULONG64 wrireable : 1;
		ULONG64 executeable : 1;
		ULONG64 un1 : 1;
		ULONG64 vaild : 1;
		ULONG64 translation : 1;
		ULONG64 un2 : 3;
		ULONG64 NMIUnblocking : 1;
		ULONG64 un3 : 51;
	} eptinfo;

	//0x400000 => mov eax, dword ptr ds:[0x12345678] ������г����쳣
	//��ô rip Ϊ 0x400000
	//LineAddress ���� 0x12345678
	ULONG64 rip = 0;
	ULONG64 rsp = 0;
	ULONG64 cr3 = 0;
	ULONG64 instLen = 0; //ָ���

	ULONG64 guestLineAddress = 0;
	ULONG64 guestPhyAddress = 0;

	__vmx_vmread(EXIT_QUALIFICATION, (PULONG64)&eptinfo); //ƫ����

	__vmx_vmread(GUEST_RSP, &rsp);
	__vmx_vmread(GUEST_RIP, &rip);
	__vmx_vmread(GUEST_CR3, &cr3);

	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instLen); // ��ȡָ���

	if (!eptinfo.vaild)
	{
		return;
	}

	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	//��ȡ���Ե�ַ
	__vmx_vmread(GUEST_LINEAR_ADDRESS, &guestLineAddress);
	//��ȡGPA
	__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &guestPhyAddress);

	if (eptinfo.read)
	{
		//��������쳣
		VmxUpdateEptPage(ACCESS_EPT_READ, cr3, guestLineAddress, guestPhyAddress);
	}

	if (eptinfo.wrire)
	{
		//д������쳣
		VmxUpdateEptPage(ACCESS_EPT_WRITE, cr3, guestLineAddress, guestPhyAddress);
	}

	if (eptinfo.execute)
	{
		//ִ��������쳣
		VmxUpdateEptPage(ACCESS_EPT_EXECUTE, cr3, guestLineAddress, guestPhyAddress);
	}

	Asminvept(2, &cpuPcb->vmxEptp.Flags);

	__vmx_vmwrite(GUEST_RIP, rip);
	__vmx_vmwrite(GUEST_RSP, rsp);
}