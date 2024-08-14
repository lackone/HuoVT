#include "VMX.h"
#include <intrin.h>
#include "VMXDefine.h"
#include "VMXTools.h"
#include "VMXAsm.h"
#include "VMXEpt.h"

VMXCPUPCB vmxCpuPcbs[128] = { 0 };

PVMXCPUPCB GetVMXCPUPCB(ULONG cpuNumber)
{
	return &vmxCpuPcbs[cpuNumber];
}

PVMXCPUPCB GetCurrentVMXCPUPCB()
{
	return GetVMXCPUPCB(KeGetCurrentProcessorNumberEx(NULL));
}

VOID FullGdtDataItem(INT index, USHORT select)
{
	//��ȡGDT��
	GdtTable gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);

	//ȥ��ѡ������3λ
	select &= 0xFFF8;

	// 00cf9300`0000ffff ����λ����ݶ�ռ8�ֽ�
	ULONG limit = __segmentlimit(select);

	//��3λ��0���൱������3λ������8�����������select���ó���8
	PULONG item = (PULONG)(gdtTable.base + select);

	//��ȡbase
	LARGE_INTEGER itemBase = { 0 };
	itemBase.LowPart = (*item & 0xFFFF0000) >> 16;
	item += 1;
	itemBase.LowPart |= (*item & 0xFF000000) | ((*item & 0xFF) << 16);

	//����attr
	ULONG attr = (*item & 0x00F0FF00) >> 8;


	//if ((attr & 0x8000) == 0x8000)
	//{
	//	limit = (limit << 12) + 0xFFF; //���������
	//}

	if (select == 0)
	{
		attr |= 1 << 16; //����attrΪ��Ч������
	}

	__vmx_vmwrite(GUEST_ES_BASE + index * 2, itemBase.QuadPart);
	__vmx_vmwrite(GUEST_ES_LIMIT + index * 2, limit);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + index * 2, attr);
	__vmx_vmwrite(GUEST_ES_SELECTOR + index * 2, select);
}

VOID VmxInitVMCSGuest(ULONG64 guestEsp, ULONG64 guestEip)
{
	FullGdtDataItem(0, AsmReadES());
	FullGdtDataItem(1, AsmReadCS());
	FullGdtDataItem(2, AsmReadSS());
	FullGdtDataItem(3, AsmReadDS());
	FullGdtDataItem(4, AsmReadFS());
	FullGdtDataItem(5, AsmReadGS());
	FullGdtDataItem(6, AsmReadLDTR()); //LDTR����0

	//��ȡGDT��
	GdtTable gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);

	ULONG trSelect = AsmReadTR();
	trSelect &= 0xFFF8;
	ULONG trlimit = __segmentlimit(trSelect);

	LARGE_INTEGER trBase = { 0 };
	PULONG trItem = (PULONG)(gdtTable.base + trSelect);

	//��TR��TR�Ĵ�����ϵͳ�Σ�ռ16�ֽ�
	// 00008bb9`c0000067 00000000`fffff800
	// fffff800`00b9c000
	trBase.LowPart = ((trItem[0] >> 16) & 0xFFFF) | ((trItem[1] & 0xFF) << 16) | ((trItem[1] & 0xFF000000));
	trBase.HighPart = trItem[2];

	//����
	ULONG attr = (trItem[1] & 0x00F0FF00) >> 8;

	__vmx_vmwrite(GUEST_TR_BASE, trBase.QuadPart);
	__vmx_vmwrite(GUEST_TR_LIMIT, trlimit);
	__vmx_vmwrite(GUEST_TR_AR_BYTES, attr);
	__vmx_vmwrite(GUEST_TR_SELECTOR, trSelect);

	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_DR7, __readdr(7));
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(GUEST_RSP, guestEsp);
	__vmx_vmwrite(GUEST_RIP, guestEip);

	__vmx_vmwrite(VMCS_LINK_POINTER, -1);

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(IA32_MSR_DEBUGCTL));
	__vmx_vmwrite(GUEST_IA32_PAT, __readmsr(IA32_MSR_PAT));
	__vmx_vmwrite(GUEST_IA32_EFER, __readmsr(IA32_MSR_EFER));

	__vmx_vmwrite(GUEST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE, __readmsr(IA32_GS_BASE));

	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(0x174));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(0x175));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(0x176));

	//IDT GDT
	GdtTable idtTable = { 0 };
	__sidt(&idtTable);

	__vmx_vmwrite(GUEST_GDTR_BASE, gdtTable.base);
	__vmx_vmwrite(GUEST_GDTR_LIMIT, gdtTable.limit);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, idtTable.limit);
	__vmx_vmwrite(GUEST_IDTR_BASE, idtTable.base);
}

VOID VmxInitVMCSHost(ULONG64 HostEip)
{
	GdtTable gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);

	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	ULONG trSelect = AsmReadTR();
	trSelect &= 0xFFF8;
	LARGE_INTEGER trBase = { 0 };
	PULONG trItem = (PULONG)(gdtTable.base + trSelect);
	//��TR
	trBase.LowPart = ((trItem[0] >> 16) & 0xFFFF) | ((trItem[1] & 0xFF) << 16) | ((trItem[1] & 0xFF000000));
	trBase.HighPart = trItem[2];

	//����
	__vmx_vmwrite(HOST_TR_BASE, trBase.QuadPart);
	__vmx_vmwrite(HOST_TR_SELECTOR, trSelect);
	__vmx_vmwrite(HOST_ES_SELECTOR, AsmReadES() & 0xfff8);
	__vmx_vmwrite(HOST_CS_SELECTOR, AsmReadCS() & 0xfff8);
	__vmx_vmwrite(HOST_SS_SELECTOR, AsmReadSS() & 0xfff8);
	__vmx_vmwrite(HOST_DS_SELECTOR, AsmReadDS() & 0xfff8);
	__vmx_vmwrite(HOST_FS_SELECTOR, AsmReadFS() & 0xfff8);
	__vmx_vmwrite(HOST_GS_SELECTOR, AsmReadGS() & 0xfff8);

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	__vmx_vmwrite(HOST_CR3, __readcr3());

	__vmx_vmwrite(HOST_RSP, (ULONG64)cpuPcb->vmxHostStackBase);
	__vmx_vmwrite(HOST_RIP, HostEip);

	__vmx_vmwrite(HOST_IA32_PAT, __readmsr(IA32_MSR_PAT));
	__vmx_vmwrite(HOST_IA32_EFER, __readmsr(IA32_MSR_EFER));

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(IA32_GS_BASE));

	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(0x174));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(0x175));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(0x176));

	//IDT GDT
	GdtTable idtTable = { 0 };
	__sidt(&idtTable);

	__vmx_vmwrite(HOST_GDTR_BASE, gdtTable.base);
	__vmx_vmwrite(HOST_IDTR_BASE, idtTable.base);

}

VOID VmxInitEntry()
{
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);
	//�õ�55λ���ж����ĸ��Ĵ���
	ULONG64 reg = ((basic >> 55) & 1) ? IA32_MSR_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;

	//��9λ��IA-32e mode guestΪ1
	ULONG64 value = VmxGetWriteControlValue(0x200, reg);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, value);
	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
}

VOID VmxInitExit()
{
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);
	//�õ�55λ���ж����ĸ��Ĵ���
	ULONG64 reg = ((basic >> 55) & 1) ? IA32_MSR_VMX_TRUE_EXIT_CTLS : IA32_MSR_VMX_EXIT_CTLS;

	//��9λ��host address-space size Ϊ1
	//��15λ��acknowledge interrupt on exit Ϊ1
	ULONG64 value = VmxGetWriteControlValue(0x200 | 0x8000, reg);

	__vmx_vmwrite(VM_EXIT_CONTROLS, value);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_INTR_INFO, 0);
}

VOID VmxInitControls()
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	ULONG64 basic = __readmsr(IA32_VMX_BASIC);
	//�õ�55λ���ж����ĸ��Ĵ���
	ULONG64 reg = ((basic >> 55) & 1) ? IA32_MSR_VMX_TRUE_PINBASED_CTLS : IA32_MSR_VMX_PINBASED_CTLS;

	ULONG64 value = VmxGetWriteControlValue(0, reg);

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, value);

	reg = ((basic >> 55) & 1) ? IA32_MSR_VMX_TRUE_PROCBASED_CTLS : IA32_MSR_VMX_PROCBASED_CTLS;

	//���� activate secondary controls ֧�� win10
	ULONG64 cpuValue = CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;

	//����CR3
	//cpuValue |= CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING;

	value = VmxGetWriteControlValue(cpuValue, reg);

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, value);

	//����msrBitMap
	PHYSICAL_ADDRESS phy = { 0 };
	phy.QuadPart = -1;
	cpuPcb->msrBitMap = MmAllocateContiguousMemory(PAGE_SIZE, phy);
	memset(cpuPcb->msrBitMap, 0, PAGE_SIZE);
	cpuPcb->msrBitMapAddrPhy = MmGetPhysicalAddress(cpuPcb->msrBitMap);

	__vmx_vmwrite(MSR_BITMAP, cpuPcb->msrBitMapAddrPhy.QuadPart);

	//���� syscall
	//win7 KiSystemCall64
	//win10 KiSystemCall64Shadow
	//VmxSetReadMsrBitmap(cpuPcb->msrBitMap, 0xC0000082, TRUE);
	//VmxSetWriteMsrBitmap(cpuPcb->msrBitMap, 0xC0000082, TRUE);

	//����BIOS�Ƿ�֧��VT
	VmxSetReadMsrBitmap(cpuPcb->msrBitMap, IA32_FEATURE_CONTROL, TRUE);
	VmxSetWriteMsrBitmap(cpuPcb->msrBitMap, IA32_FEATURE_CONTROL, TRUE);

	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE3, 0);

	//����CR4��VT�Ƿ���
	ULONG64 cr4 = __readcr4();
	__vmx_vmwrite(CR4_READ_SHADOW, cr4 & (~0x2000));
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, cr4 & 0x2000);

	//��չ����
	reg = IA32_MSR_VMX_PROCBASED_CTLS2;

	//���� RDTSCP INVPCID XSAVES ֧�� win10
	ULONG64 secValue = SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_INVPCID | SECONDARY_EXEC_XSAVES;

	//����EPT
	if (VmxInitEPT())
	{
		secValue |= SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_VPID;

		//����VPID �Ż�Ч��
		ULONG number = KeGetCurrentProcessorNumberEx(NULL);
		__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, number + 1);

		//д��EPT ��ַ
		__vmx_vmwrite(EPT_POINTER, cpuPcb->vmxEptp.Flags);
	}

	value = VmxGetWriteControlValue(secValue, reg);
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, value);

	//�����쳣����
	//int3
	ULONG64 exceptionBitmap = 1 << 3;
	__vmx_vmwrite(EXCEPTION_BITMAP, exceptionBitmap);
}

INT VmxInitVMCS(ULONG64 guestEsp, ULONG64 guestEip, ULONG64 hostEip)
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	//����һ���ڴ�
	PHYSICAL_ADDRESS lowPhys = { 0 };
	PHYSICAL_ADDRESS higPhys = { 0 };
	lowPhys.QuadPart = 0;  //��ʾ 0x0
	higPhys.QuadPart = -1; //-1��ʾ0xFFFFFFFF`FFFFFFFF

	//����Ƿ�ҳ�ڴ�
	cpuPcb->vmcsAddr = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lowPhys, higPhys, lowPhys, MmCached);

	if (!cpuPcb->vmcsAddr)
	{
		//�����ڴ�ʧ��
		return -1;
	}

	//��ʼ������ֹδ��������ҳ
	memset(cpuPcb->vmcsAddr, 0, PAGE_SIZE);
	//��ȡ�����ַ
	cpuPcb->vmcsAddrPhy = MmGetPhysicalAddress(cpuPcb->vmcsAddr);

	cpuPcb->vmxHostStackTop = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 36, lowPhys, higPhys, lowPhys, MmCached);

	if (!cpuPcb->vmxHostStackTop)
	{
		//�����ڴ�ʧ��
		return -1;
	}

	memset(cpuPcb->vmxHostStackTop, 0, PAGE_SIZE * 36);
	cpuPcb->vmxHostStackBase = (ULONG64)cpuPcb->vmxHostStackTop + PAGE_SIZE * 36 - 0x200;


	//�� IA32_VMX_BASIC �Ĵ�������ȡ VMCS_ID
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);

	//4�ֽڣ����ID
	*(PULONG)(cpuPcb->vmcsAddr) = (ULONG)basic;

	//��״̬���
	__vmx_vmclear(&cpuPcb->vmcsAddrPhy.QuadPart);

	//����vmcs�ṹ
	__vmx_vmptrld(&cpuPcb->vmcsAddrPhy.QuadPart);

	VmxInitVMCSGuest(guestEsp, guestEip);

	VmxInitVMCSHost(hostEip);

	VmxInitEntry();

	VmxInitExit();

	VmxInitControls();

	return 0;
}

VOID VmxDestory()
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	if (cpuPcb->vmxonAddr && MmIsAddressValid(cpuPcb->vmxonAddr))
	{
		MmFreeContiguousMemorySpecifyCache(cpuPcb->vmxonAddr, PAGE_SIZE, MmCached);
	}

	cpuPcb->vmxonAddr = NULL;

	if (cpuPcb->vmcsAddr && MmIsAddressValid(cpuPcb->vmcsAddr))
	{
		MmFreeContiguousMemorySpecifyCache(cpuPcb->vmcsAddr, PAGE_SIZE, MmCached);
	}

	cpuPcb->vmcsAddr = NULL;

	if (cpuPcb->vmxHostStackTop && MmIsAddressValid(cpuPcb->vmxHostStackTop))
	{
		MmFreeContiguousMemorySpecifyCache(cpuPcb->vmxHostStackTop, PAGE_SIZE * 36, MmCached);
	}

	cpuPcb->vmxHostStackTop = NULL;

	if (cpuPcb->msrBitMap && MmIsAddressValid(cpuPcb->msrBitMap))
	{
		MmFreeContiguousMemory(cpuPcb->msrBitMap);
	}

	cpuPcb->msrBitMap = NULL;

	if (cpuPcb->vmxManagerPage && MmIsAddressValid(cpuPcb->vmxManagerPage))
	{
		ExFreePool(cpuPcb->vmxManagerPage);
	}

	cpuPcb->vmxManagerPage = NULL;

	//����CR4�ĵ�14λ
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;
	__writecr4(cr4);
}

INT VmxInit(ULONG64 hostEip)
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	cpuPcb->cpuNumber = KeGetCurrentProcessorNumberEx(NULL);

	// call���ö�ջͼ
	//  xxxxx
	//  xxxxx
	//  ������ջ
	//  xxxxx
	//  call��һ�е�ַ,���ص�ַ ��=  ESPָ������
	//  ����1
	//  ����2
	//  ����3

	//��ȡ���ص�ַ�ĵ�ַ��Ҳ���൱����ESP����ESP���ֵ�����Ƿ��ص�ַ
	PULONG64 retAddr = (PULONG64)_AddressOfReturnAddress();
	//+1��64λ�൱�ڼ�8�ֽڣ�ָ�����1��λ�ã�������һ��������ESP
	ULONG64 guestEsp = retAddr + 1;
	ULONG64 guestEip = *retAddr;

	INT error = VmxInitVmON();

	//0��ȷ����0����
	if (error)
	{
		Log("vmon��ʼ��ʧ�� error = %d cpunumber = %d", error, KeGetCurrentProcessorNumberEx(NULL));
		return error;
	}


	error = VmxInitVMCS(guestEsp, guestEip, hostEip);

	if (error)
	{
		Log("vmcs��ʼ��ʧ�� error = %d cpunumber = %d", error, KeGetCurrentProcessorNumberEx(NULL));

		__vmx_off();
		VmxDestory();
		return error;
	}

	//����VT
	error = __vmx_vmlaunch();

	if (error)
	{
		Log("__vmx_vmlaunchʧ�� error = %d cpunumber = %d", error, KeGetCurrentProcessorNumberEx(NULL));

		__vmx_off();
		VmxDestory();
		return error;
	}

	return 0;
}



INT VmxInitVmON()
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	//����һ���ڴ�
	PHYSICAL_ADDRESS lowPhys = { 0 };
	PHYSICAL_ADDRESS higPhys = { 0 };
	lowPhys.QuadPart = 0;  //��ʾ 0x0
	higPhys.QuadPart = -1; //-1��ʾ0xFFFFFFFF`FFFFFFFF

	//����Ƿ�ҳ�ڴ�
	cpuPcb->vmxonAddr = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lowPhys, higPhys, lowPhys, MmCached);

	if (!cpuPcb->vmxonAddr)
	{
		//�����ڴ�ʧ��
		return -1;
	}

	//��ʼ������ֹδ��������ҳ
	memset(cpuPcb->vmxonAddr, 0, PAGE_SIZE);
	//��ȡ�����ַ
	cpuPcb->vmxonAddrPhy = MmGetPhysicalAddress(cpuPcb->vmxonAddr);

	//�� IA32_VMX_BASIC �Ĵ�������ȡ VMCS_ID
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);

	//4�ֽڣ����ID
	*(PULONG)(cpuPcb->vmxonAddr) = (ULONG)basic;

	//��ʼ�� CR0��CR4
	ULONG64 cr0Fixed0 = __readmsr(IA32_VMX_CR0_FIXED0);
	ULONG64 cr0Fixed1 = __readmsr(IA32_VMX_CR0_FIXED1);
	ULONG64 cr4Fixed0 = __readmsr(IA32_VMX_CR4_FIXED0);
	ULONG64 cr4Fixed1 = __readmsr(IA32_VMX_CR4_FIXED1);

	ULONG64 cr4 = __readcr4();
	ULONG64 cr0 = __readcr0();

	//�Ȼ� ��Ȼ���� ��
	cr4 |= cr4Fixed0;
	cr4 &= cr4Fixed1;

	cr0 |= cr0Fixed0;
	cr0 &= cr0Fixed1;

	//�޸� CR0 , CR4
	__writecr0(cr0);

	__writecr4(cr4);

	//ָ�� 64 λ 4KB ���������ַ��ָ�� VMXON ���򣩵�ָ�롣
	INT error = __vmx_on(&cpuPcb->vmxonAddrPhy.QuadPart);

	if (error)
	{
		//��������ͷ��ڴ棬����CR4
		cr4 &= ~cr4Fixed0; //�Ե�14λVMXEȡ��
		__writecr4(cr4);

		//�ͷ��ڴ�
		MmFreeContiguousMemorySpecifyCache(cpuPcb->vmxonAddr, PAGE_SIZE, MmCached);

		cpuPcb->vmxonAddr = NULL;
		cpuPcb->vmxonAddrPhy.QuadPart = 0;
	}

	return error;
}