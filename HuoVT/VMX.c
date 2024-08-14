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
	//获取GDT表
	GdtTable gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);

	//去掉选择子右3位
	select &= 0xFFF8;

	// 00cf9300`0000ffff 代码段或数据段占8字节
	ULONG limit = __segmentlimit(select);

	//右3位置0，相当于左移3位，乘以8，所以下面的select不用乘以8
	PULONG item = (PULONG)(gdtTable.base + select);

	//获取base
	LARGE_INTEGER itemBase = { 0 };
	itemBase.LowPart = (*item & 0xFFFF0000) >> 16;
	item += 1;
	itemBase.LowPart |= (*item & 0xFF000000) | ((*item & 0xFF) << 16);

	//属性attr
	ULONG attr = (*item & 0x00F0FF00) >> 8;


	//if ((attr & 0x8000) == 0x8000)
	//{
	//	limit = (limit << 12) + 0xFFF; //换算颗粒度
	//}

	if (select == 0)
	{
		attr |= 1 << 16; //代表attr为无效的属性
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
	FullGdtDataItem(6, AsmReadLDTR()); //LDTR就是0

	//获取GDT表
	GdtTable gdtTable = { 0 };
	AsmGetGdtTable(&gdtTable);

	ULONG trSelect = AsmReadTR();
	trSelect &= 0xFFF8;
	ULONG trlimit = __segmentlimit(trSelect);

	LARGE_INTEGER trBase = { 0 };
	PULONG trItem = (PULONG)(gdtTable.base + trSelect);

	//读TR，TR寄存器是系统段，占16字节
	// 00008bb9`c0000067 00000000`fffff800
	// fffff800`00b9c000
	trBase.LowPart = ((trItem[0] >> 16) & 0xFFFF) | ((trItem[1] & 0xFF) << 16) | ((trItem[1] & 0xFF000000));
	trBase.HighPart = trItem[2];

	//属性
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
	//读TR
	trBase.LowPart = ((trItem[0] >> 16) & 0xFFFF) | ((trItem[1] & 0xFF) << 16) | ((trItem[1] & 0xFF000000));
	trBase.HighPart = trItem[2];

	//属性
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
	//拿到55位，判断用哪个寄存器
	ULONG64 reg = ((basic >> 55) & 1) ? IA32_MSR_VMX_TRUE_ENTRY_CTLS : IA32_VMX_ENTRY_CTLS;

	//第9位，IA-32e mode guest为1
	ULONG64 value = VmxGetWriteControlValue(0x200, reg);
	__vmx_vmwrite(VM_ENTRY_CONTROLS, value);
	__vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
}

VOID VmxInitExit()
{
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);
	//拿到55位，判断用哪个寄存器
	ULONG64 reg = ((basic >> 55) & 1) ? IA32_MSR_VMX_TRUE_EXIT_CTLS : IA32_MSR_VMX_EXIT_CTLS;

	//第9位，host address-space size 为1
	//第15位，acknowledge interrupt on exit 为1
	ULONG64 value = VmxGetWriteControlValue(0x200 | 0x8000, reg);

	__vmx_vmwrite(VM_EXIT_CONTROLS, value);
	__vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	__vmx_vmwrite(VM_EXIT_INTR_INFO, 0);
}

VOID VmxInitControls()
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	ULONG64 basic = __readmsr(IA32_VMX_BASIC);
	//拿到55位，判断用哪个寄存器
	ULONG64 reg = ((basic >> 55) & 1) ? IA32_MSR_VMX_TRUE_PINBASED_CTLS : IA32_MSR_VMX_PINBASED_CTLS;

	ULONG64 value = VmxGetWriteControlValue(0, reg);

	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, value);

	reg = ((basic >> 55) & 1) ? IA32_MSR_VMX_TRUE_PROCBASED_CTLS : IA32_MSR_VMX_PROCBASED_CTLS;

	//开启 activate secondary controls 支持 win10
	ULONG64 cpuValue = CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;

	//拦载CR3
	//cpuValue |= CPU_BASED_CR3_LOAD_EXITING | CPU_BASED_CR3_STORE_EXITING;

	value = VmxGetWriteControlValue(cpuValue, reg);

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, value);

	//设置msrBitMap
	PHYSICAL_ADDRESS phy = { 0 };
	phy.QuadPart = -1;
	cpuPcb->msrBitMap = MmAllocateContiguousMemory(PAGE_SIZE, phy);
	memset(cpuPcb->msrBitMap, 0, PAGE_SIZE);
	cpuPcb->msrBitMapAddrPhy = MmGetPhysicalAddress(cpuPcb->msrBitMap);

	__vmx_vmwrite(MSR_BITMAP, cpuPcb->msrBitMapAddrPhy.QuadPart);

	//拦截 syscall
	//win7 KiSystemCall64
	//win10 KiSystemCall64Shadow
	//VmxSetReadMsrBitmap(cpuPcb->msrBitMap, 0xC0000082, TRUE);
	//VmxSetWriteMsrBitmap(cpuPcb->msrBitMap, 0xC0000082, TRUE);

	//拦载BIOS是否支持VT
	VmxSetReadMsrBitmap(cpuPcb->msrBitMap, IA32_FEATURE_CONTROL, TRUE);
	VmxSetWriteMsrBitmap(cpuPcb->msrBitMap, IA32_FEATURE_CONTROL, TRUE);

	__vmx_vmwrite(CR3_TARGET_COUNT, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE0, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE1, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE2, 0);
	__vmx_vmwrite(CR3_TARGET_VALUE3, 0);

	//隐藏CR4中VT是否开启
	ULONG64 cr4 = __readcr4();
	__vmx_vmwrite(CR4_READ_SHADOW, cr4 & (~0x2000));
	__vmx_vmwrite(CR4_GUEST_HOST_MASK, cr4 & 0x2000);

	//扩展部分
	reg = IA32_MSR_VMX_PROCBASED_CTLS2;

	//开启 RDTSCP INVPCID XSAVES 支持 win10
	ULONG64 secValue = SECONDARY_EXEC_ENABLE_RDTSCP | SECONDARY_EXEC_ENABLE_INVPCID | SECONDARY_EXEC_XSAVES;

	//开启EPT
	if (VmxInitEPT())
	{
		secValue |= SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_VPID;

		//增加VPID 优化效率
		ULONG number = KeGetCurrentProcessorNumberEx(NULL);
		__vmx_vmwrite(VIRTUAL_PROCESSOR_ID, number + 1);

		//写入EPT 地址
		__vmx_vmwrite(EPT_POINTER, cpuPcb->vmxEptp.Flags);
	}

	value = VmxGetWriteControlValue(secValue, reg);
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, value);

	//设置异常拦截
	//int3
	ULONG64 exceptionBitmap = 1 << 3;
	__vmx_vmwrite(EXCEPTION_BITMAP, exceptionBitmap);
}

INT VmxInitVMCS(ULONG64 guestEsp, ULONG64 guestEip, ULONG64 hostEip)
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	//申请一块内存
	PHYSICAL_ADDRESS lowPhys = { 0 };
	PHYSICAL_ADDRESS higPhys = { 0 };
	lowPhys.QuadPart = 0;  //表示 0x0
	higPhys.QuadPart = -1; //-1表示0xFFFFFFFF`FFFFFFFF

	//申请非分页内存
	cpuPcb->vmcsAddr = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lowPhys, higPhys, lowPhys, MmCached);

	if (!cpuPcb->vmcsAddr)
	{
		//申请内存失败
		return -1;
	}

	//初始化，防止未挂上物理页
	memset(cpuPcb->vmcsAddr, 0, PAGE_SIZE);
	//获取物理地址
	cpuPcb->vmcsAddrPhy = MmGetPhysicalAddress(cpuPcb->vmcsAddr);

	cpuPcb->vmxHostStackTop = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE * 36, lowPhys, higPhys, lowPhys, MmCached);

	if (!cpuPcb->vmxHostStackTop)
	{
		//申请内存失败
		return -1;
	}

	memset(cpuPcb->vmxHostStackTop, 0, PAGE_SIZE * 36);
	cpuPcb->vmxHostStackBase = (ULONG64)cpuPcb->vmxHostStackTop + PAGE_SIZE * 36 - 0x200;


	//读 IA32_VMX_BASIC 寄存器，获取 VMCS_ID
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);

	//4字节，填充ID
	*(PULONG)(cpuPcb->vmcsAddr) = (ULONG)basic;

	//把状态清空
	__vmx_vmclear(&cpuPcb->vmcsAddrPhy.QuadPart);

	//加载vmcs结构
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

	//重置CR4的第14位
	ULONG64 cr4 = __readcr4();
	cr4 &= ~0x2000;
	__writecr4(cr4);
}

INT VmxInit(ULONG64 hostEip)
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	cpuPcb->cpuNumber = KeGetCurrentProcessorNumberEx(NULL);

	// call调用堆栈图
	//  xxxxx
	//  xxxxx
	//  提升堆栈
	//  xxxxx
	//  call下一行地址,返回地址 《=  ESP指向这里
	//  参数1
	//  参数2
	//  参数3

	//获取返回地址的地址，也就相当于是ESP，而ESP里的值，才是返回地址
	PULONG64 retAddr = (PULONG64)_AddressOfReturnAddress();
	//+1，64位相当于加8字节，指向参数1的位置，就是上一个函数的ESP
	ULONG64 guestEsp = retAddr + 1;
	ULONG64 guestEip = *retAddr;

	INT error = VmxInitVmON();

	//0正确，非0错误
	if (error)
	{
		Log("vmon初始化失败 error = %d cpunumber = %d", error, KeGetCurrentProcessorNumberEx(NULL));
		return error;
	}


	error = VmxInitVMCS(guestEsp, guestEip, hostEip);

	if (error)
	{
		Log("vmcs初始化失败 error = %d cpunumber = %d", error, KeGetCurrentProcessorNumberEx(NULL));

		__vmx_off();
		VmxDestory();
		return error;
	}

	//开启VT
	error = __vmx_vmlaunch();

	if (error)
	{
		Log("__vmx_vmlaunch失败 error = %d cpunumber = %d", error, KeGetCurrentProcessorNumberEx(NULL));

		__vmx_off();
		VmxDestory();
		return error;
	}

	return 0;
}



INT VmxInitVmON()
{
	PVMXCPUPCB cpuPcb = GetCurrentVMXCPUPCB();

	//申请一块内存
	PHYSICAL_ADDRESS lowPhys = { 0 };
	PHYSICAL_ADDRESS higPhys = { 0 };
	lowPhys.QuadPart = 0;  //表示 0x0
	higPhys.QuadPart = -1; //-1表示0xFFFFFFFF`FFFFFFFF

	//申请非分页内存
	cpuPcb->vmxonAddr = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, lowPhys, higPhys, lowPhys, MmCached);

	if (!cpuPcb->vmxonAddr)
	{
		//申请内存失败
		return -1;
	}

	//初始化，防止未挂上物理页
	memset(cpuPcb->vmxonAddr, 0, PAGE_SIZE);
	//获取物理地址
	cpuPcb->vmxonAddrPhy = MmGetPhysicalAddress(cpuPcb->vmxonAddr);

	//读 IA32_VMX_BASIC 寄存器，获取 VMCS_ID
	ULONG64 basic = __readmsr(IA32_VMX_BASIC);

	//4字节，填充ID
	*(PULONG)(cpuPcb->vmxonAddr) = (ULONG)basic;

	//初始化 CR0，CR4
	ULONG64 cr0Fixed0 = __readmsr(IA32_VMX_CR0_FIXED0);
	ULONG64 cr0Fixed1 = __readmsr(IA32_VMX_CR0_FIXED1);
	ULONG64 cr4Fixed0 = __readmsr(IA32_VMX_CR4_FIXED0);
	ULONG64 cr4Fixed1 = __readmsr(IA32_VMX_CR4_FIXED1);

	ULONG64 cr4 = __readcr4();
	ULONG64 cr0 = __readcr0();

	//先或 ，然后再 与
	cr4 |= cr4Fixed0;
	cr4 &= cr4Fixed1;

	cr0 |= cr0Fixed0;
	cr0 &= cr0Fixed1;

	//修改 CR0 , CR4
	__writecr0(cr0);

	__writecr4(cr4);

	//指向 64 位 4KB 对齐物理地址（指向 VMXON 区域）的指针。
	INT error = __vmx_on(&cpuPcb->vmxonAddrPhy.QuadPart);

	if (error)
	{
		//如果出错，释放内存，重置CR4
		cr4 &= ~cr4Fixed0; //对第14位VMXE取反
		__writecr4(cr4);

		//释放内存
		MmFreeContiguousMemorySpecifyCache(cpuPcb->vmxonAddr, PAGE_SIZE, MmCached);

		cpuPcb->vmxonAddr = NULL;
		cpuPcb->vmxonAddrPhy.QuadPart = 0;
	}

	return error;
}