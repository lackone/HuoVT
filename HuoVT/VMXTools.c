#include "VMXTools.h"

/**
 * 检测BIOS是否开启VT
 */
BOOLEAN VmxChcekBIOS()
{
	ULONG64 msr = __readmsr(IA32_FEATURE_CONTROL);

	//判断第0位和第2位是否为1
	//Lock 位为1
	//VMX outside SMX 位为1
	return (msr & 0x5) == 0x5;
}

/**
 * 检测CPU是否支持VT
 */
BOOLEAN VmxChcekCPUID()
{
	int cpuidInfo[4] = { 0 };
	//主标志位 eax 设为 01h，查询 处理器信息和特性位
	//子标志位 为0，表示 不使用子标志位
	__cpuidex(cpuidInfo, 1, 0);

	//ECX 索引为2
	//第6位 VMX
	return (cpuidInfo[2] >> 5) & 1;
}

/**
 * 检则CR4是否启VT
 */
BOOLEAN VmxCheckCR4()
{
	ULONG64 cr4 = __readcr4();

	//第14位，VMXE，如果为1，说明VT已被开启，否则可以开启
	return ((cr4 >> 13) & 1) == 0;
}

/**
 * 获取写入的值
 */
ULONG64 VmxGetWriteControlValue(ULONG64 value, ULONG64 msr)
{
	LARGE_INTEGER msrVal = { 0 };
	msrVal.QuadPart = __readmsr(msr);
	//先或低位，再与上高位
	return (value | msrVal.LowPart) & msrVal.HighPart;
}

/**
 * 设置msr读位
 */
BOOLEAN VmxSetReadMsrBitmap(PUCHAR msrBitmap, ULONG64 msrIndex, BOOLEAN isEnable)
{
	//msrBitmap占4K
	//第1个1K，代表 0 - 0xFFF 范围内msr的读
	//第2个1K，代表 0xC0000000 - 0xC0000fff 范围内msr的读
	//第3个1K，代表 0 - 0xFFF 范围内msr的写
	//第4个1K，代表 0xC0000000 - 0xC0000fff 范围内msr的写
	if (msrIndex >= 0xC0000000)
	{
		msrBitmap += 1024;
		msrIndex -= 0xC0000000;
	}

	ULONG64 moveByte = 0;
	ULONG64 setBit = 0;

	if (msrIndex != 0)
	{
		moveByte = msrIndex / 8;
		setBit = msrIndex % 8;
		msrBitmap += moveByte;
	}

	if (isEnable)
	{
		*msrBitmap |= 1 << setBit;
	}
	else
	{
		*msrBitmap &= ~(1 << setBit);
	}

	return TRUE;
}

/**
 * 设置msr写位
 */
BOOLEAN VmxSetWriteMsrBitmap(PUCHAR msrBitmap, ULONG64 msrIndex, BOOLEAN isEnable)
{
	msrBitmap += 2048;

	return VmxSetReadMsrBitmap(msrBitmap, msrIndex, isEnable);
}

/**
 * 开启MTF
 */
VOID VmxEnableMTF(BOOLEAN isEnable)
{
	ULONG64 value = 0;
	__vmx_vmread(CPU_BASED_VM_EXEC_CONTROL, &value);

	if (isEnable)
	{
		value |= CPU_BASED_MONITOR_TRAP_FLAG;
	}
	else
	{
		value &= ~CPU_BASED_MONITOR_TRAP_FLAG;
	}

	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, value);
}