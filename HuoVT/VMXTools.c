#include "VMXTools.h"

/**
 * ���BIOS�Ƿ���VT
 */
BOOLEAN VmxChcekBIOS()
{
	ULONG64 msr = __readmsr(IA32_FEATURE_CONTROL);

	//�жϵ�0λ�͵�2λ�Ƿ�Ϊ1
	//Lock λΪ1
	//VMX outside SMX λΪ1
	return (msr & 0x5) == 0x5;
}

/**
 * ���CPU�Ƿ�֧��VT
 */
BOOLEAN VmxChcekCPUID()
{
	int cpuidInfo[4] = { 0 };
	//����־λ eax ��Ϊ 01h����ѯ ��������Ϣ������λ
	//�ӱ�־λ Ϊ0����ʾ ��ʹ���ӱ�־λ
	__cpuidex(cpuidInfo, 1, 0);

	//ECX ����Ϊ2
	//��6λ VMX
	return (cpuidInfo[2] >> 5) & 1;
}

/**
 * ����CR4�Ƿ���VT
 */
BOOLEAN VmxCheckCR4()
{
	ULONG64 cr4 = __readcr4();

	//��14λ��VMXE�����Ϊ1��˵��VT�ѱ�������������Կ���
	return ((cr4 >> 13) & 1) == 0;
}

/**
 * ��ȡд���ֵ
 */
ULONG64 VmxGetWriteControlValue(ULONG64 value, ULONG64 msr)
{
	LARGE_INTEGER msrVal = { 0 };
	msrVal.QuadPart = __readmsr(msr);
	//�Ȼ��λ�������ϸ�λ
	return (value | msrVal.LowPart) & msrVal.HighPart;
}

/**
 * ����msr��λ
 */
BOOLEAN VmxSetReadMsrBitmap(PUCHAR msrBitmap, ULONG64 msrIndex, BOOLEAN isEnable)
{
	//msrBitmapռ4K
	//��1��1K������ 0 - 0xFFF ��Χ��msr�Ķ�
	//��2��1K������ 0xC0000000 - 0xC0000fff ��Χ��msr�Ķ�
	//��3��1K������ 0 - 0xFFF ��Χ��msr��д
	//��4��1K������ 0xC0000000 - 0xC0000fff ��Χ��msr��д
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
 * ����msrдλ
 */
BOOLEAN VmxSetWriteMsrBitmap(PUCHAR msrBitmap, ULONG64 msrIndex, BOOLEAN isEnable)
{
	msrBitmap += 2048;

	return VmxSetReadMsrBitmap(msrBitmap, msrIndex, isEnable);
}

/**
 * ����MTF
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