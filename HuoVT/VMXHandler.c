#include "VMXHandler.h"
#include <intrin.h>
#include "VMXDefine.h"
#include "VMXTools.h"
#include "VMXAsm.h"
#include "VMXEpt.h"
#include "VMXEptHook.h"

#define MAKE_REG(XXX1,XXX2) ((XXX1 & 0xFFFFFFFF) | (XXX2<<32))

VOID VmxCpuidHandler(PGuestContext context)
{
	if (context->mRax == 0x8888)
	{
		context->mRax = 0x11111111;
		context->mRbx = 0x22222222;
		context->mRcx = 0x33333333;
		context->mRdx = 0x44444444;

		//VmxEnableMTF(TRUE);

		/*
		//注入指令前事件
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
		VMXExitIntEvent VmEvent = { 0 };
		VmEvent.vaild = 1; //有效
		VmEvent.type = 7;
		VmEvent.vector = 0;
		__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, *(PULONG64)&VmEvent);
		__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, 0);
		*/
	}
	else if (context->mRax == 1)
	{
		int cpuids[4] = { 0 };
		__cpuidex(cpuids, context->mRax, context->mRcx);

		context->mRax = cpuids[0];
		context->mRbx = cpuids[1];
		//隐藏CPUID，开启VT
		context->mRcx = cpuids[2] & (~0x20);
		context->mRdx = cpuids[3];
	}
	else
	{
		int cpuids[4] = { 0 };
		__cpuidex(cpuids, context->mRax, context->mRcx);

		context->mRax = cpuids[0];
		context->mRbx = cpuids[1];
		context->mRcx = cpuids[2];
		context->mRdx = cpuids[3];
	}
}

VOID VmxMsrReadHandler(PGuestContext context)
{
	if (context->mRcx == 0xC0000082)
	{
		ULONG64 value = __readmsr(context->mRcx);
		context->mRax = value & 0xFFFFFFFF;
		context->mRdx = (value >> 32) & 0xFFFFFFFF;
	}
	else
	{
		ULONG64 value = __readmsr(context->mRcx);

		if (context->mRcx == IA32_FEATURE_CONTROL)
		{
			//把后3位去掉，让读此寄存器的认为BIOS不支持VT
			value &= ~7; 
		}

		context->mRax = value & 0xFFFFFFFF;
		context->mRdx = (value >> 32) & 0xFFFFFFFF;
	}
}

VOID VmxMsrWriteHandler(PGuestContext context)
{
	if (context->mRcx == 0xC0000082)
	{
		ULONG64 value = MAKE_REG(context->mRax, context->mRdx);
		__writemsr(context->mRcx, value);
	}
	else
	{
		ULONG64 value = MAKE_REG(context->mRax, context->mRdx);

		if (context->mRcx == IA32_FEATURE_CONTROL)
		{
			//不让写，啥也不干
		}
		else
		{
			__writemsr(context->mRcx, value);
		}
	}
}

VOID VmxINVPCIDHandler(PGuestContext context)
{
	ULONG64 instInfo = 0; //指令详情
	ULONG64 qualInfo = 0;
	ULONG64 rsp = 0;

	__vmx_vmread(VMX_INSTRUCTION_INFO, &instInfo);
	__vmx_vmread(EXIT_QUALIFICATION, &qualInfo);
	__vmx_vmread(GUEST_RSP, &rsp);

	PINVPCID pinfo = (PINVPCID)&instInfo;

	ULONG64 base = 0;
	ULONG64 index = 0;
	ULONG64 scale = pinfo->scale ? 2 ^ pinfo->scale : 0;
	ULONG64 addr = 0;
	ULONG64 regopt = ((PULONG64)context)[pinfo->regOpt];

	// INVPCID rax, [fs : rbx + rsi * 8 + 0Ch]
	//判断base是否有效
	if (!pinfo->baseInvaild)
	{
		if (pinfo->base == 4)
		{
			base = rsp;
		}
		else
		{
			base = ((PULONG64)context)[pinfo->base];
		}
	}

	if (!pinfo->indexInvaild)
	{
		if (pinfo->index == 4)
		{
			index = rsp;
		}
		else
		{
			index = ((PULONG64)context)[pinfo->index];
		}
	}

	if (pinfo->addrssSize == 0)
	{
		addr = *(PSHORT)(base + index * scale + qualInfo);
	}
	else if (pinfo->addrssSize == 1)
	{
		addr = *(PULONG)(base + index * scale + qualInfo);
	}
	else
	{
		addr = *(PULONG64)(base + index * scale + qualInfo);
	}

	_invpcid(regopt, &addr);
}

VOID VmxExceptionHandler(PGuestContext context)
{
	//获取中断信息
	VMXExitIntEvent vmEvent = { 0 };

	ULONG64 instLen = 0;
	ULONG64 rip = 0;
	ULONG64 rsp = 0;
	ULONG64 errorcode = 0;

	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instLen); // 获取指令长度
	__vmx_vmread(GUEST_RIP, &rip); //获取客户机触发VT事件的地址
	__vmx_vmread(GUEST_RSP, &rsp);
	__vmx_vmread(VM_EXIT_INTR_INFO, &vmEvent); //中断详情
	__vmx_vmread(VM_EXIT_INTR_ERROR_CODE, &errorcode); //指令错误

	if (!vmEvent.vaild)
	{
		__vmx_vmwrite(GUEST_RIP, rip + instLen);
		__vmx_vmwrite(GUEST_RSP, rsp);
		return;
	}

	if (vmEvent.errorCode)
	{
		__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, errorcode);
	}

	switch (vmEvent.type)
	{
	case EXCEPTION_W_INT:
		break;
	case EXCEPTION_NMI_INT:
		break;
	case EXCEPTION_HARDWARE:
		break;
	case EXCEPTION_SOFT:
	{
		if (vmEvent.vector == 3)
		{
			Log("interput int 3");

			//如果是int 3
			__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, *(PULONG64)&vmEvent);
			__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, instLen);

			instLen = 0;
		}
	}
	break;
	}

	__vmx_vmwrite(GUEST_RIP, rip + instLen);
	__vmx_vmwrite(GUEST_RSP, rsp);
}

VOID VmxMTFHandler(PGuestContext context)
{
	ULONG64 reason = 0; //指令原因
	ULONG64 instLen = 0; //指令长度
	ULONG64 instInfo = 0; //指令详情
	ULONG64 rip = 0;
	ULONG64 rsp = 0;

	__vmx_vmread(VM_EXIT_REASON, &reason);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instLen);
	__vmx_vmread(VMX_INSTRUCTION_INFO, &instInfo);
	__vmx_vmread(GUEST_RIP, &rip); //获取客户机触发VT事件的地址
	__vmx_vmread(GUEST_RSP, &rsp);

	DbgBreakPoint();

	VmxEnableMTF(FALSE);
}

VOID VmxCRHandler(PGuestContext context)
{
	struct
	{
		ULONG64 crn : 4;
		ULONG64 accessType : 2;
		ULONG64 LMSWOp : 1;
		ULONG64 rv1 : 1;
		ULONG64 gpr : 4;
		ULONG64 rv2 : 4;
		ULONG64 LMSWSrc : 16;
		ULONG64 rv3 : 32;
	} CRInfo;

	ULONG64 rip = 0;
	ULONG64 rsp = 0;
	ULONG64 qualInfo = 0;
	ULONG64 instLen = 0;

	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instLen);
	__vmx_vmread(GUEST_RIP, &rip);
	__vmx_vmread(GUEST_RSP, &rsp);
	__vmx_vmread(EXIT_QUALIFICATION, &CRInfo);

	if (CRInfo.accessType == 0)
	{
		if (CRInfo.crn == 3)
		{
			ULONG64 cr3 = 0;
			//mov cr3, rax
			if (CRInfo.gpr == 4)
			{
				cr3 = rsp;
			}
			else
			{
				cr3 = ((PULONG64)context)[CRInfo.gpr];
			}

			__vmx_vmwrite(GUEST_CR3, cr3);
		}
	}
	else if (CRInfo.accessType == 1)
	{
		if (CRInfo.crn == 3)
		{
			ULONG64 cr3 = 0;
			__vmx_vmread(GUEST_CR3, &cr3);

			//mov rax, cr3
			if (CRInfo.gpr == 4)
			{
				rsp = cr3;
			}
			else
			{
				((PULONG64)context)[CRInfo.gpr] = cr3;
			}
		}
	}

	__vmx_vmwrite(GUEST_RIP, rip + instLen);
	__vmx_vmwrite(GUEST_RSP, rsp);
}

VOID InjectExceptionEvent(ULONG64 type, ULONG64 vector)
{
	//注入指令前事件
	__vmx_vmwrite(VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
	VMXExitIntEvent VmEvent = { 0 };
	VmEvent.vaild = 1;
	VmEvent.type = type;
	VmEvent.vector = vector;
	__vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, *(PULONG64)&VmEvent);
	__vmx_vmwrite(VM_ENTRY_INSTRUCTION_LEN, 0);
}

EXTERN_C VOID VmxExitHandler(PGuestContext context)
{
	ULONG64 reason = 0; //指令原因
	ULONG64 instLen = 0; //指令长度
	ULONG64 instInfo = 0; //指令详情
	ULONG64 rip = 0;
	ULONG64 rsp = 0;

	__vmx_vmread(VM_EXIT_REASON, &reason);

	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instLen);

	__vmx_vmread(VMX_INSTRUCTION_INFO, &instInfo);

	__vmx_vmread(GUEST_RIP, &rip); //获取客户机触发VT事件的地址
	__vmx_vmread(GUEST_RSP, &rsp);

	//只拿16位，获取事件码
	reason = reason & 0xFFFF;

	switch (reason)
	{
	case EXIT_REASON_EPT_VIOLATION:
	{
		VmxEptHandler(context);
		return;
	}
	break;
	case EXIT_REASON_EPT_CONFIG:
	{
		DbgBreakPoint();
		Log("EPT_CONFIG reason = %x rip = %llx", reason, rip);
	}
	break;
	case EXIT_REASON_CR_ACCESS:;
	{
		VmxCRHandler(context);
		return;
	}
	break;
	case EXIT_REASON_MTF:
	{
		VmxMTFHandler(context);
		return;
	}
	break;
	case EXIT_REASON_EXCEPTION_NMI:
	{
		VmxExceptionHandler(context);
		//这里不能break
		return;
	}
	break;
	case EXIT_REASON_CPUID:
	{
		VmxCpuidHandler(context);
	}
	break;
	case EXIT_REASON_GETSEC:
	{
		DbgBreakPoint();
		Log("GETSEC reason = %x rip = %llx", reason, rip);
	}
	break;
	case EXIT_REASON_INVD:
	{
		AsmInvd();
	}
	break;
	case EXIT_REASON_RDTSCP:
	{
		ULONG in = 0;
		LARGE_INTEGER value = { 0 };
		value.QuadPart = __rdtscp(&in);
		context->mRax = value.LowPart;
		context->mRdx = value.HighPart;
		context->mRcx = in;
	}
	break;
	case EXIT_REASON_INVPCID:
	{
		//_invpcid(context->mRcx, context->mRdx);
		VmxINVPCIDHandler(context);
	}
	break;
	case EXIT_REASON_XSETBV:
	{
		ULONG64 value = MAKE_REG(context->mRax, context->mRdx);
		_xsetbv(context->mRcx, value);
	}
	break;
	case EXIT_REASON_MSR_READ:
	{
		VmxMsrReadHandler(context);
	}
	break;
	case EXIT_REASON_MSR_WRITE:
	{
		VmxMsrWriteHandler(context);
	}
	break;
	case EXIT_REASON_TRIPLE_FAULT:
	{
		DbgBreakPoint();
		Log("TRIPLE_FAULT reason = %x rip = %llx", reason, rip);
	}
	break;
	case EXIT_REASON_VMCALL:
	{
		if (context->mRax == 'byte')
		{
			__vmx_off();
			AsmJmpRet(rip + instLen, rsp);
			return;
		}
		else if (context->mRax == __EPT_PAGE_HOOK)
		{
			EptHookHandler(context->mRcx, context->mRdx, context->mR8, context->mR9);
		}
		else
		{
			ULONG64 rflags = 0;
			__vmx_vmread(GUEST_RFLAGS, &rflags);
			// ZF 和 CF 位置 1
			rflags |= 0x41;
			//如果是上面VM指令引起的EXIT，直接返回错误
			__vmx_vmwrite(GUEST_RFLAGS, rflags);
		}
	}
	break;
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	{
		ULONG64 rflags = 0;
		__vmx_vmread(GUEST_RFLAGS, &rflags);
		// ZF 和 CF 位置 1
		rflags |= 0x41;
		//如果是上面VM指令引起的EXIT，直接返回错误
		__vmx_vmwrite(GUEST_RFLAGS, rflags);
	}
	break;
	default:
		break;
	}

	ULONG64 rf = 0;
	__vmx_vmread(GUEST_RFLAGS, &rf);
	//判断是否是单步
	if ((rf & 0x100) == 0x100)
	{
		//注入一个硬件调试中断
		//3硬件异常
		InjectExceptionEvent(3, 1);

		ULONG64 info = 0;
		__vmx_vmread(GUEST_INTERRUPTIBILITY_INFO, &info);
		//把 blocking by MOV-SS 置0
		info &= ~2;
		__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, info);
	}

	__vmx_vmwrite(GUEST_RIP, rip + instLen);
	__vmx_vmwrite(GUEST_RSP, rsp);
}