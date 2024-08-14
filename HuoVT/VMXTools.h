#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "VMXDefine.h"

/**
 * ��ӡ��־
 */
#define Log(Format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[HuoVT] " Format "\n", ##__VA_ARGS__)

 /**
  * ���BIOS�Ƿ���VT
  */
BOOLEAN VmxChcekBIOS();

/**
 * ���CPU�Ƿ�֧��VT
 */
BOOLEAN VmxChcekCPUID();

/**
 * ����CR4�Ƿ���VT
 */
BOOLEAN VmxCheckCR4();

/**
 * ��ȡд���ֵ
 */
ULONG64 VmxGetWriteControlValue(ULONG64 value, ULONG64 msr);

/**
 * ����msr��λ
 */
BOOLEAN VmxSetReadMsrBitmap(PUCHAR msrBitmap, ULONG64 msrIndex, BOOLEAN isEnable);

/**
 * ����msrдλ
 */
BOOLEAN VmxSetWriteMsrBitmap(PUCHAR msrBitmap, ULONG64 msrIndex, BOOLEAN isEnable);

/**
 * ����MTF
 */
VOID VmxEnableMTF(BOOLEAN isEnable);