#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "VMXDefine.h"

/**
 * 打印日志
 */
#define Log(Format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[HuoVT] " Format "\n", ##__VA_ARGS__)

 /**
  * 检测BIOS是否开启VT
  */
BOOLEAN VmxChcekBIOS();

/**
 * 检测CPU是否支持VT
 */
BOOLEAN VmxChcekCPUID();

/**
 * 检则CR4是否启VT
 */
BOOLEAN VmxCheckCR4();

/**
 * 获取写入的值
 */
ULONG64 VmxGetWriteControlValue(ULONG64 value, ULONG64 msr);

/**
 * 设置msr读位
 */
BOOLEAN VmxSetReadMsrBitmap(PUCHAR msrBitmap, ULONG64 msrIndex, BOOLEAN isEnable);

/**
 * 设置msr写位
 */
BOOLEAN VmxSetWriteMsrBitmap(PUCHAR msrBitmap, ULONG64 msrIndex, BOOLEAN isEnable);

/**
 * 开启MTF
 */
VOID VmxEnableMTF(BOOLEAN isEnable);