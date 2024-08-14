#pragma once
#include <ntifs.h>
#include "VMXHandler.h"

#define EPML4_INDEX(__ADDRESS__)		((__ADDRESS__ >> 39) & 0x1FF)
#define EPDPTE_INDEX(__ADDRESS__)		((__ADDRESS__ >> 30) & 0x1FF)
#define EPDE_INDEX(__ADDRESS__)			((__ADDRESS__ >> 21) & 0x1FF)
#define EPTE_INDEX(__ADDRESS__)			((__ADDRESS__ >> 12) & 0x1FF)

#define PML4E_ENTRY_COUNT 512
#define PDPTE_ENTRY_COUNT 512
#define PDE_ENTRY_COUNT   512
#define PTE_ENTRY_COUNT   512

typedef union _EPML4E
{
	struct
	{
		ULONG64 ReadAccess : 1;
		ULONG64 WriteAccess : 1;
		ULONG64 ExecuteAccess : 1;
		ULONG64 Reserved1 : 5;
		ULONG64 Accessed : 1;
		ULONG64 Reserved2 : 1;
		ULONG64 UserModeExecute : 1;
		ULONG64 Reserved3 : 1;
		ULONG64 PageFrameNumber : 36;
		ULONG64 Reserved4 : 16;
	};

	ULONG64 Flags;
} EPML4E, * PEPML4E;

typedef union _EPDPTE_1GB
{
	struct
	{
		ULONG64 ReadAccess : 1;
		ULONG64 WriteAccess : 1;
		ULONG64 ExecuteAccess : 1;
		ULONG64 MemoryType : 3;
		ULONG64 IgnorePat : 1;
		ULONG64 LargePage : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 UserModeExecute : 1;
		ULONG64 Reserved1 : 19;
		ULONG64 PageFrameNumber : 18;
		ULONG64 Reserved2 : 15;
		ULONG64 SuppressVe : 1;
	};

	ULONG64 Flags;
} EPDPTE_1GB, * PEPDPTE_1GB;

typedef union _EPDPTE
{
	struct
	{
		ULONG64 ReadAccess : 1;
		ULONG64 WriteAccess : 1;
		ULONG64 ExecuteAccess : 1;
		ULONG64 Reserved1 : 5;
		ULONG64 Accessed : 1;
		ULONG64 Reserved2 : 1;
		ULONG64 UserModeExecute : 1;
		ULONG64 Reserved3 : 1;
		ULONG64 PageFrameNumber : 36;
		ULONG64 Reserved4 : 16;
	};

	ULONG64 Flags;
} EPDPTE, * PEPDPTE;

typedef union _EPDE_2MB
{
	struct
	{
		ULONG64 ReadAccess : 1;
		ULONG64 WriteAccess : 1;
		ULONG64 ExecuteAccess : 1;
		ULONG64 MemoryType : 3;
		ULONG64 IgnorePat : 1;
		ULONG64 LargePage : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 UserModeExecute : 1;
		ULONG64 Reserved1 : 10;
		ULONG64 PageFrameNumber : 27;
		ULONG64 Reserved2 : 15;
		ULONG64 SuppressVe : 1;
	};

	ULONG64 Flags;
} EPDE_2MB, * PEPDE_2MB;

typedef union _EPDE
{
	struct
	{
		ULONG64 ReadAccess : 1;
		ULONG64 WriteAccess : 1;
		ULONG64 ExecuteAccess : 1;
		ULONG64 Reserved1 : 5;
		ULONG64 Accessed : 1;
		ULONG64 Reserved2 : 1;
		ULONG64 UserModeExecute : 1;
		ULONG64 Reserved3 : 1;
		ULONG64 PageFrameNumber : 36;
		ULONG64 Reserved4 : 16;
	};

	ULONG64 Flags;
} EPDE, * PEPDE;

typedef union _EPTE
{
	struct
	{

		ULONG64 ReadAccess : 1;
		ULONG64 WriteAccess : 1;
		ULONG64 ExecuteAccess : 1;
		ULONG64 MemoryType : 3;
		ULONG64 IgnorePat : 1;
		ULONG64 Reserved1 : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 UserModeExecute : 1;
		ULONG64 Reserved2 : 1;
		ULONG64 PageFrameNumber : 36;
		ULONG64 Reserved3 : 15;
		ULONG64 SuppressVe : 1;
	};

	ULONG64 Flags;
} EPTE, * PEPTE;


typedef union _VMX_EPTP
{
	struct
	{
		ULONG64 MemoryType : 3;
		ULONG64 PageWalkLength : 3;
		ULONG64 EnableAccessAndDirtyFlags : 1;
		ULONG64 Reserved1 : 5;
		ULONG64 PageFrameNumber : 36;
		ULONG64 Reserved2 : 16;
	};

	ULONG64 Flags;
} VMX_EPTP, * VMX_PEPTP;


typedef struct _VMX_MAMAGER_PAGE_ENTRY
{
	EPML4E pmlt[PML4E_ENTRY_COUNT];
	EPDPTE pdptt[PDPTE_ENTRY_COUNT];
	EPDE_2MB pdt[PDE_ENTRY_COUNT][PTE_ENTRY_COUNT];

} VMX_MAMAGER_PAGE_ENTRY, * PVMX_MAMAGER_PAGE_ENTRY;


BOOLEAN VmxInitEPT();

VOID VmxEptHandler(PGuestContext context);

PEPDE_2MB GetPDE2MHpaByGpa(ULONG64 gpa);

PEPTE EptGetPte(ULONG64 PfNumber);