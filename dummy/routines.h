#pragma once
#include "kernel_structs.h"

NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI VOID NTAPI RtlInitUnicodeString(_Out_ PUNICODE_STRING DestinationString, _In_opt_z_ __drv_aliasesMem PCWSTR SourceString);
NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

NTSTATUS KeReadProcessMemory(PEPROCESS SourceProcess, PEPROCESS TargetProcess, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)//SourceProcess - откуда читаем TargetProcess - куда читаем
{
	SIZE_T Result;

	return MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result);
}

NTSTATUS KeWriteProcessMemory(PEPROCESS SourceProcess, PEPROCESS TargetProcess, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)//SourceProcess - откуда пишем TargetProcess - куда пишем
{
	SIZE_T Result;

	return MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result);
}

PVOID GetModuleBaseAddr(PEPROCESS pProcess, IN PUNICODE_STRING pModuleName)
{
	PPEB peb = PsGetProcessPeb(pProcess);
	if (!peb || !peb->Ldr)
		return NULL;

	//only for x64 applications!
	for (PLIST_ENTRY pListEntry = peb->Ldr->InLoadOrderModuleList.Flink; pListEntry != &peb->Ldr->InLoadOrderModuleList; pListEntry = pListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&pEntry->BaseDllName, pModuleName, TRUE) == 0)
			return pEntry->DllBase;
	}
	return NULL;
}

VOID KernelSleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}