//#include <ntddk.h>
#include <ntifs.h>
#include "other.h"
#include <intrin.h>
//#include <C:\\Program Files\\VMProtect Ultimatezz\\Include\\C\\VMProtectDDK.h>

//DRIVER_INITIALIZE DriverEntry;
//#pragma alloc_text(INIT, DriverEntry)
/*
ULONG64 GetNotifyVarAddress()
{
	ULONG64 i = 0;
	PULONG64 pAddrOfFnc = 0;
	UNICODE_STRING fncName;
	RtlInitUnicodeString(&fncName, L"PsSetLoadImageNotifyRoutine");
	ULONG64 fncAddr = (ULONG64)MmGetSystemRoutineAddress(&fncName);
	if (fncAddr)
	{
		fncAddr += 0x50;
		for (i = fncAddr; i < fncAddr + 0x15; i++)
		{
			if (*(UCHAR*)i == 0x8B && *(UCHAR*)(i + 1) == 0x05)//mov eax 8B 05
			{
				LONG OffsetAddr = 0;
				memcpy(&OffsetAddr, (UCHAR*)(i + 2), 4);

				pAddrOfFnc = (ULONG64*)(OffsetAddr + i + 0x6);
				break;
			}
		}
		return (ULONG64)pAddrOfFnc;
	}
	return 0;
}

#define SETBIT(X,Y)     X|=(1ULL<<(Y))
#define UNSETBIT(X,Y)   X&=(~(1ULL<<(Y)))

VOID CHANGE_NOTIFY_MASK(BOOLEAN enableThread, BOOLEAN enableImage)
{
	ULONG64 varaddress = GetNotifyVarAddress();
	if (varaddress)
	{
		ULONG val = *(ULONG*)(varaddress);
		if (!enableThread)
		{
			UNSETBIT(val, 3);
			UNSETBIT(val, 4);
		}
		else
		{
			SETBIT(val, 3);
			SETBIT(val, 4);
		}

		if (!enableImage)
		{
			UNSETBIT(val, 0);
		}
		else
		{
			SETBIT(val, 0);
		}

		*(ULONG*)(varaddress) = val;
	}
}*/
 
#define UnderProt


 

typedef NTSTATUS(__fastcall *MiProcessLoaderEntry)(PVOID pDriverSection, int bLoad);

MiProcessLoaderEntry g_pfnMiProcessLoaderEntry = NULL;

extern POBJECT_TYPE *IoSectionObjectType, *IoDeviceObjectType, *IoDriverObjectType;

BOOLEAN HideDriverWin7(PDRIVER_OBJECT pTargetDriverObject)
{
	UNICODE_STRING usFuncName = { 0 };
	PUCHAR pMiProcessLoaderEntry = NULL;
	size_t i = 0;



	PCWSTR Nm = L"EtwWriteString";//VMProtectDecryptStringW(L"EtwWriteString");
	RtlInitUnicodeString(&usFuncName, Nm);//

	pMiProcessLoaderEntry = (PUCHAR)MmGetSystemRoutineAddress(&usFuncName);

	//VMProtectFreeString(Nm);
	pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x600;

	__try {
		for (i = 0; i < 0x600; i++)
		{

			if (*pMiProcessLoaderEntry == 0xbb && *(pMiProcessLoaderEntry + 1) == 0x01 && *(pMiProcessLoaderEntry + 2) == 0x0 &&
				*(pMiProcessLoaderEntry + 5) == 0x48 && *(pMiProcessLoaderEntry + 0xc) == 0x8a && *(pMiProcessLoaderEntry + 0xd) == 0xd3
				&& *(pMiProcessLoaderEntry + 0xe) == 0xe8)
			{
				pMiProcessLoaderEntry = pMiProcessLoaderEntry - 0x40;
				for (i = 0; i < 0x30; i++)
				{
					if (*pMiProcessLoaderEntry == 0x90 && *(pMiProcessLoaderEntry + 1) == 0x48)
					{
						pMiProcessLoaderEntry++;
						goto MiProcessSuccess;
					}
					pMiProcessLoaderEntry++;
				}
				return FALSE;
			}
			pMiProcessLoaderEntry++;
		}
	}
	__except (1)
	{
		return FALSE;
	}

	return FALSE;
MiProcessSuccess:

	g_pfnMiProcessLoaderEntry = pMiProcessLoaderEntry;

	// DPRINT("0x%p\n", g_pfnMiProcessLoaderEntry);

 
	g_pfnMiProcessLoaderEntry(pTargetDriverObject->DriverSection, 0);

	 
	pTargetDriverObject->DriverSection = NULL;
	pTargetDriverObject->DriverStart = NULL;
	pTargetDriverObject->DriverSize = NULL;
	pTargetDriverObject->DriverUnload = NULL;
	pTargetDriverObject->DriverInit = NULL;
	pTargetDriverObject->DeviceObject = NULL;
	RtlFreeUnicodeString(&pTargetDriverObject->DriverName);
	pTargetDriverObject->Flags = 0;
	RtlFreeUnicodeString(&pTargetDriverObject->HardwareDatabase);

 
	RtlFreeUnicodeString(&pTargetDriverObject->DriverExtension->ServiceKeyName);
	for (int i = 0; i < 28; i++)
		pTargetDriverObject->MajorFunction[i] = NULL;
	pTargetDriverObject->Size = 0;
	pTargetDriverObject->Type = 0;
	return TRUE;
}
 

PEPROCESS TargetProcHandle;
DWORD64 UnityPlayerBaseAddr = 0;
BOOLEAN AllowMemOperation = FALSE;


typedef struct _GameData {
	DWORD32 TargetPID;
	DWORD32 MyPID; 
} GameData, *PGameData;




typedef struct _NON_PAGED_DEBUG_INFO
{
	USHORT      Signature;
	USHORT      Flags;
	ULONG       Size;
	USHORT      Machine;
	USHORT      Characteristics;
	ULONG       TimeDateStamp;
	ULONG       CheckSum;
	ULONG       SizeOfImage;
	ULONGLONG   ImageBase;
} NON_PAGED_DEBUG_INFO, *PNON_PAGED_DEBUG_INFO;
typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	PVOID ExceptionTable;
	ULONG ExceptionTableSize;
	// ULONG padding on IA64
	PVOID GpValue;
	PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT __Unused5;
	PVOID SectionPointer;
	ULONG CheckSum;
	// ULONG padding on IA64
	PVOID LoadedImports;
	PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

VOID HideFromKLDR(PVOID Module)
{
	PKLDR_DATA_TABLE_ENTRY PrevEntry, ModuleEntry, NextEntry;

	ModuleEntry = (PKLDR_DATA_TABLE_ENTRY)Module;

	PrevEntry = (PKLDR_DATA_TABLE_ENTRY)ModuleEntry->InLoadOrderLinks.Blink;
	NextEntry = (PKLDR_DATA_TABLE_ENTRY)ModuleEntry->InLoadOrderLinks.Flink;

	PrevEntry->InLoadOrderLinks.Flink = ModuleEntry->InLoadOrderLinks.Flink;
	NextEntry->InLoadOrderLinks.Blink = ModuleEntry->InLoadOrderLinks.Blink;

	ModuleEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)ModuleEntry;
	ModuleEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)ModuleEntry;
	
	ModuleEntry->BaseDllName.Buffer = NULL;
	ModuleEntry->BaseDllName.Length = 0;
	ModuleEntry->BaseDllName.MaximumLength = 0;

	ModuleEntry->FullDllName.Buffer = NULL;
	ModuleEntry->FullDllName.Length = 0;
	ModuleEntry->FullDllName.MaximumLength = 0;

	ModuleEntry->Flags |= 0x20;
	//RtlSecureZeroMemory(ModuleEntry, sizeof(PKLDR_DATA_TABLE_ENTRY));
}

PDRIVER_OBJECT g_pDriverObject = NULL;


NTSTATUS KeReadProcessMemory(PEPROCESS SourceProcess, PEPROCESS TargetProcess, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)//SourceProcess - откуда читаем TargetProcess - куда читаем
{
	SIZE_T Result;

	NTSTATUS status = MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result);
	return status;

}

NTSTATUS KeWriteProcessMemory(PEPROCESS SourceProcess, PEPROCESS TargetProcess, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)//SourceProcess - откуда пишем TargetProcess - куда пишем
{
	SIZE_T Result;

	NTSTATUS status = MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result);
	return status;

}


DWORD64 RegAddr[511];
INT Counter = 0;

VOID GetMemoryRegionList()
{
	PVOID Addr = NULL;
	MEMORY_BASIC_INFORMATION MemInfo = { 0 };
	SIZE_T RetVal = 0;
	INT tmpC = 0;



	for (Addr = MM_LOWEST_USER_ADDRESS; Addr < MM_HIGHEST_USER_ADDRESS; Addr = (void*)((DWORD64)(MemInfo.BaseAddress) + MemInfo.RegionSize))
	{
		NTSTATUS status = ZwQueryVirtualMemory(NtCurrentProcess(), Addr, MemoryBasicInformation, &MemInfo, sizeof(MemInfo), &RetVal);
		if (RetVal = 0) break;

		if (MemInfo.RegionSize == 65536 &&  MemInfo.Protect == PAGE_EXECUTE_READWRITE && MemInfo.State == MEM_COMMIT && MemInfo.Type == MEM_PRIVATE)
		{
			//DbgPrint("Address: %p\n", MemInfo.BaseAddress);
			RegAddr[tmpC] = MemInfo.BaseAddress;
			tmpC++;
			if (tmpC >= 510) break;
		}
	}

	Counter = tmpC;
}

#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)

VOID KernelSleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}


typedef struct _TalkStruct
{
	DWORD64 g_CiOptions;
	DWORD64 CommunicateBuffer;//
	DWORD32 Pid;
} TalkStruct, *PTaklStruct;

 
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned int        UINT;

typedef struct _CommandSpace
{
	BYTE Flag;
	DWORD32 PID;//PID
	/*
		0 - ничего не делаем
		1 - чтение
		2 - запись
		3 - получения базового адреса модуля
		4 - выход из цикла в драйвере
		5 - передача драйверу PID 
	*/
	PVOID Addr1; //при чтении: откуда читаем   при записи: куда пишем
	PVOID Addr2; //при чтении: куда читаем  при записи: откуда пишем
	DWORD32 Size;//размер чтения/записи
	DWORD64 Result;//результат(используется не всегда)
} CommandSpace, *PCommandSpace;


PTaklStruct TalkStructp;//получение основной информации
PCommandSpace CommandSpacep;//общение с приложением

PEPROCESS TargetProcess = NULL, HackProcess = NULL;

//цикл в ядре использую поток user-mode 
VOID Loop()
{
	INT log = 0;
	BOOLEAN ExitFromLoop = FALSE;
	LONG Interv = 2000;
	CommandSpacep = (PCommandSpace)(void*)TalkStructp->CommunicateBuffer;
	 
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TalkStructp->Pid, &HackProcess);
	if (NT_SUCCESS(status) == FALSE)
	{
		//DbgPrint("Error PsLookupProcessByProcessId: %lx with PID: %d\n", status, TalkStructp->Pid);
		return;
	}

	KAPC_STATE pc;
	KeStackAttachProcess(HackProcess, &pc);  
	while (TRUE)
	{
		switch (CommandSpacep->Flag)
		{
		case 1://1 - чтение
			if ((TargetProcess == NULL) || (HackProcess == NULL))
			{
				//DbgPrint("Can not read! TargetProcess: %p CurrentProcess: %p\n", TargetProcess, HackProcess);
				CommandSpacep->Flag = 0;
				CommandSpacep->Result = -1;
				break;
			}
			if (CommandSpacep->Size <= 0)
			{
				//DbgPrint("Can not read! Size: %d\n", CommandSpacep->Size);
				CommandSpacep->Flag = 0;
				CommandSpacep->Result = -1;
				break;
			}
			//CommandSpacep->Addr1 - откуда читаем - адрес в чужом приложении
			//CommandSpacep->Addr2 - куда читаем
			status = KeReadProcessMemory(TargetProcess, HackProcess, CommandSpacep->Addr1, CommandSpacep->Addr2, CommandSpacep->Size);
			CommandSpacep->Flag = 0;
			CommandSpacep->Result = NT_SUCCESS(status);
			break;
			 
		case 2://2 - запись
			if ((TargetProcess == NULL) || (HackProcess == NULL))
			{
				//DbgPrint("Can not read! TargetProcess: %p CurrentProcess: %p\n", TargetProcess, HackProcess);
				CommandSpacep->Flag = 0;
				CommandSpacep->Result = -1;
				break;
			}
			if (CommandSpacep->Size <= 0)
			{
				//DbgPrint("Can not read! Size: %d\n", CommandSpacep->Size);
				CommandSpacep->Flag = 0;
				CommandSpacep->Result = -1;
				break;
			}
			//CommandSpacep->Addr1 - откуда пишем - адрес в чужом приложении
			//CommandSpacep->Addr2 - куда пишем
			status = KeWriteProcessMemory(HackProcess, TargetProcess, CommandSpacep->Addr2, CommandSpacep->Addr1, CommandSpacep->Size);//Sourceprocess - откуда мы пишем, targetProc - куда пишем
			CommandSpacep->Flag = 0;
			CommandSpacep->Result = NT_SUCCESS(status);
			break;

		case 3://3 - получения базового адреса модуля
			UNICODE_STRING DllName;
			PCWSTR Nm = L"";//VMProtectDecryptStringW(L"UnityPlayer.dll");
			PVOID AddressOfModule = NULL;
			RtlInitUnicodeString(&DllName, Nm);//L"UnityPlayer.dll");
			//DbgPrint("Flag: 3!\n");

			KeUnstackDetachProcess(&pc);//отключаемся от нашего процесса

			KeStackAttachProcess(TargetProcess, &pc);//подключаемся к игровому процессу
				AddressOfModule = GetModuleBaseAddr(TargetProcess, &DllName);
				 
				//VMProtectFreeString(Nm); 
				//if (AddressOfModule != NULL) DbgPrint("AddressOfModule: %p\n", AddressOfModule);
			KeUnstackDetachProcess(&pc);

			///VMProtectFreeString(Nm);

			KeStackAttachProcess(HackProcess, &pc);//подключаемся к нашему процесса

			if (AddressOfModule != NULL) RtlCopyMemory(CommandSpacep->Addr1, &AddressOfModule, sizeof(DWORD64));

			Interv = 30;//меняем интервал чтобы быстро читать/писать
			CommandSpacep->Flag = 0;
			CommandSpacep->Result = AddressOfModule != NULL;
			break;

		case 4://4 - выход из цикла в драйвере
			//DbgPrint("Send Flag 4! Break cycle!");
			ExitFromLoop = TRUE;
			CommandSpacep->Flag = 0;
			CommandSpacep->Result = 1; 
			break;

		case 5://5 - передача драйверу PID
			if (CommandSpacep->PID > 0) status = PsLookupProcessByProcessId(CommandSpacep->PID, &TargetProcess);
			//DbgPrint("Send Flag 5! RustProcess: %p\n", TargetProcess);
			 
			CommandSpacep->Flag = 0;
			CommandSpacep->Result = NT_SUCCESS(status);
			break;

		case 6://получение регионов памяти
			KeUnstackDetachProcess(&pc);

			KeStackAttachProcess(TargetProcess, &pc);
				GetMemoryRegionList();//заполняет RegAddr адресами регионов 
			KeUnstackDetachProcess(&pc);
			
			KeStackAttachProcess(HackProcess, &pc);
			//DbgPrint("Address for memReg: %p\n", CommandSpacep->Addr1);
			 
			if (CommandSpacep->Addr1 > MM_LOWEST_USER_ADDRESS && CommandSpacep->Addr1 <  MM_HIGHEST_USER_ADDRESS) 
				RtlCopyMemory(CommandSpacep->Addr1, &RegAddr, sizeof(RegAddr));
			
			 
			CommandSpacep->Size = Counter;
			CommandSpacep->Flag = 0;
			CommandSpacep->Result = 0;
			
			//DbgPrint("Flag are nulled!\n");
			break;
		case 7:
			Interv = CommandSpacep->Size;
			//DbgPrint("Change interval!\n");
			CommandSpacep->Flag = 0;
			CommandSpacep->Result = 0;
			break;

		case 8:
			PEPROCESS targetProc = NULL;

			if (CommandSpacep->PID > 0) status = PsLookupProcessByProcessId(CommandSpacep->PID, &targetProc);
			if (NT_SUCCESS(status)) {
				PPEB peb = PsGetProcessPeb(targetProc);
				if (peb) 
					CommandSpacep->Addr1 = peb;
				
				ObDereferenceObject(targetProc);
			}
			CommandSpacep->Flag = 0;
			CommandSpacep->Result = NT_SUCCESS(status);
			break;

		default:
			KernelSleep(Interv);
			break;
		}

		if (ExitFromLoop == TRUE) break;
	}
 
	KeUnstackDetachProcess(&pc);
	if (TargetProcess != NULL) ObDereferenceObject(TargetProcess);
	if (HackProcess != NULL) ObDereferenceObject(HackProcess);
}

BYTE TmpStorage[sizeof(TalkStruct)];


VOID GetInformationFromFileMap()
{
	NTSTATUS status;
	UNICODE_STRING usSectionName;
	OBJECT_ATTRIBUTES objAttributes;
	SIZE_T viewSize = PAGE_SIZE;
		
	PCWSTR Nm = L"";//VMProtectDecryptStringW(L"\\BaseNamedObjects\\ASDFGHJKL");//PCWSTR Nm = L"\\BaseNamedObjects\\ASDFGHJKL";
	RtlInitUnicodeString(&usSectionName, Nm);				 
	InitializeObjectAttributes(&objAttributes, &usSectionName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0);
	HANDLE m_SectionHandle = 0;
	DWORD64* m_pAddrMap = NULL;

	status = ZwOpenSection(&m_SectionHandle, GENERIC_READ | GENERIC_WRITE, &objAttributes);
//	VMProtectFreeString(Nm);
	 
	if (NT_SUCCESS(status))
	{
		status = ZwMapViewOfSection(m_SectionHandle, NtCurrentProcess(), &m_pAddrMap, 0L, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
		if (NT_SUCCESS(status))
		{

			memcpy(&TmpStorage, m_pAddrMap, sizeof(TalkStruct));

			TalkStructp = (PTaklStruct)&TmpStorage;

			//DbgPrint("g_CiOptions: %p ComBufer: %p\n", TalkStructp->g_CiOptions, TalkStructp->CommunicateBuffer);

			DWORD64* g_CiOptions = (void*)TalkStructp->g_CiOptions;

			//если g_CiOptions содержит 0x8(testsigning) то  temp = true
			BOOLEAN isUnderTestSign = (*g_CiOptions & 0x8) != 0;//Eh - 14d => 0x8(testsigning) + 0x6(standard mode)
			if (isUnderTestSign) //если есть тестовый режим - удаляем
				*g_CiOptions -= 0x8;

			BOOLEAN isUnderNormalMode = (*g_CiOptions & 0x6) != 0;//проверим, есть ли нормальный режим
			if (isUnderNormalMode == FALSE)//если нормального режима нету - устанавливаем
				*g_CiOptions += 0x6;

			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "g_CiOptions: %x isUnderTestSign: %d isUnderNormalMode: %d\n", *g_CiOptions, isUnderTestSign, isUnderNormalMode);
			//if (*g_CiOptions == 0xE) *g_CiOptions = 0x6;
			//DbgPrint("ValueNow: %d\n", *g_CiOptions);

			*m_pAddrMap = 0xCC;//сигнализируем успех
			

			ZwUnmapViewOfSection(NtCurrentProcess(), m_pAddrMap);
			m_pAddrMap = NULL;
			ZwClose(m_SectionHandle);

			//if (VMProtectIsDebuggerPresent(TRUE) == FALSE) Loop();
			
		}
		else
		{
			//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "1 %lx\n", status);
			ZwClose(m_SectionHandle);
		}
	}
	//else
		//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "2 %lx\n", status);
}


DWORD64 CPUID = 0x6535FF6535FF11;
 

INT64 sMOVVEudbE;
BOOLEAN GetCPUInfo()
{
	int trg[5] = { 0, 2, 0x80000002, 0x80000003, 0x80000004 };
	DWORD32 Res[5];

	int regs[4];

	for (int i = 0; i < 5; i++)
	{
		__cpuid(regs, trg[i]);
		Res[i] = regs[0] + regs[1] + regs[2] + regs[3];
	}

	DWORD64 Result = Res[0] + Res[1] + Res[2] + Res[3] + Res[4];
	//DbgPrint("getCPUID: %x CPUID: %x\n", Result, CPUID);
	return (Result + Result) == CPUID;
}


INT64 OfsAEwoxIt = 0;
VOID Reinitialize(_In_ PDRIVER_OBJECT pDriverObject, _In_opt_ PVOID Context, _In_ ULONG Count)
{
	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Reinitialize:CPU Good %s\n", "world");
	ObMakeTemporaryObject(g_pDriverObject);


	ObDereferenceObject(g_pDriverObject);


	if (GetCPUInfo())
	{
		HideDriverWin7(pDriverObject);
		GetInformationFromFileMap();
	}

	//DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Reinitialize!\n", "");
}


/*
typedef unsigned long long uint64_t;

typedef struct _OBJECT_HEADER
{
	LONG	PointerCount;
	union
	{
		LONG	HandleCount;
		PVOID	NextToFree;
	};
	uint64_t	Lock;
	UCHAR		TypeIndex;
	union
	{
		UCHAR	TraceFlags;
		struct
		{
			UCHAR	DbgRefTrace : 1;
			UCHAR	DbgTracePermanent : 1;
			UCHAR	Reserved : 6;
		};
	};
	UCHAR	InfoMask;
	union
	{
		UCHAR	Flags;
		struct
		{
			UCHAR	NewObject : 1;
			UCHAR	KernelObject : 1;
			UCHAR	KernelOnlyAccess : 1;
			UCHAR	ExclusiveObject : 1;
			UCHAR	PermanentObject : 1;
			UCHAR	DefaultSecurityQuota : 1;
			UCHAR	SingleHandleEntry : 1;
			UCHAR	DeletedInline : 1;
		};
	};
	union
	{
		PVOID	ObjectCreateInfo;
		PVOID	QuotaBlockCharged;
	};
	PVOID	SecurityDescriptor;
	PVOID	Body;
} OBJECT_HEADER, *POBJECT_HEADER;


VOID OpenPhysicalMemory()
{
	UNICODE_STRING		physmemString;
	OBJECT_ATTRIBUTES	attributes;
	WCHAR				physmemName[] = L"\\Device\\PhysicalMemory";
	NTSTATUS			status;
	HANDLE				physmem = 0;

	PVOID pSecObj = NULL;
	RtlInitUnicodeString(&physmemString, physmemName);

	InitializeObjectAttributes(&attributes, &physmemString, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenSection(&physmem, SECTION_ALL_ACCESS, &attributes);
	DbgPrint("ZwOpenSection: %x PhysMemHandle: %x\n", status, physmem);

	if (NT_SUCCESS(status))
	{
		PPHYSICAL_MEMORY_RANGE physicalMemoryRanges = MmGetPhysicalMemoryRanges();
		DWORD64 SzByte = 0;
		for (INT i = 0; (physicalMemoryRanges[i].BaseAddress.QuadPart) || (physicalMemoryRanges[i].NumberOfBytes.QuadPart); i++)
		{
			DbgPrint("Address: %p NumOfByte: %d\n", physicalMemoryRanges[i].BaseAddress.QuadPart, physicalMemoryRanges[i].NumberOfBytes.QuadPart);
			if (i > 0) SzByte = SzByte + physicalMemoryRanges[i].NumberOfBytes.QuadPart;
		}
		

		
		/*for (SIZE_T i = 0;; i++)
		{
			PPHYSICAL_MEMORY_RANGE physicalMemoryRange = &physicalMemoryRanges[i];

			if (physicalMemoryRange->BaseAddress.QuadPart == 0 && physicalMemoryRange->NumberOfBytes.QuadPart == 0)
			{
				break;
			}

			 physicalMemoryRange->BaseAddress.QuadPart + physicalMemoryRange->NumberOfBytes.QuadPart;
		}*/



		/*status = ObReferenceObjectByHandle(physmem, 0xF001Fu, 0i64, 0, &pSecObj, 0i64);
		DbgPrint("ObReferenceObjectByHandle: %x Object: %p\n", status, pSecObj);

		if (NT_SUCCESS(status))
		{
			POBJECT_HEADER PhysMemObject = (POBJECT_HEADER)((DWORD64)pSecObj - 0x30);
			DbgPrint("Flags: %d KernelObject: %d KernelOnlyAccess: %d\n", PhysMemObject->Flags, PhysMemObject->KernelObject, PhysMemObject->KernelOnlyAccess);
			PhysMemObject->KernelObject = 0;
			PhysMemObject->KernelOnlyAccess = 0;

			ObDereferenceObject(pSecObj);
		}*/
			
	//}

	//ZwClose(physmem);
//}


NTSTATUS DriverEntry(_In_  struct _DRIVER_OBJECT *DriverObject,  _In_  PUNICODE_STRING RegistryPath)
{

	RegistryPath = NULL;
	
	HideFromLDR(DriverObject->DriverSection);
	HideFromKLDR(DriverObject->DriverSection);
	
	g_pDriverObject = DriverObject;
	IoRegisterDriverReinitialization(DriverObject, Reinitialize, NULL);
	DbgPrint("DriverEntry: hello!\n");
	 
	return STATUS_SUCCESS;
}