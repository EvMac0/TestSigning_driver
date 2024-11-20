#include <ntifs.h>
#include <intrin.h>
#include "kernel_structs.h"
#include "routines.h"
#include "talk_structs.h"

PEPROCESS TargetProcHandle;
DWORD64 UnityPlayerBaseAddr = 0;
BOOLEAN AllowMemOperation = FALSE;


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
		if (RetVal == 0) 
			break;

		if (MemInfo.RegionSize == 65536 && MemInfo.Protect == PAGE_EXECUTE_READWRITE && MemInfo.State == MEM_COMMIT && MemInfo.Type == MEM_PRIVATE)
		{
			//DbgPrint("Address: %p\n", MemInfo.BaseAddress);
			RegAddr[tmpC] = MemInfo.BaseAddress;
			tmpC++;
			if (tmpC >= 510) 
				break;
		}
	}

	Counter = tmpC;
}
 

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

	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)TalkStructp->PID, &HackProcess);
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

			if (CommandSpacep->Addr1 > MM_LOWEST_USER_ADDRESS && CommandSpacep->Addr1 < MM_HIGHEST_USER_ADDRESS)
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

	PCWSTR Nm = L"\\BaseNamedObjects\\ASDFGHJKL";
	RtlInitUnicodeString(&usSectionName, Nm);
	InitializeObjectAttributes(&objAttributes, &usSectionName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, 0);
	HANDLE m_SectionHandle = 0;
	DWORD64* m_pAddrMap = NULL;

	status = ZwOpenSection(&m_SectionHandle, GENERIC_READ | GENERIC_WRITE, &objAttributes);

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


			Loop();

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




NTSTATUS DriverEntry(_In_  struct _DRIVER_OBJECT* DriverObject, _In_  PUNICODE_STRING RegistryPath)
{
	DbgPrint("DriverEntry: start\n");

	GetInformationFromFileMap();

	return STATUS_SUCCESS;
}