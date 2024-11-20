#pragma once
#include <ntifs.h>

typedef struct _GameData {
	DWORD32 TargetPID;
	DWORD32 MyPID;
} GameData, * PGameData;


typedef struct _TalkStruct
{
	DWORD64 g_CiOptions;
	DWORD64 CommunicateBuffer;//
	DWORD32 PID;
} TalkStruct, * PTaklStruct;


typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef unsigned int        UINT;

typedef struct _CommandSpace
{
	BYTE Flag;
	DWORD32 PID;
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
} CommandSpace, * PCommandSpace;