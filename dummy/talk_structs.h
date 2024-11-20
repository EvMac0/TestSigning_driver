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
		0 - ������ �� ������
		1 - ������
		2 - ������
		3 - ��������� �������� ������ ������
		4 - ����� �� ����� � ��������
		5 - �������� �������� PID
	*/
	PVOID Addr1; //��� ������: ������ ������   ��� ������: ���� �����
	PVOID Addr2; //��� ������: ���� ������  ��� ������: ������ �����
	DWORD32 Size;//������ ������/������
	DWORD64 Result;//���������(������������ �� ������)
} CommandSpace, * PCommandSpace;