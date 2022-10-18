#include <Windows.h>
#include <stdio.h>
#include "Syscalls.h"

#pragma comment (lib, "Syscalls.lib")


// generated using hasher.c (Seed = 7)
#define NtAllocateVirtualMemory_StrHashed   0x014044AE
#define NtProtectVirtualMemory_StrHashed    0xE67C7320
#define NtCreateSection_StrHashed			0xAC2EDA02
#define NtOpenSection_StrHashed				0xD443EC8C
#define NtMapViewOfSection_StrHashed		0x92DD00B3
#define NtUnmapViewOfSection_StrHashed		0x12D71086
#define NtClose_StrHashed					0x7B3F64A4
#define NtQuerySystemInformation_StrHashed  0xEFFC1CF8
#define NtCreateUserProcess_StrHashed		0x0C43BACB
#define NtWriteVirtualMemory_StrHashed		0x1130814D





int main() {

	NTSTATUS	STATUS		= NULL;
	


	HashStruct SyscallHashStruct = {

	.NtAllocateVirtualMemory_Hash	= NtAllocateVirtualMemory_StrHashed,
	.NtProtectVirtualMemory_Hash	= NtProtectVirtualMemory_StrHashed,
	.NtCreateSection_Hash			= NtCreateSection_StrHashed,
	.NtOpenSection_Hash				= NtOpenSection_StrHashed,
	.NtMapViewOfSection_Hash		= NtMapViewOfSection_StrHashed,
	.NtUnmapViewOfSection_Hash		= NtUnmapViewOfSection_StrHashed,
	.NtClose_Hash					= NtClose_StrHashed,
	.NtWriteVirtualMemory_Hash		= NtWriteVirtualMemory_StrHashed,
	.NtQuerySystemInformation_Hash	= NtQuerySystemInformation_StrHashed,
	.NtCreateUserProcess_Hash		= NtCreateUserProcess_StrHashed

	};


	if (!InitializeStruct(0x07, &SyscallHashStruct)) {
		printf("[-] InitializeStruct Failed \n");
		goto _exit;
	}


	


_exit:
	
	printf("[i] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}
