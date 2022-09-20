#include <Windows.h>
#include <stdio.h>
#include "Syscalls.h"

#pragma comment (lib, "Syscalls.lib")


// generated using hasher.c (Seed = 7)
#define NtAllocateVirtualMemory_StrHashed       0x014044AE
#define NtProtectVirtualMemory_StrHashed        0xE67C7320
#define NtCreateSection_StrHashed       0xAC2EDA02
#define NtOpenSection_StrHashed         0xD443EC8C
#define NtMapViewOfSection_StrHashed    0x92DD00B3
#define NtUnmapViewOfSection_StrHashed  0x12D71086
#define NtClose_StrHashed       0x7B3F64A4


int main() {

	NTSTATUS	STATUS		= NULL;
	PVOID		pAddress	= NULL;
	


	HashStruct SyscallHashStruct = {

	.NtAllocateVirtualMemory_Hash = NtAllocateVirtualMemory_StrHashed,
	.NtProtectVirtualMemory_Hash	= NtProtectVirtualMemory_StrHashed,
	.NtCreateSection_Hash			= NtCreateSection_StrHashed,
	.NtOpenSection_Hash			= NtOpenSection_StrHashed,
	.NtMapViewOfSection_Hash		= NtMapViewOfSection_StrHashed,
	.NtUnmapViewOfSection_Hash	= NtUnmapViewOfSection_StrHashed,
	.NtClose_Hash					= NtClose_StrHashed,

	};


	if (!InitializeStruct(0x07, &SyscallHashStruct)) {
		printf("[-] InitializeStruct Failed \n");
		goto _exit;
	}


	pAddress = NtAllocateVirtualMemory2(0x100, &STATUS);
	if (pAddress == NULL) {
		printf("[-] Error Occured : 0x%0.8X \n", STATUS);
		goto _exit;
	}
	printf("[+] pAddress : 0x%p \n", pAddress);




_exit:
	printf("[i] Press <Enter> To Quit ... ");
	getchar();
	return 0;
}