### Syscallslib: a library that automates some clean syscalls to make it easier & faster to implement. its pretty basic code, im using hellsgate (TartarusGate) tech to fetch direct syscalls, and it saves times when needed.


### So Far The Syscalls Supported :
- NtAllocateVirtualMemory
- NtProtectVirtualMemory
- NtCreateSection
- NtOpenSection
- NtMapViewOfSection
- NtUnmapViewOfSection
- NtClose

### Usage :
- initialize the struct holding the hashes of the syscalls names using *InitializeStruct()*, it takes 2 parameters, the seed used, and a pointer to *HashStruct* struct:
- to automates this even more, i included [Hasher.c](https://github.com/ORCx41/Syscallslib/blob/main/Hasher/Hasher.c) file that can output the hashes of the syscalls directly ...
- after that you are ready to do syscalls
- added a small project to demonstrate the usage [here](https://github.com/ORCx41/Syscallslib/tree/main/Test).
```
#include <Windows.h>
#include <stdio.h>
#include "Syscalls.h"

#pragma comment (lib, "Syscalls.lib")


// generated using hasher.c (Seed = 7)
#define NtAllocateVirtualMemory_StrHashed       0x014044AE
#define NtProtectVirtualMemory_StrHashed        0xE67C7320
#define NtCreateSection_StrHashed               0xAC2EDA02
#define NtOpenSection_StrHashed                 0xD443EC8C
#define NtMapViewOfSection_StrHashed            0x92DD00B3
#define NtUnmapViewOfSection_StrHashed          0x12D71086
#define NtClose_StrHashed                       0x7B3F64A4


int main() {

	NTSTATUS	STATUS		= NULL;
	PVOID		pAddress	= NULL;
	


	HashStruct SyscallHashStruct = {

	.NtAllocateVirtualMemory_Hash = NtAllocateVirtualMemory_StrHashed,
	.NtProtectVirtualMemory_Hash	= NtProtectVirtualMemory_StrHashed,
	.NtCreateSection_Hash			    = NtCreateSection_StrHashed,
	.NtOpenSection_Hash			      = NtOpenSection_StrHashed,
	.NtMapViewOfSection_Hash		  = NtMapViewOfSection_StrHashed,
	.NtUnmapViewOfSection_Hash	  = NtUnmapViewOfSection_StrHashed,
	.NtClose_Hash					        = NtClose_StrHashed,

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

```




### TODO:
- Add support for more usefull syscalls


### Thanks For:
- [TartarusGate](https://github.com/trickster0/TartarusGate)
- [HellsGate](https://github.com/am0nsec/HellsGate)
