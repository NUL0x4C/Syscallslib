#include <Windows.h>
#include "Structs.h"
#include "Utils.h"

#define UP		-32
#define DOWN	32


int Seed = 0;


VOID InitializeSeed(INT SEED) {
	Seed = SEED;
}

SIZE_T StringLengthA(LPCSTR String)
{
	LPCSTR String2;

	for (String2 = String; *String2; ++String2);

	return (String2 - String);
}

UINT32 HashStringRotr32SubA(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

INT HashStringRotr32A(PCHAR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < StringLengthA(String); Index++)
		Value = String[Index] + HashStringRotr32SubA(Value, Seed);

	return Value;
}

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 StrHashed;
	WORD    wSystemCall;
	INT     Rotr32Seed;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

VX_TABLE_ENTRY VxTbleEntry = { 0 };

typedef struct _NtdllConfig {
	PVOID pNtdll;
	PIMAGE_DOS_HEADER pDosHdr;
	PIMAGE_NT_HEADERS pNtHdr;
	PIMAGE_EXPORT_DIRECTORY pIED;
	PDWORD pdwAddressOfFunctions;
	PDWORD pdwAddressOfNames;
	PWORD pwAddressOfNameOrdinales;
} NtdllConfig, * PNtdllConfig;

NtdllConfig NtdllConfigStruct = { 0 };

BOOL InitializeNtdllConfigStruct() {

	PPEB pPeb = (PPEB)__readgsqword(0x60);
	if (pPeb == NULL || pPeb->OSMajorVersion != 0xA) {
		return FALSE;
	}

	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	PVOID pNtdll = pDte->DllBase;
	if (pNtdll == NULL) {
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pNtdll;
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pNtdll + pDosHdr->e_lfanew);
	if (pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdll + pNtHdr->OptionalHeader.DataDirectory[0].VirtualAddress);
	if (pIED == NULL) {
		return FALSE;
	}

	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pNtdll + pIED->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pNtdll + pIED->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pNtdll + pIED->AddressOfNameOrdinals);


	NtdllConfigStruct.pNtdll = pNtdll;
	NtdllConfigStruct.pDosHdr = pDosHdr;
	NtdllConfigStruct.pNtHdr = pNtHdr;
	NtdllConfigStruct.pIED = pIED;
	NtdllConfigStruct.pdwAddressOfFunctions = pdwAddressOfFunctions;
	NtdllConfigStruct.pdwAddressOfNames = pdwAddressOfNames;
	NtdllConfigStruct.pwAddressOfNameOrdinales = pwAddressOfNameOrdinales;

	return TRUE;

}

BOOL InitializeSyscallviaTartarus(INT StrHashed) {

	if (StrHashed == NULL) {
		return FALSE;
	}

	if (NtdllConfigStruct.pNtdll == NULL ||
		NtdllConfigStruct.pdwAddressOfFunctions == NULL ||
		NtdllConfigStruct.pdwAddressOfNames == NULL ||
		NtdllConfigStruct.pwAddressOfNameOrdinales == NULL) {

		if (!InitializeNtdllConfigStruct()) {
			return FALSE;
		}
	}

	for (WORD cx = 0; cx < NtdllConfigStruct.pIED->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)NtdllConfigStruct.pNtdll + NtdllConfigStruct.pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)NtdllConfigStruct.pNtdll + NtdllConfigStruct.pdwAddressOfFunctions[NtdllConfigStruct.pwAddressOfNameOrdinales[cx]];
		if (HashStringRotr32A(pczFunctionName) == StrHashed) {
			VxTbleEntry.pAddress = pFunctionAddress;

			// First opcodes should be :
			//    MOV R10, RCX
			//    MOV RAX, <syscall>
			if (*((PBYTE)pFunctionAddress) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6) == 0x00
				&& *((PBYTE)pFunctionAddress + 7) == 0x00) {

				BYTE high = *((PBYTE)pFunctionAddress + 5);
				BYTE low = *((PBYTE)pFunctionAddress + 4);
				VxTbleEntry.wSystemCall = (high << 8) | low;

				return TRUE;
			}
			//if hooked check the neighborhood to find clean syscall
			if (*((PBYTE)pFunctionAddress) == 0xe9) {
				for (WORD idx = 1; idx <= 500; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						VxTbleEntry.wSystemCall = (high << 8) | low - idx;

						return TRUE;
					}
					// check neighboring syscall up
					if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						VxTbleEntry.wSystemCall = (high << 8) | low + idx;

						return TRUE;
					}

				}
				return FALSE;
			}
			if (*((PBYTE)pFunctionAddress + 3) == 0xe9) {
				for (WORD idx = 1; idx <= 500; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
						VxTbleEntry.wSystemCall = (high << 8) | low - idx;
						return TRUE;
					}
					// check neighboring syscall up
					if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
						&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
						&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
						&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
						&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
						BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
						VxTbleEntry.wSystemCall = (high << 8) | low + idx;
						return TRUE;
					}

				}
				return FALSE;
			}
		}
	}
	return FALSE;
}

PVOID getSyscallAddress() {
	return VxTbleEntry.pAddress;
}

WORD getSyscallNumber() {
	return VxTbleEntry.wSystemCall;
}

