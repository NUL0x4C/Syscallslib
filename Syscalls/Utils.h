#pragma once
#include <Windows.h>

SIZE_T	StringLengthA(LPCSTR String);

VOID	InitializeSeed(INT SEED);

INT		HashStringRotr32A(PCHAR String);

BOOL InitializeSyscallviaTartarus(INT StrHashed);

WORD getSyscallNumber();

PVOID getSyscallAddress();

extern VOID HellsGate(WORD wSystemCall);

extern HellDescent();
