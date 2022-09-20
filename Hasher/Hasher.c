#include <Windows.h>
#include <stdio.h>

#define SEED 0x07
#define NAME "_StrHashed"

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
        Value = String[Index] + HashStringRotr32SubA(Value, SEED);

    return Value;
}




int main() {

 
    printf("#define %s%s \t0x%0.8X \n", "NtAllocateVirtualMemory", NAME, HashStringRotr32A("NtAllocateVirtualMemory"));
    printf("#define %s%s \t0x%0.8X \n", "NtProtectVirtualMemory", NAME, HashStringRotr32A("NtProtectVirtualMemory"));

    printf("#define %s%s \t0x%0.8X \n", "NtCreateSection", NAME, HashStringRotr32A("NtCreateSection"));
	printf("#define %s%s \t0x%0.8X \n", "NtOpenSection", NAME, HashStringRotr32A("NtOpenSection"));
    printf("#define %s%s \t0x%0.8X \n", "NtMapViewOfSection", NAME, HashStringRotr32A("NtMapViewOfSection"));
    
	printf("#define %s%s \t0x%0.8X \n", "NtUnmapViewOfSection", NAME, HashStringRotr32A("NtUnmapViewOfSection"));
    printf("#define %s%s \t0x%0.8X \n", "NtClose", NAME, HashStringRotr32A("NtClose"));



    


    //printf("#define %s%s \t0x%0.8X \n", "", NAME, HashStringRotr32A(""));


    return 0;

}

