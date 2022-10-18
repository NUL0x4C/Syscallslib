#include <Windows.h>
#include <stdio.h>
#include "Structs.h"
#include "Utils.h"


typedef struct _HashStruct {

	DWORD NtAllocateVirtualMemory_StrHashed;
	DWORD NtProtectVirtualMemory_StrHashed;

	DWORD NtCreateSection_StrHashed;
	DWORD NtOpenSection_StrHashed;
	DWORD NtMapViewOfSection_StrHashed;
	DWORD NtUnmapViewOfSection_StrHashed;

	DWORD NtClose_StrHashed;


	DWORD NtQuerySystemInformation_StrHashed;
	DWORD NtCreateUserProcess_StrHashed;
	DWORD NtWriteVirtualMemory_StrHashed;


}HashStruct, * PHashStruct;


HashStruct SyscallHashStruct = { 0 };


BOOL
InitializeStruct(
	IN INT Seed,
	IN PHashStruct PStruct) {

	if (Seed == 0 || PStruct == NULL) {
		return FALSE;
	}

	InitializeSeed(Seed);

	SyscallHashStruct.NtAllocateVirtualMemory_StrHashed = PStruct->NtAllocateVirtualMemory_StrHashed;
	SyscallHashStruct.NtProtectVirtualMemory_StrHashed = PStruct->NtProtectVirtualMemory_StrHashed;
	SyscallHashStruct.NtCreateSection_StrHashed = PStruct->NtCreateSection_StrHashed;
	SyscallHashStruct.NtOpenSection_StrHashed = PStruct->NtOpenSection_StrHashed;

	SyscallHashStruct.NtMapViewOfSection_StrHashed = PStruct->NtMapViewOfSection_StrHashed;
	SyscallHashStruct.NtUnmapViewOfSection_StrHashed = PStruct->NtUnmapViewOfSection_StrHashed;
	SyscallHashStruct.NtClose_StrHashed = PStruct->NtClose_StrHashed;


	SyscallHashStruct.NtQuerySystemInformation_StrHashed = PStruct->NtQuerySystemInformation_StrHashed;
	SyscallHashStruct.NtCreateUserProcess_StrHashed = PStruct->NtCreateUserProcess_StrHashed;
	SyscallHashStruct.NtWriteVirtualMemory_StrHashed = PStruct->NtWriteVirtualMemory_StrHashed;


	return TRUE;
}


PVOID 
NtAllocateVirtualMemory (
	IN  OPTIONAL  HANDLE	ProcessHandle,	
	IN  OPTIONAL  PVOID		BaseAddress,		
	IN			  SIZE_T	RegionSize,			
	IN  OPTIONAL  ULONG		AllocationType,		
	IN  OPTIONAL  ULONG		Protect,			
	OUT OPTIONAL  PNTSTATUS	STATUS				// OUTPUT : the return from the syscall
){
	if (RegionSize == NULL)
		return NULL;

	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtAllocateVirtualMemory_StrHashed))
		return NULL;

	// default values:
	HANDLE	 tmpProcessHandle	= (HANDLE)-1;
	PVOID	 tmpBaseAddress		= NULL;
	SIZE_T	 tmpRegionSize		= RegionSize;
	ULONG	 tmpAllocationType	= MEM_COMMIT | MEM_RESERVE;
	ULONG	 tmpProtect			= PAGE_READWRITE;

	// variables needed for the syscall:
	ULONG_PTR ZeroBits			= 0;

	// in case of new non-default values:
	if (ProcessHandle != NULL)
		tmpProcessHandle = ProcessHandle;
	if (BaseAddress != NULL)
		tmpBaseAddress = BaseAddress;
	if (AllocationType != NULL)
		tmpAllocationType = AllocationType;
	if (Protect != NULL)
		tmpProtect = Protect;
	

	HellsGate(getSyscallNumber());
	
	NTSTATUS Status = HellDescent(tmpProcessHandle, &tmpBaseAddress, ZeroBits, &tmpRegionSize, tmpAllocationType, tmpProtect);
	
	if (STATUS != NULL)
		*STATUS = Status;

	return tmpBaseAddress;
}

PVOID
NtAllocateVirtualMemory2(
	IN			  SIZE_T	RegionSize,
	OUT OPTIONAL  PNTSTATUS	STATUS				// OUTPUT : the return from the syscall
){
	return NtAllocateVirtualMemory(NULL, NULL, RegionSize, NULL, NULL, STATUS);
}



ULONG 
NtProtectVirtualMemory(
	IN  OPTIONAL HANDLE		ProcessHandle,			
	IN			 PVOID		BaseAddress,			
	IN			 SIZE_T		NumberOfBytesToProtect,	
	IN			 ULONG		NewAccessProtection,	
	OUT OPTIONAL PNTSTATUS	STATUS					// OUTPUT : the return from the syscall
){

	if (BaseAddress == NULL || NumberOfBytesToProtect == NULL || NewAccessProtection == NULL)
		return NULL;

	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtProtectVirtualMemory_StrHashed))
		return NULL;


	// default values:
	HANDLE	 tmpProcessHandle			= (HANDLE)-1;
	PVOID	 tmpBaseAddress				= BaseAddress;
	SIZE_T	 tmpNumberOfBytesToProtect	= NumberOfBytesToProtect;
	ULONG	 tmpNewAccessProtection		= NewAccessProtection;
	
	// variables needed for the syscall:
	ULONG	 OldAccessProtection		= NULL;

	// in case of new non-default values:
	if (ProcessHandle != NULL)
		tmpProcessHandle = ProcessHandle;


	HellsGate(getSyscallNumber());

	NTSTATUS Status = HellDescent(tmpProcessHandle, &tmpBaseAddress, &tmpNumberOfBytesToProtect, tmpNewAccessProtection, &OldAccessProtection);

	if (STATUS != NULL)
		*STATUS = Status;

	return OldAccessProtection;
}




HANDLE 
NtCreateSection(
	IN	OPTIONAL	ACCESS_MASK			DesiredAccess,
	IN	OPTIONAL	POBJECT_ATTRIBUTES	ObjectAttributes,
	IN				SIZE_T				NumberOfBytes,
	IN	OPTIONAL	ULONG               SectionPageProtection,
	IN	OPTIONAL	ULONG               AllocationAttributes,
	IN	OPTIONAL	HANDLE              FileHandle,
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall

) {

	if (NumberOfBytes == NULL)
		return INVALID_HANDLE_VALUE;

	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtCreateSection_StrHashed))
		return INVALID_HANDLE_VALUE;


	// default values:
	ACCESS_MASK			tmpDesiredAccess			= SECTION_ALL_ACCESS;
	POBJECT_ATTRIBUTES	tmpObjectAttributes			= NULL;
	SIZE_T				tmpNumberOfBytes			= NumberOfBytes;
	ULONG				tmpSectionPageProtection	= PAGE_READWRITE;
	ULONG				tmpAllocationAttributes		= SEC_COMMIT;
	HANDLE				tmpFileHandle				= NULL;
	
	// variables needed for the syscall:
	HANDLE			hSection		= INVALID_HANDLE_VALUE;
	LARGE_INTEGER	Size			= { .HighPart = 0, .LowPart = tmpNumberOfBytes };

	// in case of new non-default values:
	if (DesiredAccess != NULL)
		tmpDesiredAccess = DesiredAccess;
	if (ObjectAttributes != NULL)
		tmpObjectAttributes = ObjectAttributes;
	if (SectionPageProtection != NULL)
		tmpSectionPageProtection = SectionPageProtection;
	if (AllocationAttributes != NULL)
		tmpAllocationAttributes = AllocationAttributes;
	if (FileHandle != NULL)
		tmpFileHandle = FileHandle;


	HellsGate(getSyscallNumber());

	NTSTATUS Status = HellDescent(&hSection, tmpDesiredAccess, tmpObjectAttributes, &Size, tmpSectionPageProtection, tmpAllocationAttributes, tmpFileHandle);

	if (STATUS != NULL)
		*STATUS = Status;


	return hSection;
}


HANDLE 
NtOpenSection(
	IN	OPTIONAL	ACCESS_MASK			DesiredAccess,
	IN				POBJECT_ATTRIBUTES  ObjectAttributes,
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall
) {

	if (ObjectAttributes == NULL)
		return INVALID_HANDLE_VALUE;

	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtOpenSection_StrHashed))
		return INVALID_HANDLE_VALUE;


	ACCESS_MASK		tmpDesiredAccess = SECTION_ALL_ACCESS;

	HANDLE			hSection = INVALID_HANDLE_VALUE;

	if (DesiredAccess != NULL) {
		tmpDesiredAccess = DesiredAccess;
	}


	HellsGate(getSyscallNumber());
	NTSTATUS Status = HellDescent(&hSection, tmpDesiredAccess, ObjectAttributes);

	if (STATUS != NULL)
		*STATUS = Status;

	return hSection;

}




PVOID
NtMapViewOfSection(
	IN				HANDLE              SectionHandle,
	IN  OPTIONAL	HANDLE              ProcessHandle,
	IN  OPTIONAL	PVOID				BaseAddress,
	IN  OPTIONAL	ULONG               AllocationType,
	IN  OPTIONAL	ULONG               Protect,
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall

) {

	if (SectionHandle == NULL)
		return NULL;


	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtMapViewOfSection_StrHashed))
		return NULL;

	// default values:
	HANDLE              tmpSectionHandle	= SectionHandle;
	HANDLE              tmpProcessHandle	= (HANDLE)-1;
	PVOID				tmpBaseAddress		= NULL;
	ULONG               tmpAllocationType	= 0;
	ULONG               tmpProtect			= PAGE_READWRITE;

	// variables needed for the syscall:
	ULONG_PTR            ZeroBits				= 0;
	SIZE_T               CommitSize				= 0;
	PLARGE_INTEGER		 SectionOffset			= NULL;
	PSIZE_T				 ViewSize				= NULL;
	
	
	// in case of new non-default values:
	if (ProcessHandle != NULL)
		tmpProcessHandle = ProcessHandle;
	if (BaseAddress != NULL)
		tmpBaseAddress = BaseAddress;
	if (AllocationType != NULL)
		tmpAllocationType = AllocationType;
	if (Protect != NULL)
		tmpProtect = Protect;


	HellsGate(getSyscallNumber());

	NTSTATUS Status = HellDescent(tmpSectionHandle, tmpProcessHandle, &tmpBaseAddress, ZeroBits, CommitSize, SectionOffset, &ViewSize, ViewShare, tmpAllocationType, tmpProtect);

	if (STATUS != NULL)
		*STATUS = Status;

	return tmpBaseAddress;
}



VOID 
NtUnmapViewOfSection(
	IN  OPTIONAL	HANDLE              ProcessHandle,
	IN  			PVOID				BaseAddress,
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall
) {

	if (BaseAddress == NULL)
		return;

	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtUnmapViewOfSection_StrHashed))
		return;
	
	// default values:
	HANDLE              tmpProcessHandle = (HANDLE)-1;
	HANDLE				tmpBaseAddress   = BaseAddress;

	// in case of new non-default values:
	if (ProcessHandle != NULL)
		tmpProcessHandle = ProcessHandle;

	HellsGate(getSyscallNumber());
	
	NTSTATUS Status = HellDescent(tmpProcessHandle, tmpBaseAddress);
	
	if (STATUS != NULL)
		*STATUS = Status;

}


VOID 
NtClose(
	IN				HANDLE              SectionHandle,
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall
) {

	if (SectionHandle == NULL)
		return NULL;


	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtClose_StrHashed))
		return NULL;

	HellsGate(getSyscallNumber());

	NTSTATUS Status = HellDescent(SectionHandle);

	if (STATUS != NULL)
		*STATUS = Status;

}



SIZE_T NtWriteVirtualMemory(
	IN OPTIONAL		HANDLE               ProcessHandle,
	IN				PVOID                BaseAddress,
	IN				PVOID                Buffer,
	IN				SIZE_T               NumberOfBytesToWrite,
	OUT OPTIONAL	PNTSTATUS			 STATUS						// OUTPUT : the return from the syscall
) {


	if (BaseAddress == NULL || Buffer == NULL || NumberOfBytesToWrite == NULL)
		return NULL;

	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtWriteVirtualMemory_StrHashed))
		return NULL;

	// default values:
	HANDLE              tmpProcessHandle		= (HANDLE)-1;
	PVOID               tmpBaseAddress			= (PVOID)BaseAddress;
	PVOID				tmpBuffer				= (PVOID)Buffer;
	SIZE_T				tmpNumberOfBytesToWrite = (SIZE_T)NumberOfBytesToWrite;



	// in case of new non-default values:
	if (ProcessHandle != NULL)
		tmpProcessHandle = ProcessHandle;


	// variables needed for the syscall:
	SIZE_T NumberOfBytesWritten = NULL;

	
	
	HellsGate(getSyscallNumber());
	NTSTATUS Status = HellDescent(tmpProcessHandle, tmpBaseAddress, tmpBuffer, tmpNumberOfBytesToWrite, &NumberOfBytesWritten);

	if (STATUS != NULL)
		*STATUS = Status;

	return NumberOfBytesWritten;
}




BOOL NtCreateUserProcess(
	OUT				PHANDLE							ProcessHandle,
	OUT				PHANDLE							ThreadHandle,
	IN	OPTIONAL	ACCESS_MASK						ProcessDesiredAccess,
	IN	OPTIONAL	ACCESS_MASK						ThreadDesiredAccess,
	IN	OPTIONAL	POBJECT_ATTRIBUTES				ProcessObjectAttributes,
	IN	OPTIONAL	POBJECT_ATTRIBUTES				ThreadObjectAttributes,
	IN	OPTIONAL	ULONG							ProcessFlags,
	IN	OPTIONAL	ULONG							ThreadFlags,
	IN				PRTL_USER_PROCESS_PARAMETERS	ProcessParameters,
	IN				PPS_CREATE_INFO					CreateInfo,
	IN				PPS_ATTRIBUTE_LIST				AttributeList,
	OUT OPTIONAL	PNTSTATUS						STATUS						// OUTPUT : the return from the syscall
) {


	if (ProcessHandle == NULL || ThreadHandle == NULL || ProcessParameters == NULL || CreateInfo == NULL || AttributeList == NULL) {
		printf("[!] NULL Check \n");
		return FALSE;
	}

	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtCreateUserProcess_StrHashed)) {
		printf("[!] InitializeSyscallviaTartarus \n");
		return FALSE;
	}

	// default values:
	ACCESS_MASK						tmpProcessDesiredAccess		= PROCESS_ALL_ACCESS;
	ACCESS_MASK						tmpThreadDesiredAccess		= PROCESS_ALL_ACCESS;
	POBJECT_ATTRIBUTES				tmpProcessObjectAttributes	= NULL;
	POBJECT_ATTRIBUTES				tmpThreadObjectAttributes	= NULL;
	ULONG							tmpProcessFlags				= NULL;
	ULONG							tmpThreadFlags				= NULL;



	// in case of new non-default values:
	if (ProcessDesiredAccess != NULL)
		tmpProcessDesiredAccess = ProcessDesiredAccess;
	if (ThreadDesiredAccess != NULL)
		tmpThreadDesiredAccess = ThreadDesiredAccess;
	if (ProcessObjectAttributes != NULL)
		tmpProcessObjectAttributes = ProcessObjectAttributes;
	if (ThreadObjectAttributes != NULL)
		tmpThreadObjectAttributes = ThreadObjectAttributes;
	if (ProcessFlags != NULL)
		tmpProcessFlags = ProcessFlags;
	if (ThreadFlags != NULL)
		tmpThreadFlags = ThreadFlags;


	HellsGate(getSyscallNumber());

	NTSTATUS Status = HellDescent(
		ProcessHandle,
		ThreadHandle,
		tmpProcessDesiredAccess,
		tmpThreadDesiredAccess,
		tmpProcessObjectAttributes,
		tmpThreadObjectAttributes,
		tmpProcessFlags,
		tmpThreadFlags,
		ProcessParameters,
		CreateInfo,
		AttributeList
	);

	if (STATUS != NULL)
		*STATUS = Status;

	if (*ProcessHandle == NULL || *ThreadHandle == NULL)
		return FALSE;

	return TRUE;
}


BOOL NtCreateUserProcess2(
	OUT				PHANDLE							ProcessHandle,
	OUT				PHANDLE							ThreadHandle,
	IN				PRTL_USER_PROCESS_PARAMETERS	ProcessParameters,
	IN				PPS_CREATE_INFO					CreateInfo,
	IN				PPS_ATTRIBUTE_LIST				AttributeList,
	OUT OPTIONAL	PNTSTATUS						STATUS						// OUTPUT : the return from the syscall
) {
	
	return NtCreateUserProcess(ProcessHandle, ThreadHandle, NULL, NULL, NULL, NULL, NULL, NULL, ProcessParameters, CreateInfo, AttributeList, STATUS);
}



BOOL NtQuerySystemInformation(
	IN					SYSTEM_INFORMATION_CLASS		SystemInformationClass,
	IN	OPTIONAL		PVOID							SystemInformation,
	IN	OPTIONAL		ULONG							SystemInformationLength,
	OUT OPTIONAL		PULONG							ReturnLength,
	OUT OPTIONAL		PNTSTATUS						STATUS						// OUTPUT : the return from the syscall
) {

	if (SystemInformationClass == NULL || ReturnLength == NULL)
		return FALSE;

	if (!InitializeSyscallviaTartarus(SyscallHashStruct.NtQuerySystemInformation_StrHashed))
		return FALSE;


	// default values:
	PVOID tmpSystemInformation				= NULL;
	PVOID tmpSystemInformationLength		= NULL;


	// in case of new non-default values:
	if (SystemInformation != NULL)
		tmpSystemInformation = SystemInformation;
	if (SystemInformationLength != NULL)
		tmpSystemInformationLength = SystemInformationLength;


	HellsGate(getSyscallNumber());


	NTSTATUS Status = HellDescent(SystemInformationClass, tmpSystemInformation, tmpSystemInformationLength, ReturnLength);

	if (STATUS != NULL)
		*STATUS = Status;

	if (*ReturnLength == NULL)
		return FALSE;

	return TRUE;
}










