#pragma once

#ifdef __cplusplus
#define EXTERN extern "C"
#else
#define EXTERN extern
#endif

#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include <Windows.h>


//========================================================================================================================================================================//
//												tmp structs for the syscalls (you can remove if found in your code)

#ifndef TMP_STRUCTS
#define TMP_STRUCTS


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


#define RTL_MAX_DRIVE_LETTERS 32



typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	USHORT Flags;
	USHORT Length;
	ULONG TimeStamp;
	UNICODE_STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} CURDIR, * PCURDIR;


typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;
	ULONG Length;

	ULONG Flags;
	ULONG DebugFlags;

	HANDLE ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StandardInput;
	HANDLE StandardOutput;
	HANDLE StandardError;

	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PWCHAR Environment;

	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;

	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

	ULONG_PTR EnvironmentSize;
	ULONG_PTR EnvironmentVersion;
	PVOID PackageDependencyData;
	ULONG ProcessGroupId;
	ULONG LoaderThreads;

} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;




typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates

} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		struct
		{
			union
			{
				ULONG InitFlags;
				struct
				{
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				} s1;
			} u1;
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		struct
		{
			HANDLE FileHandle;
		} FailSection;

		struct
		{
			USHORT DllCharacteristics;
		} ExeFormat;

		struct
		{
			HANDLE IFEOKey;
		} ExeName;

		struct
		{
			union
			{
				ULONG OutputFlags;
				struct
				{
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1;
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				} s2;
			} u2;
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};

} PS_CREATE_INFO, * PPS_CREATE_INFO;



typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;

} PS_ATTRIBUTE, * PPS_ATTRIBUTE;



typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[3];

} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;




#define PS_ATTRIBUTE_NUMBER_MASK    0x0000ffff
#define PS_ATTRIBUTE_THREAD         0x00010000 // Attribute may be used with thread creation
#define PS_ATTRIBUTE_INPUT          0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE       0x00040000 // Attribute may be "accumulated", e.g. bitmasks, counters, etc.

typedef enum _PS_ATTRIBUTE_NUM
{
	PsAttributeParentProcess,                   // in HANDLE
	PsAttributeDebugPort,                       // in HANDLE
	PsAttributeToken,                           // in HANDLE
	PsAttributeClientId,                        // out PCLIENT_ID
	PsAttributeTebAddress,                      // out PTEB
	PsAttributeImageName,                       // in PWSTR
	PsAttributeImageInfo,                       // out PSECTION_IMAGE_INFORMATION
	PsAttributeMemoryReserve,                   // in PPS_MEMORY_RESERVE
	PsAttributePriorityClass,                   // in UCHAR
	PsAttributeErrorMode,                       // in ULONG
	PsAttributeStdHandleInfo,                   // in PPS_STD_HANDLE_INFO
	PsAttributeHandleList,                      // in PHANDLE
	PsAttributeGroupAffinity,                   // in PGROUP_AFFINITY
	PsAttributePreferredNode,                   // in PUSHORT
	PsAttributeIdealProcessor,                  // in PPROCESSOR_NUMBER
	PsAttributeUmsThread,                       // see MSDN UpdateProceThreadAttributeList (CreateProcessW) - in PUMS_CREATE_THREAD_ATTRIBUTES
	PsAttributeMitigationOptions,               // in UCHAR
	PsAttributeProtectionLevel,                 // in ULONG
	PsAttributeSecureProcess,                   // since THRESHOLD (Virtual Secure Mode, Device Guard)
	PsAttributeJobList,
	PsAttributeChildProcessPolicy,              // since THRESHOLD2
	PsAttributeAllApplicationPackagesPolicy,    // since REDSTONE
	PsAttributeWin32kFilter,
	PsAttributeSafeOpenPromptOriginClaim,
	PsAttributeBnoIsolation,
	PsAttributeDesktopAppPolicy,
	PsAttributeMax
} PS_ATTRIBUTE_NUM;


#define PsAttributeValue(Number, Thread, Input, Additive)		\
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK)	|					\
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0)	|					\
    ((Input) ? PS_ATTRIBUTE_INPUT : 0)		|					\
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS									\
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)		
#define PS_ATTRIBUTE_DEBUG_PORT										\
    PsAttributeValue(PsAttributeDebugPort, FALSE, TRUE, TRUE)			
#define PS_ATTRIBUTE_TOKEN											\
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)				
#define PS_ATTRIBUTE_CLIENT_ID										\
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)			
#define PS_ATTRIBUTE_TEB_ADDRESS									\
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)			
#define PS_ATTRIBUTE_IMAGE_NAME										\
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)			
#define PS_ATTRIBUTE_IMAGE_INFO										\
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)			
#define PS_ATTRIBUTE_MEMORY_RESERVE									\
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)		
#define PS_ATTRIBUTE_PRIORITY_CLASS									\
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)		
#define PS_ATTRIBUTE_ERROR_MODE										\
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)			
#define PS_ATTRIBUTE_STD_HANDLE_INFO								\
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)		
#define PS_ATTRIBUTE_HANDLE_LIST									\
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)			
#define PS_ATTRIBUTE_GROUP_AFFINITY									\
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)		
#define PS_ATTRIBUTE_PREFERRED_NODE									\
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)		
#define PS_ATTRIBUTE_IDEAL_PROCESSOR								\
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)		
#define PS_ATTRIBUTE_MITIGATION_OPTIONS								\
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL								\
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, FALSE)	
#define PS_ATTRIBUTE_UMS_THREAD										\
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_SECURE_PROCESS									\
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST										\
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY							\
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY				\
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER									\
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM					\
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION									\
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY								\
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)




#define RTL_USER_PROC_PARAMS_NORMALIZED			0x00000001
#define RTL_USER_PROC_PROFILE_USER				0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL			0x00000004
#define RTL_USER_PROC_PROFILE_SERVER			0x00000008
#define RTL_USER_PROC_RESERVE_1MB				0x00000020
#define RTL_USER_PROC_RESERVE_16MB				0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE			0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT		0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL		0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT		0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING			0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS				0x00020000





typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformation = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	MaxSystemInfoClass = 82

} SYSTEM_INFORMATION_CLASS;

#endif // !TMP_STRUCTS




//========================================================================================================================================================================//




// struct here : [IMPORTANT FOR INITIALIZATION]
typedef struct _HashStruct {
	DWORD NtAllocateVirtualMemory_Hash;
	DWORD NtProtectVirtualMemory_Hash;

	DWORD NtCreateSection_Hash;
	DWORD NtOpenSection_Hash;
	DWORD NtMapViewOfSection_Hash;
	DWORD NtUnmapViewOfSection_Hash;

	DWORD NtClose_Hash;

	DWORD NtQuerySystemInformation_Hash;
	DWORD NtCreateUserProcess_Hash;
	DWORD NtWriteVirtualMemory_Hash;


}HashStruct, * PHashStruct;



EXTERN BOOL
InitializeStruct(
	IN			INT			Seed,						// INPUT : Seed Of The Rotr32 Hashing algo
	IN			PHashStruct PStruct							// INPUT : pointer to a struct of type 'HashStruct' that will initialize the data 
);

EXTERN PVOID
NtAllocateVirtualMemory(
	IN  OPTIONAL  HANDLE	ProcessHandle,								// INPUT  : in case of null, the function will run localy
	IN  OPTIONAL  PVOID		BaseAddress,							// INPUT  : NULL by default  
	IN			  SIZE_T	RegionSize,						// INPUT  : can't be NULL
	IN  OPTIONAL  ULONG		AllocationType,							// INPUT  : MEM_COMMIT | MEM_RESERVE by default
	IN  OPTIONAL  ULONG		Protect,							// INPUT  : PAGE_READWRITE by default
	OUT OPTIONAL  PNTSTATUS	STATUS									// OUTPUT : the return from the syscall
);

// calling the default NtAllocateVirtualMemory | u can do such thing to the others ...
EXTERN PVOID
NtAllocateVirtualMemory2(
	IN			  SIZE_T	RegionSize,						// INPUT  : can't be NULL
	OUT OPTIONAL  PNTSTATUS	STATUS									// OUTPUT : the return from the syscall
);

EXTERN ULONG
NtProtectVirtualMemory(
	IN  OPTIONAL HANDLE		ProcessHandle,							// INPUT  : in case of null, the function will run localy
	IN			 PVOID		BaseAddress,						// INPUT  : can't be NULL
	IN			 SIZE_T		NumberOfBytesToProtect,					// INPUT  : can't be NULL
	IN			 ULONG		NewAccessProtection,					// INPUT  : can't be NULL
	OUT OPTIONAL PNTSTATUS	STATUS									// OUTPUT : the return from the syscall
);

EXTERN HANDLE
NtCreateSection(
	IN	OPTIONAL	ACCESS_MASK			DesiredAccess,				// INPUT  : SECTION_ALL_ACCESS by default
	IN	OPTIONAL	POBJECT_ATTRIBUTES	ObjectAttributes,				// INPUT  : NULL by default
	IN				SIZE_T				NumberOfBytes,			// INPUT  : can't be NULL
	IN	OPTIONAL	ULONG               SectionPageProtection,				// INPUT  : PAGE_READWRITE be default
	IN	OPTIONAL	ULONG               AllocationAttributes,				// INPUT  : SEC_COMMIT by default
	IN	OPTIONAL	HANDLE              FileHandle,						// INPUT  : NULL by default
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall

);



EXTERN HANDLE
NtOpenSection(
	IN	OPTIONAL	ACCESS_MASK			DesiredAccess,				// INPUT  : SECTION_ALL_ACCESS by default
	IN				POBJECT_ATTRIBUTES  ObjectAttributes,				// INPUT  : can't be NULL
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall
);

EXTERN PVOID
NtMapViewOfSection(
	IN				HANDLE              SectionHandle,				// INPUT  : can't be NULL
	IN  OPTIONAL	HANDLE              ProcessHandle,						// INPUT  : in case of null, the function will run localy
	IN  OPTIONAL	PVOID				BaseAddress,					// INPUT  : NULL by default
	IN  OPTIONAL	ULONG               AllocationType,						// INPUT  : NULL by default
	IN  OPTIONAL	ULONG               Protect,							// INPUT  : PAGE_READWRITE by default
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall

);


EXTERN VOID
NtUnmapViewOfSection(
	IN  OPTIONAL	HANDLE              ProcessHandle,						// INPUT  : in case of null, the function will run localy
	IN  			PVOID				BaseAddress,				// INPUT  : can't be NULL
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall
);



EXTERN VOID
NtClose(															
	IN				HANDLE              SectionHandle,				// INPUT  : can't be NULL
	OUT OPTIONAL	PNTSTATUS			STATUS						// OUTPUT : the return from the syscall
);



EXTERN SIZE_T 
NtWriteVirtualMemory(
	IN OPTIONAL		HANDLE               ProcessHandle,
	IN				PVOID                BaseAddress,
	IN				PVOID                Buffer,
	IN				SIZE_T               NumberOfBytesToWrite,
	OUT OPTIONAL	PNTSTATUS			 STATUS						// OUTPUT : the return from the syscall
);

EXTERN BOOL
NtCreateUserProcess(
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
);

EXTERN BOOL
NtCreateUserProcess2(
	OUT				PHANDLE							ProcessHandle,
	OUT				PHANDLE							ThreadHandle,
	IN				PRTL_USER_PROCESS_PARAMETERS	ProcessParameters,
	IN				PPS_CREATE_INFO					CreateInfo,
	IN				PPS_ATTRIBUTE_LIST				AttributeList,
	OUT OPTIONAL	PNTSTATUS						STATUS						// OUTPUT : the return from the syscall
);


EXTERN BOOL
NtQuerySystemInformation(
	IN					SYSTEM_INFORMATION_CLASS		SystemInformationClass,
	IN	OPTIONAL		PVOID							SystemInformation,
	IN	OPTIONAL		ULONG							SystemInformationLength,
	OUT OPTIONAL		PULONG							ReturnLength,
	OUT OPTIONAL		PNTSTATUS						STATUS						// OUTPUT : the return from the syscall
);








#endif // !_SYSCALLS_H
