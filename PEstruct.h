#pragma once

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>

#endif
#include "minidumpapiset.h"

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OVERWRITE_IF 0x00000005
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
struct PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
};
//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	//...
};
/*
struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWCH Buffer;
};
*/
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	//...
};

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;


typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

enum SYSTEM_INFORMATION_CLASS {
	SystemExtendedProcessInformation = 57
};


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	int BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(NTAPI* myNtQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
	);


typedef NTSTATUS(NTAPI* myNtOpenProcess)(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

typedef VOID(WINAPI* RtlMoveMemory_t)(
	VOID UNALIGNED* Destination,
	const VOID UNALIGNED* Source,
	SIZE_T Length);

typedef DWORD(WINAPI* myQueueUserAPC)(
	IN PAPCFUNC  pfnAPC,
	IN HANDLE    hThread,
	IN ULONG_PTR dwData
	);

typedef NTSTATUS(NTAPI* myNtAllocateVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

typedef NTSTATUS(NTAPI* myNtWriteVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS(NTAPI* myNtProtectVirtualMemory)(
	IN  HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG RegionSize,
	IN  ULONG NewProtect,
	OUT PULONG OldProtect
	);

typedef NTSTATUS(NTAPI* myNtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

typedef NTSTATUS(NTAPI* myRtlCreateUserThread)(
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT PCLIENT_ID          ClientID
	);

typedef NTSTATUS(NTAPI* NtCreateSection_t)(
	OUT PHANDLE SectionHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG PageAttributess,
	IN ULONG SectionAttributes,
	IN HANDLE FileHandle OPTIONAL);

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect);

typedef NTSTATUS(NTAPI* myNtReadVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	OUT PVOID               Buffer,
	IN ULONG                NumberOfBytesToRead,
	OUT PULONG              NumberOfBytesReaded OPTIONAL
	);

typedef NTSTATUS(NTAPI* myNtCreateFile)(
	OUT          PHANDLE            FileHandle,
	IN           ACCESS_MASK        DesiredAccess,
	IN           POBJECT_ATTRIBUTES ObjectAttributes,
	OUT          PIO_STATUS_BLOCK   IoStatusBlock,
	IN           PLARGE_INTEGER     AllocationSize OPTIONAL,
	IN           ULONG              FileAttributes,
	IN           ULONG              ShareAccess,
	IN           ULONG              CreateDisposition,
	IN           ULONG              CreateOptions,
	IN			 PVOID              EaBuffer OPTIONAL,
	IN           ULONG              EaLength
	);

typedef void (WINAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef NTSTATUS(NTAPI* PNtClose)(
	IN HANDLE Handle
	);

typedef NTSTATUS(NTAPI* PNtOpenProcessToken)(
	IN  HANDLE      ProcessHandle,
	IN  ACCESS_MASK DesiredAccess,
	OUT PHANDLE     TokenHandle
	);

typedef  NTSTATUS(NTAPI* PNtQueryInformationToken)(
	IN  HANDLE                  TokenHandle,
	IN  TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID                   TokenInformation,
	IN  ULONG                   TokenInformationLength,
	OUT PULONG                  ReturnLength
	);

typedef NTSTATUS(NTAPI* PNtAdjustPrivilegesToken)(
	IN HANDLE               TokenHandle,
	IN BOOLEAN              DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES    TokenPrivileges,
	IN ULONG                PreviousPrivilegesLength,
	OUT PTOKEN_PRIVILEGES   PreviousPrivileges OPTIONAL,
	OUT PULONG              RequiredLength OPTIONAL
	);

typedef BOOL(WINAPI* PMiniDumpWriteDump)(
	IN HANDLE hProcess,
	IN DWORD ProcessId,
	IN HANDLE hFile,
	IN MINIDUMP_TYPE DumpType,
	IN PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam OPTIONAL,
	IN PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam OPTIONAL,
	IN PMINIDUMP_CALLBACK_INFORMATION CallbackParam OPTIONAL
	);

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

struct ThreadInfo {
	DWORD* threadIds;
	DWORD numThreads;
};

typedef VOID(WINAPI* RtlMoveMemory_t)(
	VOID UNALIGNED* Destination,
	const VOID UNALIGNED* Source,
	SIZE_T Length);

using myNtTestAlert = NTSTATUS(NTAPI*)();

typedef NTSTATUS (NTAPI* PNtFreeVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN PVOID* BaseAddress,
	IN OUT PULONG           RegionSize,
	IN ULONG                FreeType
);


#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects
#endif

typedef struct {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} T_CLIENT_ID;

typedef struct
{
	HANDLE ReflectionProcessHandle;
	HANDLE ReflectionThreadHandle;
	T_CLIENT_ID ReflectionClientId;
} T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;


typedef NTSTATUS(NTAPI* RtlCreateProcessReflectionFunc) (
	HANDLE ProcessHandle,
	ULONG Flags,
	PVOID StartRoutine,
	PVOID StartContext,
	HANDLE EventHandle,
	T_RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation
	);

typedef struct {
	DWORD64 unk1;
	ULONG Flags;
	PVOID StartRoutine;
	PVOID StartContext;
	PVOID unk2;
	PVOID unk3;
	PVOID EventHandle;
} ReflectionContext;