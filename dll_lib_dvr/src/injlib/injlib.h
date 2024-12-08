#pragma once

#include <ntddk.h>
#include <wdm.h>
#ifdef __cplusplus
extern "C" {
#endif

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////

#if DBG
#  define InjDbgPrint(Format, ...)  \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,         \
               DPFLTR_ERROR_LEVEL,          \
               Format,                      \
               __VA_ARGS__)
#else
#  define InjDbgPrint(Format, ...)
#endif

//////////////////////////////////////////////////////////////////////////
// Enumerations.
//////////////////////////////////////////////////////////////////////////

typedef enum _INJ_ARCHITECTURE
{
  InjArchitectureX86,
  InjArchitectureX64,
  InjArchitectureARM32,
  InjArchitectureARM64,
  InjArchitectureMax,

#if defined(_M_IX86)
  InjArchitectureNative = InjArchitectureX86
#elif defined (_M_AMD64)
  InjArchitectureNative = InjArchitectureX64
#elif defined (_M_ARM64)
  InjArchitectureNative = InjArchitectureARM64
#endif
} INJ_ARCHITECTURE;

typedef enum _INJ_METHOD
{
  //
  // Inject process by executing short "shellcode" which
  // calls LdrLoadDll.
  // This method always loads DLL of the same architecture
  // as the process.
  //

  InjMethodThunk,

  //
  // Inject process by directly setting LdrLoadDll as the
  // user-mode APC routine.
  // This method always loads x64 DLL into the process.
  //
  // N.B. Available only on x64.
  //

  InjMethodThunkless,

  //
  // Inject Wow64 process by redirecting path of the "wow64log.dll"
  // to the path of the "injdll".  Native processes are injected
  // as if the "thunk method" was selected (InjMethodThunk).
  //
  // This method always loads DLL of the same architecture
  // as the OS into the process.
  //

  InjMethodWow64LogReparse,
} INJ_METHOD;

//////////////////////////////////////////////////////////////////////////
// Structures.
//////////////////////////////////////////////////////////////////////////

typedef struct _INJ_SETTINGS
{
  //
  // Paths to the inject DLLs for each architecture.
  // Unsupported architectures (either by OS or the
  // method) can have empty string.
  //

  UNICODE_STRING  DllPath[InjArchitectureMax];

  //
  // Injection method.
  //

  INJ_METHOD      Method;
} INJ_SETTINGS, *PINJ_SETTINGS;

typedef struct _INJ_INJECTION_INFO
{
  LIST_ENTRY  ListEntry;

  //
  // Process ID.
  //

  HANDLE      ProcessId;

  //
  // Combination of INJ_SYSTEM_DLL flags indicating
  // which DLLs has been already loaded into this
  // process.
  //

  ULONG       LoadedDlls;

  //
  // If true, the process has been already injected.
  //

  BOOLEAN     IsInjected;

  //
  // If true, trigger of the queued user APC will be
  // immediately forced upon next kernel->user transition.
  //

  BOOLEAN     ForceUserApc;

  //
  // Address of LdrLoadDll routine within ntdll.dll
  // (which ntdll.dll is selected is based on the INJ_METHOD).
  //

  PVOID       LdrLoadDllRoutineAddress;

  //
  // Injection method.
  //

  INJ_METHOD  Method;
} INJ_INJECTION_INFO, *PINJ_INJECTION_INFO;

//////////////////////////////////////////////////////////////////////////
// Public functions.
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
InjInitialize(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath,
  _In_ PINJ_SETTINGS Settings
  );

VOID
NTAPI
InjDestroy(
  VOID
  );

NTSTATUS
NTAPI
InjCreateInjectionInfo(
  _In_opt_ PINJ_INJECTION_INFO* InjectionInfo,
  _In_ HANDLE ProcessId
  );

VOID
NTAPI
InjRemoveInjectionInfo(
  _In_ PINJ_INJECTION_INFO InjectionInfo,
  _In_ BOOLEAN FreeMemory
  );

VOID
NTAPI
InjRemoveInjectionInfoByProcessId(
  _In_ HANDLE ProcessId,
  _In_ BOOLEAN FreeMemory
  );

PINJ_INJECTION_INFO
NTAPI
InjFindInjectionInfo(
  _In_ HANDLE ProcessId
  );

BOOLEAN
NTAPI
InjCanInject(
  _In_ PINJ_INJECTION_INFO InjectionInfo
  );

NTSTATUS
NTAPI
InjInject(
  _In_ PINJ_INJECTION_INFO InjectionInfo
  );

//////////////////////////////////////////////////////////////////////////
// Notify routines.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
InjCreateProcessNotifyRoutineEx(
  _Inout_ PEPROCESS Process,
  _In_ HANDLE ProcessId,
  _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
  );

VOID
NTAPI
InjLoadImageNotifyRoutine(
  _In_opt_ PUNICODE_STRING FullImageName,
  _In_ HANDLE ProcessId,
  _In_ PIMAGE_INFO ImageInfo
  );





//**********************************新添加的********************************************

NTSTATUS AnsiToUnicode(
  const char* ansiStr,  // 输入的ANSI字符串
  PUNICODE_STRING unicodeStr, // 输出的UNICODE_STRING结构
  ULONG bufferSize // 容纳宽字符字符串的缓冲区大小
);

typedef struct _PROCESS_ENTRY {
  LIST_ENTRY ListEntry;        // 用于链接到链表
  UNICODE_STRING ProcessName;  // 进程名
} PROCESS_ENTRY, * PPROCESS_ENTRY;


LIST_ENTRY g_ProcessListHead; // 进程链表的头部





BOOLEAN IsProcessNameExists(PCWSTR ProcessName);

BOOLEAN AddProcessName(PCWSTR ProcessName);

BOOLEAN RemoveProcessName(PCWSTR ProcessName);




//0x40 bytes (sizeof)
struct _SECTION
{
  struct _RTL_BALANCED_NODE SectionNode;                                  //0x0
  ULONGLONG StartingVpn;                                                  //0x18
  ULONGLONG EndingVpn;                                                    //0x20
  union
  {
    struct _CONTROL_AREA* ControlArea;                                  //0x28
    struct _FILE_OBJECT* FileObject;                                    //0x28
    ULONGLONG RemoteImageFileObject : 1;                                  //0x28
    ULONGLONG RemoteDataFileObject : 1;                                   //0x28
  } u1;                                                                   //0x28
  ULONGLONG SizeOfSection;                                                //0x30
  union
  {
    ULONG LongFlags;                                                    //0x38
  } u;                                                                    //0x38
  ULONG InitialPageProtection : 12;                                         //0x3c
  ULONG SessionId : 19;                                                     //0x3c
  ULONG NoValidationNeeded : 1;                                             //0x3c
};

struct _EX_FAST_REF
{
  union
  {
    VOID* Object;                                                       //0x0
    ULONGLONG RefCnt : 4;                                                 //0x0
    ULONGLONG Value;                                                    //0x0
  };
};

struct _CONTROL_AREA  //这里结构体不完全
{
  struct _SEGMENT* Segment;                                               //0x0
  union
  {
    struct _LIST_ENTRY ListHead;                                        //0x8
    VOID* AweContext;                                                   //0x8
  };
  ULONGLONG NumberOfSectionReferences;                                    //0x18
  ULONGLONG NumberOfPfnReferences;                                        //0x20
  ULONGLONG NumberOfMappedViews;                                          //0x28
  ULONGLONG NumberOfUserReferences;                                       //0x30
  union
  {
    ULONG LongFlags;                                                    //0x38

  } u;                                                                    //0x38
  union
  {
    ULONG LongFlags;                                                    //0x3c

  } u1;                                                                   //0x3c
  struct _EX_FAST_REF FilePointer;
};

UNICODE_STRING m_GetProcessName(PEPROCESS m_pEprocess);


//**********************************新添加的********************************************

#ifdef __cplusplus
}
#endif
