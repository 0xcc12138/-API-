#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1

#include "wow64log.h"
#include "Hook.h"
//
// Include NTDLL-related headers.
//
#define NTDLL_NO_INLINE_INIT_STRING


#if defined(_M_IX86)
#  define ARCH_A          "x86"
#  define ARCH_W         L"x86"
#elif defined(_M_AMD64)
#  define ARCH_A          "x64"
#  define ARCH_W         L"x64"
#elif defined(_M_ARM)
#  define ARCH_A          "ARM32"
#  define ARCH_W         L"ARM32"
#elif defined(_M_ARM64)
#  define ARCH_A          "ARM64"
#  define ARCH_W         L"ARM64"
#else
#  error Unknown architecture
#endif


// size_t strlen(const char * str)
// {
//   const char *s;
//   for (s = str; *s; ++s) {}
//   return(s - str);
// }

//
// Include support for ETW logging.
// Note that following functions are mocked, because they're
// located in advapi32.dll.  Fortunatelly, advapi32.dll simply
// redirects calls to these functions to the ntdll.dll.
//





//
// Include Detours.
//


//
// This is necessary for x86 builds because of SEH,
// which is used by Detours.  Look at loadcfg.c file
// in Visual Studio's CRT source codes for the original
// implementation.
//

#if defined(_M_IX86) || defined(_X86_)

EXTERN_C PVOID __safe_se_handler_table[]; /* base of safe handler entry table */
EXTERN_C BYTE  __safe_se_handler_count;   /* absolute symbol whose address is
                                             the count of table entries */
EXTERN_C
CONST
DECLSPEC_SELECTANY
IMAGE_LOAD_CONFIG_DIRECTORY
_load_config_used = {
    sizeof(_load_config_used),
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    (SIZE_T)__safe_se_handler_table,
    (SIZE_T)&__safe_se_handler_count,
};

#endif

//
// Unfortunatelly sprintf-like functions are not exposed
// by ntdll.lib, which we're linking against.  We have to
// load them dynamically.
//



//
// ETW provider GUID and global provider handle.
//

//
// GUID:
//   {a4b4ba50-a667-43f5-919b-1e52a6d69bd5}
//

GUID ProviderGuid = {
  0xa4b4ba50, 0xa667, 0x43f5, { 0x91, 0x9b, 0x1e, 0x52, 0xa6, 0xd6, 0x9b, 0xd5 }
};


//
// Hooking functions and prototypes.
//

inline decltype(NtQuerySystemInformation)* OrigNtQuerySystemInformation = nullptr;




//EXTERN_C
//NTSTATUS
//NTAPI
//HookNtQuerySystemInformation(
//  _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
//  _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
//  _In_ ULONG SystemInformationLength,
//  _Out_opt_ PULONG ReturnLength
//  )
//{
//  //
//  // Log the function call.
//  //
//
//  WCHAR Buffer[128];
//  unsigned long long ip = Relocation(0x180);
//  
//  m_snwprintf(Buffer,
//             RTL_NUMBER_OF(Buffer),
//             L"在地址0x%llx调用了NtQuerySystemInformation",
//             ip);
//
//  EtwEventWriteString(ProviderHandle, 0, 0, Buffer);
//
//  //
//  // Call original function.
//  //
//
//  return OrigNtQuerySystemInformation(SystemInformationClass,
//                                      SystemInformation,
//                                      SystemInformationLength,
//                                      ReturnLength);
//}

inline decltype(NtCreateThreadEx)* OrigNtCreateThreadEx = nullptr;

//NTSTATUS
//NTAPI
//HookNtCreateThreadEx(
//  _Out_ PHANDLE ThreadHandle,
//  _In_ ACCESS_MASK DesiredAccess,
//  _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
//  _In_ HANDLE ProcessHandle,
//  _In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
//  _In_opt_ PVOID Argument,
//  _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
//  _In_ SIZE_T ZeroBits,
//  _In_ SIZE_T StackSize,
//  _In_ SIZE_T MaximumStackSize,
//  _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
//  )
//{
//  //
//  // Log the function call.
//  //
//
//  WCHAR Buffer[128];
//
//  unsigned long long ip = Relocation(0x80);
//  m_snwprintf(Buffer,
//    RTL_NUMBER_OF(Buffer),
//    L"在地址0x%llx调用了NtCreateThreadEx",
//    ip);
//
//  EtwEventWriteString(ProviderHandle, 0, 0, Buffer);
//
//  //
//  // Call original function.
//  //
//
//  return OrigNtCreateThreadEx(ThreadHandle,
//                              DesiredAccess,
//                              ObjectAttributes,
//                              ProcessHandle,
//                              StartRoutine,
//                              Argument,
//                              CreateFlags,
//                              ZeroBits,
//                              StackSize,
//                              MaximumStackSize,
//                              AttributeList);
//}

NTSTATUS
NTAPI
ThreadRoutine(
  _In_ PVOID ThreadParameter
  )
{
  LARGE_INTEGER Delay;
  Delay.QuadPart = -10 * 1000 * 100; // 100ms

  for (;;)
  {
    // EtwEventWriteString(ProviderHandle, 0, 0, L"NtDelayExecution(100ms)");

    NtDelayExecution(FALSE, &Delay);
  }
}

NTSTATUS
NTAPI
EnableDetours(
  VOID
  )
{
  DetourTransactionBegin();
  {
    //OrigNtQuerySystemInformation = NtQuerySystemInformation;
    //DetourAttach((PVOID*)&OrigNtQuerySystemInformation, HookNtQuerySystemInformation);

    //OrigNtCreateThreadEx = NtCreateThreadEx;
    //DetourAttach((PVOID*)&OrigNtCreateThreadEx, HookNtCreateThreadEx);


    OrigCreateProcessA = CreateProcessA;
    DetourAttach((PVOID*)&OrigCreateProcessA, HookCreateProcessA);


    OrigLoadLibraryA = LoadLibraryA;
    DetourAttach((PVOID*)&OrigLoadLibraryA, HookLoadLibraryA);

  }
  DetourTransactionCommit();

  return STATUS_SUCCESS;
}



NTSTATUS
NTAPI
DisableDetours(
  VOID
  )
{
  DetourTransactionBegin();
  {
    /*DetourDetach((PVOID*)&OrigNtQuerySystemInformation, HookNtQuerySystemInformation);
    DetourDetach((PVOID*)&OrigNtCreateThreadEx, HookNtCreateThreadEx);*/
    DetourDetach((PVOID*)OrigCreateProcessA, HookCreateProcessA);
    DetourDetach((PVOID*)OrigLoadLibraryA, HookLoadLibraryA);
  }
  DetourTransactionCommit();

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
OnProcessAttach(
  _In_ PVOID ModuleHandle
  )
{
  //
  // First, resolve address of the _snwprintf function.
  //

  ANSI_STRING RoutineName;
  RtlInitAnsiString(&RoutineName, (PSTR)"_snwprintf");

  UNICODE_STRING NtdllPath;
  RtlInitUnicodeString(&NtdllPath, (PWSTR)L"ntdll.dll");

  HANDLE NtdllHandle;
  LdrGetDllHandle(NULL, 0, &NtdllPath, &NtdllHandle);
  LdrGetProcedureAddress(NtdllHandle, &RoutineName, 0, (PVOID*)&m_snwprintf);

  //
  // Make us unloadable (by FreeLibrary calls).
  //

  LdrAddRefDll(LDR_ADDREF_DLL_PIN, ModuleHandle);

  //
  // Hide this DLL from the PEB.
  //

  PPEB Peb = NtCurrentPeb();
  PLIST_ENTRY ListEntry;

  for (ListEntry =   Peb->Ldr->InLoadOrderModuleList.Flink;
       ListEntry != &Peb->Ldr->InLoadOrderModuleList;
       ListEntry =   ListEntry->Flink)
  {
    PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

    //
    // ModuleHandle is same as DLL base address.
    //

    if (LdrEntry->DllBase == ModuleHandle)
    {
      RemoveEntryList(&LdrEntry->InLoadOrderLinks);
      RemoveEntryList(&LdrEntry->InInitializationOrderLinks);
      RemoveEntryList(&LdrEntry->InMemoryOrderLinks);
      RemoveEntryList(&LdrEntry->HashLinks);

      break;
    }
  }

  //
  // Create exports for Wow64Log* functions in
  // the PE header of this DLL.
  //

  Wow64LogCreateExports(ModuleHandle);


  //
  // Register ETW provider.
  //

  EtwEventRegister(&ProviderGuid,
                   NULL,
                   NULL,
                   &ProviderHandle);

  //
  // Create dummy thread - used for testing.
  //

  // RtlCreateUserThread(NtCurrentProcess(),
  //                     NULL,
  //                     FALSE,
  //                     0,
  //                     0,
  //                     0,
  //                     &ThreadRoutine,
  //                     NULL,
  //                     NULL,
  //                     NULL);

  //
  // Get command line of the current process and send it.
  //

  PWSTR CommandLine = Peb->ProcessParameters->CommandLine.Buffer;

  WCHAR Buffer[1024];
  m_snwprintf(Buffer,
             RTL_NUMBER_OF(Buffer),
             L"Arch: %s, CommandLine: '%s'",
             ARCH_W,
             CommandLine);

  EtwEventWriteString(ProviderHandle, 0, 0, Buffer);

  //
  // Hook all functions.
  //

  return EnableDetours();
}

NTSTATUS
NTAPI
OnProcessDetach(
  _In_ HANDLE ModuleHandle
  )
{
  //
  // Unhook all functions.
  //

  return DisableDetours();
}

EXTERN_C
BOOL
NTAPI
NtDllMain(
  _In_ HANDLE ModuleHandle,
  _In_ ULONG Reason,
  _In_ LPVOID Reserved
  )
{
  switch (Reason)
  {
    case DLL_PROCESS_ATTACH:
      OnProcessAttach(ModuleHandle);
      break;

    case DLL_PROCESS_DETACH:
      OnProcessDetach(ModuleHandle);
      break;

    case DLL_THREAD_ATTACH:

      break;

    case DLL_THREAD_DETACH:

      break;
  }

  return TRUE;
}

