
#include "Hook.h"


REGHANDLE ProviderHandle = NULL;


BOOL
WINAPI
HookCreateProcessA(
  _In_opt_ LPCSTR lpApplicationName,
  _Inout_opt_ LPSTR lpCommandLine,
  _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
  _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
  _In_ BOOL bInheritHandles,
  _In_ DWORD dwCreationFlags,
  _In_opt_ LPVOID lpEnvironment,
  _In_opt_ LPCSTR lpCurrentDirectory,
  _In_ LPSTARTUPINFOA lpStartupInfo,
  _Out_ LPPROCESS_INFORMATION lpProcessInformation
)
{
  WCHAR Buffer[128];
  unsigned long long ip = Relocation(0x1B0);

  m_snwprintf(Buffer,
    RTL_NUMBER_OF(Buffer),
    L"Address:0x%llx:CreateProcessA",
    ip);

  EventWriteString(ProviderHandle, 0, 0, Buffer);
  return OrigCreateProcessA(
    lpApplicationName,
    lpCommandLine,
    lpProcessAttributes,
    lpThreadAttributes,
    bInheritHandles,
    dwCreationFlags,
    lpEnvironment,
    lpCurrentDirectory,
    lpStartupInfo,
    lpProcessInformation
  );
}



HMODULE
WINAPI
HookLoadLibraryA(
  _In_ LPCSTR lpLibFileName
)
{
  WCHAR Buffer[128];
  unsigned long long ip = Relocation(0x180);

  m_snwprintf(Buffer,
    RTL_NUMBER_OF(Buffer),
    L"Address:0x%llx:LoadLibraryA",
    ip);

  EventWriteString(ProviderHandle, 0, 0, Buffer);
  return OrigLoadLibraryA(
    lpLibFileName
  );
}

