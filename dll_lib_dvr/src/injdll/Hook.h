#pragma once
#ifndef MY_DRIVER_H
#define MY_DRIVER_H
#include <ntdll.h>

#endif // MY_DRIVER_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include <evntprov.h>
#include <detours.h>

extern REGHANDLE ProviderHandle;


using _snwprintf_fn_t = int(__cdecl*)(
  wchar_t* buffer,
  size_t count,
  const wchar_t* format,
  ...
  );

inline _snwprintf_fn_t m_snwprintf = nullptr;




extern "C" unsigned long long Relocation(DWORD Offset);



inline decltype(CreateProcessA)* OrigCreateProcessA = nullptr;
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
);





inline decltype(LoadLibraryA)* OrigLoadLibraryA = nullptr;


HMODULE
WINAPI
HookLoadLibraryA(
  _In_ LPCSTR lpLibFileName
);


