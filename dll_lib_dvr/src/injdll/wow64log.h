#pragma once
#define NTDLL_NO_INLINE_INIT_STRING

#ifndef MY_DRIVER_H
#define MY_DRIVER_H
#include <ntdll.h>

#ifdef __cplusplus
extern "C" {
#endif

//#define WOW64_LOG_FAKE_EXPORT_ENABLE

NTSTATUS
NTAPI
Wow64LogCreateExports(
  PVOID BaseAddress
  );


#define EventActivityIdControl  EtwEventActivityIdControl
#define EventEnabled            EtwEventEnabled
#define EventProviderEnabled    EtwEventProviderEnabled
#define EventRegister           EtwEventRegister
#define EventSetInformation     EtwEventSetInformation
#define EventUnregister         EtwEventUnregister
#define EventWrite              EtwEventWrite
#define EventWriteEndScenario   EtwEventWriteEndScenario
#define EventWriteEx            EtwEventWriteEx
#define EventWriteStartScenario EtwEventWriteStartScenario
#define EventWriteString        EtwEventWriteString
#define EventWriteTransfer      EtwEventWriteTransfer


#ifdef __cplusplus
}
#endif


#endif // MY_DRIVER_H
