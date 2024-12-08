#include "../injlib/injlib.h"

#include <ntddk.h>
#define IOCTL_CUSTOM_FUNC1 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CUSTOM_FUNC2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define DebugPrint(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,__VA_ARGS__)
//////////////////////////////////////////////////////////////////////////
// Helper functions.
//////////////////////////////////////////////////////////////////////////

//
// Taken from ReactOS, used by InjpInitializeDllPaths.
//

typedef union
{
  WCHAR Name[sizeof(ULARGE_INTEGER) / sizeof(WCHAR)];
  ULARGE_INTEGER Alignment;
} ALIGNEDNAME;

//
// DOS Device Prefix \??\
//

ALIGNEDNAME ObpDosDevicesShortNamePrefix = { { L'\\', L'?', L'?', L'\\' } };
UNICODE_STRING ObpDosDevicesShortName = {
  sizeof(ObpDosDevicesShortNamePrefix), // Length
  sizeof(ObpDosDevicesShortNamePrefix), // MaximumLength
  (PWSTR)&ObpDosDevicesShortNamePrefix  // Buffer
};

NTSTATUS
NTAPI
InjpJoinPath(
  _In_ PUNICODE_STRING Directory,
  _In_ PUNICODE_STRING Filename,
  _Inout_ PUNICODE_STRING FullPath
  )
{
  UNICODE_STRING UnicodeBackslash = RTL_CONSTANT_STRING(L"\\");

  BOOLEAN DirectoryEndsWithBackslash = Directory->Length > 0 &&
                                       Directory->Buffer[Directory->Length - 1] == L'\\';

  if (FullPath->MaximumLength < Directory->Length ||
      FullPath->MaximumLength - Directory->Length -
        (!DirectoryEndsWithBackslash ? 1 : 0) < Filename->Length)
  {
    return STATUS_DATA_ERROR;
  }

  RtlCopyUnicodeString(FullPath, Directory);

  if (!DirectoryEndsWithBackslash)
  {
    RtlAppendUnicodeStringToString(FullPath, &UnicodeBackslash);
  }

  RtlAppendUnicodeStringToString(FullPath, Filename);

  return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
InjCreateSettings(
  _In_ PUNICODE_STRING RegistryPath,
  _Inout_ PINJ_SETTINGS Settings
  )
{
  //
  // In the "ImagePath" key of the RegistryPath, there
  // is a full path of this driver file.  Fetch it.
  //

  NTSTATUS Status;

  UNICODE_STRING ValueName = RTL_CONSTANT_STRING(L"ImagePath");

  OBJECT_ATTRIBUTES ObjectAttributes;
  InitializeObjectAttributes(&ObjectAttributes,
                             RegistryPath,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                             NULL,
                             NULL);

  HANDLE KeyHandle;
  Status = ZwOpenKey(&KeyHandle,
                     KEY_READ,
                     &ObjectAttributes);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  //
  // Save all information on stack - simply fail if path
  // is too long.
  //

  UCHAR KeyValueInformationBuffer[sizeof(KEY_VALUE_FULL_INFORMATION) + sizeof(WCHAR) * 128];
  PKEY_VALUE_FULL_INFORMATION KeyValueInformation = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformationBuffer;

  ULONG ResultLength;
  Status = ZwQueryValueKey(KeyHandle,
                           &ValueName,
                           KeyValueFullInformation,
                           KeyValueInformation,
                           sizeof(KeyValueInformationBuffer),
                           &ResultLength);

  ZwClose(KeyHandle);

  //
  // Check for succes.  Also check if the value is of expected
  // type and whether the path has a meaninful length.
  //

  if (!NT_SUCCESS(Status) ||
      KeyValueInformation->Type != REG_EXPAND_SZ ||
      KeyValueInformation->DataLength < sizeof(ObpDosDevicesShortNamePrefix))
  {
    return Status;
  }

  //
  // Save pointer to the fetched ImagePath value and test if
  // the path starts with "\??\" prefix - if so, skip it.
  //

  PWCHAR ImagePathValue = (PWCHAR)((PUCHAR)KeyValueInformation + KeyValueInformation->DataOffset);
  ULONG  ImagePathValueLength = KeyValueInformation->DataLength;

  if (*(PULONGLONG)(ImagePathValue) == ObpDosDevicesShortNamePrefix.Alignment.QuadPart)
  {
    ImagePathValue += ObpDosDevicesShortName.Length / sizeof(WCHAR);
    ImagePathValueLength -= ObpDosDevicesShortName.Length;
  }

  //
  // Cut the string by the last '\' character, leaving there
  // only the directory path.
  //

  PWCHAR LastBackslash = wcsrchr(ImagePathValue, L'\\');

  if (!LastBackslash)
  {
    return STATUS_DATA_ERROR;
  }

  *LastBackslash = UNICODE_NULL;

  UNICODE_STRING Directory;
  RtlInitUnicodeString(&Directory, ImagePathValue);

  //
  // Finally, fill all the buffers...
  //

#define INJ_DLL_X86_NAME    L"injdllx86.dll"
  UNICODE_STRING InjDllNameX86 = RTL_CONSTANT_STRING(INJ_DLL_X86_NAME);
  InjpJoinPath(&Directory, &InjDllNameX86, &Settings->DllPath[InjArchitectureX86]);
  InjDbgPrint("[injdrv]: DLL path (x86):   '%wZ'\n", &Settings->DllPath[InjArchitectureX86]);

#define INJ_DLL_X64_NAME    L"injdllx64.dll"
  UNICODE_STRING InjDllNameX64 = RTL_CONSTANT_STRING(INJ_DLL_X64_NAME);
  InjpJoinPath(&Directory, &InjDllNameX64, &Settings->DllPath[InjArchitectureX64]);
  InjDbgPrint("[injdrv]: DLL path (x64):   '%wZ'\n", &Settings->DllPath[InjArchitectureX64]);

#define INJ_DLL_ARM32_NAME  L"injdllARM.dll"
  UNICODE_STRING InjDllNameARM32 = RTL_CONSTANT_STRING(INJ_DLL_ARM32_NAME);
  InjpJoinPath(&Directory, &InjDllNameARM32, &Settings->DllPath[InjArchitectureARM32]);
  InjDbgPrint("[injdrv]: DLL path (ARM32): '%wZ'\n",   &Settings->DllPath[InjArchitectureARM32]);

#define INJ_DLL_ARM64_NAME  L"injdllARM64.dll"
  UNICODE_STRING InjDllNameARM64 = RTL_CONSTANT_STRING(INJ_DLL_ARM64_NAME);
  InjpJoinPath(&Directory, &InjDllNameARM64, &Settings->DllPath[InjArchitectureARM64]);
  InjDbgPrint("[injdrv]: DLL path (ARM64): '%wZ'\n",   &Settings->DllPath[InjArchitectureARM64]);

  return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// DriverEntry and DriverDestroy.
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
DriverDestroy(
  _In_ PDRIVER_OBJECT DriverObject
  )
{
  UNREFERENCED_PARAMETER(DriverObject);

  PsRemoveLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);
  PsSetCreateProcessNotifyRoutineEx(&InjCreateProcessNotifyRoutineEx, TRUE);
  if (DriverObject->DeviceObject != NULL)
  {
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\MyDevice_Link");
    IoDeleteSymbolicLink(&symbolicLink);
    IoDeleteDevice(DriverObject->DeviceObject);
  }
  InjDestroy();
}





NTSTATUS Dispatch(
  IN PDEVICE_OBJECT DeviceObject,
  IN PIRP Irp
)
{
  DeviceObject;
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}


NTSTATUS MyDeviceControlRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  DeviceObject;
  PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
  NTSTATUS status = STATUS_SUCCESS;
  ULONG controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;

  // 通过 Irp->AssociatedIrp.SystemBuffer 获取数据
  if (controlCode == IOCTL_CUSTOM_FUNC1)
  {
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    // 对 buffer 数据进行处理
    BOOLEAN result = AddProcessName((const char*)buffer);
    if (result == TRUE)
    {
      // 如果处理成功，准备返回 "true" 字符串
      const char* response = "true";
      ULONG responseLength = strlen(response) + 1; // 包括结尾的空字符

      // 确保缓冲区足够大来接收数据
      if (Irp->AssociatedIrp.SystemBuffer != NULL)
      {
        // 将 "true" 字符串复制到用户缓冲区
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, response, responseLength);

        // 设置返回的字节数
        Irp->IoStatus.Information = responseLength;

        // 设置操作成功的状态
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
    }
    else
    {
      // 如果处理失败，设置返回信息
      const char* errorMessage = "false";
      ULONG errorLength = strlen(errorMessage) + 1;

      if (Irp->AssociatedIrp.SystemBuffer != NULL)
      {
        // 将 "false" 字符串复制到用户缓冲区
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, errorMessage, errorLength);

        // 设置返回的字节数
        Irp->IoStatus.Information = errorLength;

        // 设置操作失败的状态
        Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
      }
    }


  }
  else if (controlCode == IOCTL_CUSTOM_FUNC2)
  {
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    // 对 buffer 数据进行处理

    BOOLEAN result = RemoveProcessName((const char*)buffer);
    if (result == TRUE)
    {
      // 如果处理成功，准备返回 "true" 字符串
      const char* response = "true";
      ULONG responseLength = strlen(response) + 1; // 包括结尾的空字符

      // 确保缓冲区足够大来接收数据
      if (Irp->AssociatedIrp.SystemBuffer != NULL)
      {
        // 将 "true" 字符串复制到用户缓冲区
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, response, responseLength);

        // 设置返回的字节数
        Irp->IoStatus.Information = responseLength;

        // 设置操作成功的状态
        Irp->IoStatus.Status = STATUS_SUCCESS;
      }
    }
    else
    {
      // 如果处理失败，设置返回信息
      const char* errorMessage = "false";
      ULONG errorLength = strlen(errorMessage) + 1;

      if (Irp->AssociatedIrp.SystemBuffer != NULL)
      {
        // 将 "false" 字符串复制到用户缓冲区
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, errorMessage, errorLength);

        // 设置返回的字节数
        Irp->IoStatus.Information = errorLength;

        // 设置操作失败的状态
        Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
      }
    }
  }

  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return Irp->IoStatus.Status;
}





NTSTATUS InitDevice(PDRIVER_OBJECT DriverObject)
{
  UNICODE_STRING DeviceName;
  PDEVICE_OBJECT DeviceObject = NULL;

  // 初始化设备名称
  RtlInitUnicodeString(&DeviceName, L"\\Device\\MyDevice");

  // 创建设备
  NTSTATUS status = IoCreateDevice(
    DriverObject,                // 驱动程序对象
    0,                           // 设备扩展大小
    &DeviceName,                 // 设备名称
    FILE_DEVICE_UNKNOWN,         // 设备类型
    0,                           // 设备特征
    FALSE,                       // 非独占设备
    &DeviceObject                // 返回的设备对象指针
  );

  if (!NT_SUCCESS(status)) {
    DebugPrint("Failed to create device: %X\n", status);
    return status;
  }
  DebugPrint("Device created successfully\n");

  // 创建符号链接
  UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\MyDevice_Link");
  status = IoCreateSymbolicLink(&symbolicLink, &DeviceName);

  if (!NT_SUCCESS(status)) {
    DebugPrint("Failed to create symbolic link: %X\n", status);
    IoDeleteDevice(DeviceObject); // 清理已创建的设备
    return status;
  }
  DebugPrint("Symbolic link created successfully\n");

  // 设置设备标志
  DeviceObject->Flags |= DO_BUFFERED_IO;

  // 设置分发例程
  DriverObject->MajorFunction[IRP_MJ_CREATE] = Dispatch;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDeviceControlRoutine;

  return STATUS_SUCCESS;

}



NTSTATUS
NTAPI
DriverEntry(
  _In_ PDRIVER_OBJECT DriverObject,
  _In_ PUNICODE_STRING RegistryPath
  )
{
  NTSTATUS Status;

  //
  // Register DriverUnload routine.
  //
  KdBreakPoint();
  DriverObject->DriverUnload = &DriverDestroy;

  // Create injection settings.
  //
   // 初始化链表头
  InitializeListHead(&g_ProcessListHead);


  InitDevice(DriverObject);


  INJ_SETTINGS Settings;

  WCHAR BufferDllPathX86[128];
  Settings.DllPath[InjArchitectureX86].Length = 0;
  Settings.DllPath[InjArchitectureX86].MaximumLength = sizeof(BufferDllPathX86);
  Settings.DllPath[InjArchitectureX86].Buffer = BufferDllPathX86;

  WCHAR BufferDllPathX64[128];
  Settings.DllPath[InjArchitectureX64].Length = 0;
  Settings.DllPath[InjArchitectureX64].MaximumLength = sizeof(BufferDllPathX64);
  Settings.DllPath[InjArchitectureX64].Buffer = BufferDllPathX64;

  WCHAR BufferDllPathARM32[128];
  Settings.DllPath[InjArchitectureARM32].Length = 0;
  Settings.DllPath[InjArchitectureARM32].MaximumLength = sizeof(BufferDllPathARM32);
  Settings.DllPath[InjArchitectureARM32].Buffer = BufferDllPathARM32;

  WCHAR BufferDllPathARM64[128];
  Settings.DllPath[InjArchitectureARM64].Length = 0;
  Settings.DllPath[InjArchitectureARM64].MaximumLength = sizeof(BufferDllPathARM64);
  Settings.DllPath[InjArchitectureARM64].Buffer = BufferDllPathARM64;

  Status = InjCreateSettings(RegistryPath, &Settings);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

#if defined (_M_IX86)
  Settings.Method = InjMethodThunk;
#elif defined (_M_AMD64)
  Settings.Method = InjMethodThunkless;
#elif defined (_M_ARM64)
  Settings.Method = InjMethodWow64LogReparse;
#endif
  //
  // Initialize injection driver.
  //

  Status = InjInitialize(DriverObject, RegistryPath, &Settings);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  //
  // Install CreateProcess and LoadImage notification routines.
  //

  Status = PsSetCreateProcessNotifyRoutineEx(&InjCreateProcessNotifyRoutineEx, FALSE);

  if (!NT_SUCCESS(Status))
  {
    return Status;
  }

  Status = PsSetLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);

  if (!NT_SUCCESS(Status))
  {
    PsSetCreateProcessNotifyRoutineEx(&InjCreateProcessNotifyRoutineEx, TRUE);
    return Status;
  }

  return STATUS_SUCCESS;
}
