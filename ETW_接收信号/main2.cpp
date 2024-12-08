#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <strsafe.h>
using namespace std;
#define SESSION_NAME_FILE  L"myETWsession"  // 确保会话名称是有效的
#define LOGFILE_PATH L"C:\\Users\\nzt\\Desktop\\etw.etl"


GUID ProviderGuid = {
  0xa4b4ba50, 0xa667, 0x43f5, { 0x91, 0x9b, 0x1e, 0x52, 0xa6, 0xd6, 0x9b, 0xd5 }
};

TCHAR SessionName[] = TEXT("InjSession");


VOID
WINAPI
TraceEventCallback(
    _In_ PEVENT_RECORD EventRecord
)
{
    if (!EventRecord->UserData)
    {
        return;
    }

    //
    // TODO: Check that EventRecord contains only WCHAR string.
    //

    wprintf(L"[PID:%04X][TID:%04X] %s\n",
        EventRecord->EventHeader.ProcessId,
        EventRecord->EventHeader.ThreadId,
        (PWCHAR)EventRecord->UserData);
}

VOID
NTAPI
TraceStop(
    VOID
)
{
    BYTE Buffer[sizeof(EVENT_TRACE_PROPERTIES) + 4096];
    RtlZeroMemory(Buffer, sizeof(Buffer));

    PEVENT_TRACE_PROPERTIES EventTraceProperties = (PEVENT_TRACE_PROPERTIES)Buffer;
    EventTraceProperties->Wnode.BufferSize = sizeof(Buffer);

    StopTrace(0, SessionName, EventTraceProperties);
}


BOOL
WINAPI
CtrlCHandlerRoutine(
    _In_ DWORD dwCtrlType
)
{
    if (dwCtrlType == CTRL_C_EVENT)
    {
        //
        // Ctrl+C was pressed, stop the trace session.
        //
        printf("Ctrl+C pressed, stopping trace session...\n");

        TraceStop();
    }

    return FALSE;
}


ULONG
NTAPI
TraceStart(
    VOID
)
{
    ULONG status = ERROR_SUCCESS;
    TRACEHANDLE SessionHandle = 0;
    EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
    ULONG BufferSize = 0;
    // Set up the callback for processing the trace events
    EVENT_TRACE_LOGFILE logFile = { 0 };
    TRACEHANDLE traceHandle=NULL;
    EVENT_TRACE_LOGFILEW m_Logfile = { 0 };
    ULONG rc=NULL;
    // Allocate memory for the session properties. The memory must
    // be large enough to include the log file name and session name,
    // which get appended to the end of the session properties structure.

    BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(LOGFILE_PATH) + sizeof(KERNEL_LOGGER_NAME);
    pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
    if (NULL == pSessionProperties)
    {
        wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
        goto Exit;
    }

    // Set the session properties. You only append the log file name
    // to the properties structure; the StartTrace function appends
    // the session name for you.

    ZeroMemory(pSessionProperties, BufferSize);
    pSessionProperties->Wnode.BufferSize = BufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
    //pSessionProperties->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    pSessionProperties->LogFileMode = PROCESS_TRACE_MODE_REAL_TIME;//****这里原来是 EVENT_TRACE_FILE_MODE_CIRCULAR;
    pSessionProperties->MaximumFileSize = 5;  // 5 MB
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
    StringCbCopy((LPWSTR)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset), sizeof(LOGFILE_PATH), LOGFILE_PATH);

    //// Add Kernel Process Provider GUID to the session's enabled events
    //status = EnableTrace(TRUE, 0, 0, &KernelProcessProviderGuid);

    if (status != ERROR_SUCCESS)
    {
        wprintf(L"EnableTrace failed with %lu\n", status);
        goto Exit;
    }

    // Create the trace session.

    status = StartTrace(&SessionHandle, SESSION_NAME_FILE, pSessionProperties);

    if (ERROR_SUCCESS != status)
    {
        if (ERROR_ALREADY_EXISTS == status)
        {
            wprintf(L"The NT Kernel Logger session is already in use.\n");
        }
        else
        {
            wprintf(L"EnableTrace() failed with %lu\n", status);
        }

        goto Exit;
    }

    // Enable the trace for Kernel Process events
    status = EnableTrace(TRUE, 0, 0, &ProviderGuid, SessionHandle);

    if (ERROR_SUCCESS != status)
    {
        wprintf(L"ProcessTrace() failed with %lu\n", status);
        goto Exit;
    }







    ZeroMemory(&m_Logfile, sizeof(m_Logfile));

    // 设置会话名称
    m_Logfile.LoggerName = (LPWSTR)SESSION_NAME_FILE;

    m_Logfile.LogFileName = (LPWSTR)LOGFILE_PATH;
    // 设置其他必要字段
    m_Logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;

    // 设置回调函数
    m_Logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)TraceEventCallback;
    //m_Logfile.Context = (PVOID)0x114514;  // 随便输入一个数，这里是模拟上下文数据

    // 打开 Trace 会话
    SetLastError(0);
    traceHandle = OpenTraceW(&m_Logfile);  // 使用 OpenTraceW（假设SESSION_NAME_FILE是Unicode字符串）

    if (traceHandle == (TRACEHANDLE)INVALID_HANDLE_VALUE)
    {
        wprintf(L"OpenTraceW failed with error %lu\n", GetLastError());
        system("pause");
        return (ULONG)INVALID_HANDLE_VALUE;
    }



   

    // 开始处理事件
    rc = ProcessTrace(&traceHandle, 1, 0, 0);
    if (rc != ERROR_SUCCESS)
    {
        wprintf(L"ProcessTrace failed with error %lu\n", rc);
        return (ULONG)ERROR_SUCCESS;
    }
    cout << "开始监视！" << endl;


    getchar();



Exit:
    if (traceHandle)
    {
        CloseTrace(traceHandle);
    }

    if (SessionHandle)
    {
        CloseTrace(SessionHandle);
    }

    RtlZeroMemory(pSessionProperties, sizeof(pSessionProperties));
    pSessionProperties->Wnode.BufferSize = sizeof(pSessionProperties);
    StopTrace(0, SessionName, pSessionProperties);

    if (rc != ERROR_SUCCESS)
    {
        printf("Error: %08x\n", rc);
    }
    system("pause");
    return rc;

}



int main()
{
    SetConsoleCtrlHandler(&CtrlCHandlerRoutine, TRUE);
    TraceStop();

    printf("Starting tracing session...\n");

    ULONG ErrorCode = TraceStart();
    return ErrorCode == ERROR_SUCCESS
        ? EXIT_SUCCESS
        : EXIT_FAILURE;
}